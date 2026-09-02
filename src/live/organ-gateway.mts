/**
 * organ-gateway.mts — the first live DACS seller on the Demos devnet.
 *
 * Sells a PATH-OS proof-organ answer (nws_alerts: severe-weather severity band near a
 * COMMITTED location — raw feed + location hashed, never disclosed) through a full
 * DACS-1→5 session on the sanctioned v0.1 machinery:
 *
 *   DACS-1  seller anchors a signed listing (SR-2, name-addressed — see anchor-naming.ts)
 *   DACS-2  buyer verifies the seller's cci primary claim over the listing signature
 *   DACS-3  fixed-price agreement, signed by both parties (CD-1 canonical price)
 *   DACS-4  pay-dem (§9.5.9): REAL native-DEM transfer, included-only bft-final evidence;
 *           deliver-storage-program (§9.6.1): the organ answer anchored at
 *           dacs4:deliverable:{jobId}, delivery evidence with real contentHash + locator
 *   DACS-5  both parties emit AttestationBundleV1, both copies anchored two-sided;
 *           verifyBundleV1Full runs ENFORCING against the REAL chain reads and must PASS
 *
 * Modes:
 *   npx tsx src/live/organ-gateway.mts --dry-run     (default: no chain writes, no funds —
 *       in-memory anchor map + clearly-labelled mock payment; proves the whole artifact
 *       pipeline including two-sided verification over the injected fetch)
 *   LIVE=1 npx tsx src/live/organ-gateway.mts        (real devnet: needs DEMOS_MNEMONIC
 *       (buyer, funded) + DEMOS_SELLER_MNEMONIC in your .env; ~6-7 DEM in fees/writes)
 *
 * Honest scope: cci primary claims are per-run ed25519 keys (recorded in the anchored
 * artifacts) — durable gateway identities and listing discovery/indexing come next.
 * Exit 0 iff the buyer-side bundle verification rollup is PASS (dry + live alike).
 */

import { execFileSync } from 'node:child_process';
import { generateKeypair, sign } from '../lib/sign.js';
import { bytesToHex } from '../lib/verify-bundle.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../jcs.js';
import { emitSettlementEvidenceV1, signSettlementEvidenceV1 } from '../lib/emit-settlement-evidence-v1.js';
import { emitAttestationBundleV1 } from '../lib/emit-bundle-v1.js';
import { verifyBundleV1Full, computeAnchorPairV1 } from '../lib/verify-bundle-v1.js';
import type { AttestationBundleV1, BundlePhaseEntry } from '../types/bundle.js';
import type { AttestationRef } from '../types/verify-result.js';
import type { FetchResult } from '../demos/storage.js';
import { anchorNames } from './anchor-naming.js';
import { listingLogicalAddress } from '../dacs1/addressing.js';
import { buildDiscoveryArtifacts, resolveListingFromPublishedBinding } from '../dacs1/discovery.js';
import { createPayDemJsonlJournal } from './pay-dem-journal.js';

const LIVE = process.env.LIVE === '1';
const RPC = process.env.DEMOS_RPC ?? 'https://demosnode.discus.sh/';
const QUERY = process.env.ORGAN_QUERY ?? '35.2271,-80.8431'; // buyer's committed point (lat,lon)
const ORGAN = 'nws_alerts';
const PRICE_DEM = '1'; // CD-1 canonical
const PRICE_OS = 1_000_000_000n;
const SPEND_CAP_DEM = Number(process.env.GATEWAY_SPEND_CAP_DEM ?? '50');
// Env config for running this gateway against your own setup:
//   DACS_ENV_PATH  path to the dotenv file holding DEMOS_MNEMONIC / DEMOS_SELLER_MNEMONIC (default: .env)
//   AXIOM_PY       interpreter for the deliverable generator                              (default: python3)
//   ORGAN_CLI      deliverable-generator CLI that prints the answer text on stdout        (default: organ_answer.py)
// The generator is pluggable — point AXIOM_PY/ORGAN_CLI at any interpreter + CLI. ORGAN_CLI is resolved by
// the interpreter as a script argument (not PATH-searched), so set it to a real path unless it sits in cwd.
const AXIOM_PY = process.env.AXIOM_PY ?? 'python3';
const ORGAN_CLI = process.env.ORGAN_CLI ?? 'organ_answer.py';

const hex = (b: Uint8Array) => bytesToHex(b);
/** JCS canonical form as a UTF-8 string (jcsCanonical returns bytes). */
const jcsString = (v: unknown) => new TextDecoder().decode(jcsCanonical(v));
const now = () => Date.now();
const log = (stage: string, line: string) => console.log(`[${stage}] ${line}`);

// ── anchoring layer: real SR-2 in live mode, in-memory map in dry-run ─────────────────────
const memoryAnchors = new Map<string, { data: string; owner: string; name: string }>();

async function anchorString(handle: LiveHandles['buyer'] | null, ownerLabel: string, programName: string, data: string): Promise<string> {
  if (!LIVE || !handle) {
    const locator = `dry-${jcsHashHex({ programName, ownerLabel }).slice(0, 40)}`;
    memoryAnchors.set(locator, { data, owner: ownerLabel, name: programName });
    memoryAnchors.set(`name:${ownerLabel}:${programName}`, { data, owner: ownerLabel, name: programName });
    return locator;
  }
  const { anchor } = await import('../demos/storage.js');
  const res = await anchor(handle, programName, data);
  log('SR-2', `anchored ${programName} → ${res.storageAddress} (tx ${res.txHash.slice(0, 12)}…, ${res.sizeBytes}B)`);
  return res.storageAddress;
}

type LiveHandles = {
  buyer: import('../demos/connection.js').DemosHandle;
  seller: import('../demos/connection.js').DemosHandle;
};

async function connectLive(): Promise<LiveHandles> {
  const { connectDemos, mnemonicFromEnv } = await import('../demos/connection.js');
  const { config } = await import('dotenv');
  config({ path: process.env.DACS_ENV_PATH ?? '.env' });
  const buyer = await connectDemos(mnemonicFromEnv('DEMOS_MNEMONIC'), RPC);
  const seller = await connectDemos(mnemonicFromEnv('DEMOS_SELLER_MNEMONIC'), RPC);
  return { buyer, seller };
}

// ── the session ────────────────────────────────────────────────────────────────────────────
const jobId = process.env.JOB_ID ?? `organ-gw-${LIVE ? '' : 'dry-'}${now()}`;
const handles = LIVE ? await connectLive() : null;

// paramHash — a DETERMINISTIC digest of the STABLE session parameters (what's sold, the price,
// the spend cap). Identical between a dry-run and a live run of the same config (excludes per-run
// keys / jobId / timestamps), so it works as a real match-gate: a live run recomputes it and
// REQUIRES the operator-supplied GATEWAY_DRYRUN_HASH to equal it — you can only authorize a live
// run whose parameters match a dry-run you actually passed (Codex note, 2026-07-09).
const paramHash = jcsHashHex({ v: 'organ-gateway-params:1', organ: ORGAN, query: QUERY, priceDem: PRICE_DEM, capDem: SPEND_CAP_DEM });

// PREFLIGHT (LIVE only) — a live session anchors ~7 SR-2 writes + 1 pay-dem transfer, all DEM.
// The fail-closed gate refuses to spend unless: the estimate is under the cap, the buyer wallet
// is funded, an explicit operator go is set, and the run is bound to a verified dry-run hash.
// Dry-run mode spends nothing, so it skips the gate entirely.
if (LIVE && handles) {
  const { preflight } = await import('./spend-preflight.js');
  const suppliedHash = process.env.GATEWAY_DRYRUN_HASH ?? null;
  // Match-gate: the operator's dry-run hash MUST equal this run's recomputed paramHash. A mismatch
  // (price/query/cap/organ changed since the dry-run) fails closed BEFORE the balance query.
  if (suppliedHash !== paramHash) {
    console.error(`\n❌ LIVE spend BLOCKED: GATEWAY_DRYRUN_HASH does not match this run's parameters.`);
    console.error(`  supplied: ${suppliedHash ?? '(unset)'}`);
    console.error(`  expected: ${paramHash}  (run a passing dry-run of the SAME organ/query/price/cap to get it)`);
    process.exit(2);
  }
  const info = await handles.buyer.demos.getAddressInfo(handles.buyer.address);
  const balanceDem = Number((info as { balance?: bigint })?.balance ?? 0n) / 1e9;
  const gate = preflight({
    purpose: `organ-gateway live session ${jobId}`,
    estWrites: 7 + 1,                           // 7 anchors + 1 create-headroom per fresh program
    estCostPerWriteDem: 1,                      // 1 SR-2 chunk = 1 DEM
    createCostDem: Number(PRICE_DEM),           // the pay-dem transfer itself
    maxSpendDem: SPEND_CAP_DEM,
    balanceDem,
    balanceMarginDem: 2,                        // leave fee/rounding headroom
    operatorApproved: process.env.GATEWAY_LIVE_APPROVED === '1',
    dryRunHash: suppliedHash,                   // already equals paramHash here (match-gated above)
  });
  log('preflight', `${gate.verdict} — est ${gate.estCostDem} DEM, cap ${SPEND_CAP_DEM}, balance ${balanceDem} DEM, headroom ${gate.headroomDem ?? '?'}`);
  if (gate.verdict !== 'PROCEED') {
    console.error(`\n❌ LIVE spend BLOCKED by preflight:\n  - ${gate.reasons.join('\n  - ')}\n`);
    console.error('To authorize: set GATEWAY_LIVE_APPROVED=1 + GATEWAY_DRYRUN_HASH=<paramHash from a passing dry-run>, fund the buyer wallet, then LIVE=1.');
    process.exit(2);
  }
}

// Per-run cci primary claims (ed25519) — recorded in every anchored artifact.
const sellerKeys = generateKeypair();
const buyerKeys = generateKeypair();
const sellerCci = hex(sellerKeys.pubKey);
const buyerCci = hex(buyerKeys.pubKey);
const sellerOwner = handles?.seller.address ?? 'dry-seller';
const buyerOwner = handles?.buyer.address ?? 'dry-buyer';

log('session', `jobId=${jobId} mode=${LIVE ? 'LIVE devnet' : 'dry-run'} rpc=${RPC}`);

// DACS-1 — seller publishes a signed listing, anchored via SR-2.
const listingId = `${jobId}-listing`;
const sellerPrimaryClaim = `key:${sellerCci}`;
const listingLogical = listingLogicalAddress(sellerPrimaryClaim, listingId, 1);
const listingBody = {
  v: 'dacs-listing:0.1',
  listingId,
  listingVersion: 1,
  logical_address: listingLogical,
  seller: { scheme: 'key', identifier: sellerCci },
  sellerPaymentAddress: sellerOwner,
  item: 'proof-organ:nws_alerts — severe-weather severity band near a committed point (raw feed + location committed, never disclosed)',
  deliverable: { deliverableType: 'storage-program', accessModel: 'public' },
  price: { amount: PRICE_DEM, currency: 'DEM' },
  acceptedRails: ['pay-dem'],
};
const listingCanonical = jcsCanonical(listingBody); // bytes — the signing scope
const listingHash = jcsHashHex(listingBody);
const listingSig = sign(DOMAIN_SEPARATORS.LISTING, listingCanonical, sellerKeys.privKey);
const listingSigned = { ...listingBody, signature: Buffer.from(listingSig).toString('base64') };
const listingAnchored = jcsString(listingSigned);
const listingLocator = await anchorString(handles?.seller ?? null, sellerOwner, anchorNames.listing(listingLogical), listingAnchored);
log('DACS-1', `listing ${listingHash.slice(0, 16)}… anchored @ ${listingLocator}`);

// §6.3.4(c) / LR: produce the well-known index + catalog view, then resolve strictly through
// its native locator. The resolver API has no programName input and performs no name search.
const discoveryOrigin = 'https://organ.path-os.invalid';
const discovery = buildDiscoveryArtifacts({
  listing: listingSigned,
  sellerPrimaryClaim,
  nativeAddress: listingLocator.replace(/^dry-/, 'stor-'),
  publisherOrigin: discoveryOrigin,
  generatedAt: now(),
});
const agentCardUrl = `${discoveryOrigin}/.well-known/agent.json`;
const publishedResources = new Map<string, Uint8Array>([
  [agentCardUrl, discovery.agentCardBytes],
  [`${discoveryOrigin}/.well-known/dacs/listings.json`, discovery.indexBytes],
]);
const resolvedListing = await resolveListingFromPublishedBinding(
  agentCardUrl,
  listingLogical,
  async (url) => {
    const hit = publishedResources.get(url);
    if (!hit) throw new Error(`published discovery resource absent: ${url}`);
    return hit;
  },
  async (nativeAddress) => {
    const actualAddress = LIVE ? nativeAddress : nativeAddress.replace(/^stor-/, 'dry-');
    if (!LIVE) {
      const hit = memoryAnchors.get(actualAddress);
      return hit ? { storageAddress: nativeAddress, data: hit.data } : null;
    }
    const { fetchAnchored } = await import('../demos/storage.js');
    return fetchAnchored(RPC, nativeAddress);
  },
);
if (resolvedListing.contentHash !== listingHash) throw new Error('LR discovery resolved a different listing hash');
log('DACS-1', `published-binding LR resolved ${listingLogical} → ${resolvedListing.nativeAddress} ✓`);

// DACS-2 — buyer verifies the seller's primary claim over the listing signature.
const { verify } = await import('../lib/sign.js');
const vetOk = verify(DOMAIN_SEPARATORS.LISTING, listingSig, listingCanonical, sellerKeys.pubKey);
if (!vetOk) throw new Error('DACS-2 vet FAILED: listing signature does not verify under the seller key: claim');
log('DACS-2', `seller key:${sellerCci.slice(0, 12)}… verified over the listing ✓`);

// DACS-3 — fixed-price agreement signed by BOTH parties.
const agreementBody = {
  v: 'dacs-agreement:0.1',
  jobId,
  listingRef: { listingId, contentHash: listingHash },
  terms: { price: { amount: PRICE_DEM, currency: 'DEM' }, rail: 'pay-dem', deliverableType: 'storage-program' },
  buyer: { scheme: 'cci', identifier: buyerCci },
  seller: { scheme: 'cci', identifier: sellerCci },
};
const agreementHash = jcsHashHex(agreementBody);
const agreementHashBytes = new TextEncoder().encode(agreementHash);
const buyerAgreementSig = Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, agreementHashBytes, buyerKeys.privKey)).toString('base64');
const sellerAgreementSig = Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, agreementHashBytes, sellerKeys.privKey)).toString('base64');
// Codex-review HIGH fix (2026-07-07): the SIGNED agreement is anchored and referenced from the
// bundle (agreementRef), so a verifier can independently recover + verify the signed terms —
// not just confirm hashes it cannot resolve.
const agreementSignedObj = {
  ...agreementBody,
  signatures: [
    { party: { scheme: 'cci', identifier: buyerCci }, algorithm: 'ed25519', value: buyerAgreementSig },
    { party: { scheme: 'cci', identifier: sellerCci }, algorithm: 'ed25519', value: sellerAgreementSig },
  ],
};
const agreementAnchoredStr = jcsString(agreementSignedObj);
const agreementAnchoredHash = jcsHashHex(agreementSignedObj);
const agreementLocator = await anchorString(handles?.seller ?? null, sellerOwner, anchorNames.agreement(jobId), agreementAnchoredStr);
log('DACS-3', `agreement ${agreementHash.slice(0, 16)}… signed by both parties; signed artifact anchored @ ${agreementLocator}`);

// DACS-4a — pay-dem settlement (REAL in live mode; labelled mock in dry-run).
const SETTLE_PHASE_INDEX = 3;
let payEvidence;
if (LIVE && handles) {
  const { settlePayDem } = await import('../adapters/dacs/pay-dem-demosdk.js');
  const pay = await settlePayDem({
    buyer: handles.buyer, sellerAddress: handles.seller.address,
    amountOs: PRICE_OS, amountDemCanonical: PRICE_DEM, jobId, phaseIndex: SETTLE_PHASE_INDEX,
    journal: createPayDemJsonlJournal(process.env.DACS_PAYDEM_JOURNAL),
  });
  if (!pay.ok) throw new Error(`pay-dem settlement aborted: ${pay.reason}`);
  payEvidence = pay.evidence;
  log('DACS-4', `pay-dem settled ${PRICE_DEM} DEM → tx demos:${pay.txHash.slice(0, 16)}… (bft-final)`);
} else {
  payEvidence = emitSettlementEvidenceV1({
    kind: 'payment', jobId, phase: 'pay-dem', phaseIndex: SETTLE_PHASE_INDEX, outcome: 'success',
    paymentTxRefs: [{ rail: 'pay-dem', txHash: `demos:DRYRUN-${jobId}`, kind: 'payment' }],
    paymentAmount: PRICE_DEM, paymentCurrency: 'DEM',
    finalityModel: 'bft-final', finalityObservedAt: now(), observedAt: now(),
  });
  log('DACS-4', `pay-dem MOCK (dry-run) — no funds moved`);
}
payEvidence = signSettlementEvidenceV1(payEvidence, `cci:${buyerCci}`, buyerKeys.privKey);
const payEvidenceStr = jcsString(payEvidence);
const payEvidenceHash = jcsHashHex(payEvidence);
const payEvidenceLocator = await anchorString(
  handles?.buyer ?? null, buyerOwner,
  anchorNames.paymentEvidence(jobId, 'pay-dem', SETTLE_PHASE_INDEX), payEvidenceStr,
);

// DACS-4b — deliver-storage-program (§9.6.1): the REAL organ answer, anchored.
const DELIVER_PHASE_INDEX = 4;
const organRaw = execFileSync(AXIOM_PY, [ORGAN_CLI, ORGAN, QUERY], { encoding: 'utf8', timeout: 60_000 });
const organ = JSON.parse(organRaw) as {
  organ?: string; answer?: Record<string, unknown>; error?: string;
  input_commitment?: string; commitment_scheme?: string; commitment_nonce?: string; fetched_at?: string;
};
if (!organ.answer) throw new Error(`organ bridge failed: ${organ.error ?? organRaw.slice(0, 200)}`);
// The commitment NONCE stays OUT of every anchored payload (it keys the HMAC commitment —
// publishing it would reopen the dictionary oracle Codex flagged). The seller retains it
// off-channel for a later buyer-side opening of the commitment.
const commitmentNonce = organ.commitment_nonce;
const deliverableObj = {
  v: 'pathos-organ-deliverable:0.1', jobId, agreementHash,
  organ: organ.organ, answer: organ.answer,
  input_commitment: organ.input_commitment, commitment_scheme: organ.commitment_scheme,
  fetched_at: organ.fetched_at,
};
const deliverablePayload = jcsString(deliverableObj);
const deliverableContentHash = jcsHashHex(deliverableObj);
const deliverableLocator = await anchorString(handles?.seller ?? null, sellerOwner, anchorNames.deliverable(jobId), deliverablePayload);
const deliveryEvidence = signSettlementEvidenceV1(emitSettlementEvidenceV1({
  kind: 'delivery', jobId, phase: 'deliver-storage-program', phaseIndex: DELIVER_PHASE_INDEX, outcome: 'success',
  deliverableContentHash, deliverableAnchorKind: 'storage-program', deliverableAnchorLocator: deliverableLocator,
  observedAt: now(),
}), `cci:${sellerCci}`, sellerKeys.privKey);
const deliveryEvidenceStr = jcsString(deliveryEvidence);
const deliveryEvidenceHash = jcsHashHex(deliveryEvidence);
const deliveryEvidenceLocator = await anchorString(
  handles?.seller ?? null, sellerOwner,
  anchorNames.deliveryEvidence(jobId, DELIVER_PHASE_INDEX), deliveryEvidenceStr,
);
log('DACS-4', `deliverable (${String(organ.answer['coverage'] ?? 'answer')}) anchored @ ${deliverableLocator}; delivery evidence @ ${deliveryEvidenceLocator}`);

// DACS-5 — both parties emit + anchor AttestationBundleV1; verify ENFORCING.
const refFor = (id: string, locator: string, contentHash: string): AttestationRef => ({
  anchor: { substrate: 'demos', locator }, contentHash, type: id, producedAt: new Date().toISOString(),
});
const phaseSummary: BundlePhaseEntry[] = [
  { index: 0, kind: 'identify', outcome: 'ok' },
  { index: 1, kind: 'vet-credentials', outcome: 'ok' },
  { index: 2, kind: 'negotiate-fixed-price', outcome: 'ok' },
  { index: SETTLE_PHASE_INDEX, kind: 'pay-dem', outcome: 'ok' },
  { index: DELIVER_PHASE_INDEX, kind: 'deliver-storage-program', outcome: 'ok' },
];
const unsignedBase = {
  bundleVersion: '1' as const, jobId, outcome: 'completed' as const,
  listingRef: { listingId, version: 1, contentHash: listingHash },
  parties: [
    { role: 'buyer' as const, bundleHash: agreementHash, primaryClaim: { scheme: 'cci' as const, identifier: buyerCci } },
    { role: 'seller' as const, bundleHash: agreementHash, primaryClaim: { scheme: 'cci' as const, identifier: sellerCci } },
  ],
  agreementRef: refFor('dacs-3-agreement', agreementLocator, agreementAnchoredHash),
  phaseSummary,
  vetRecords: [] as AttestationRef[],
  settlementEvidence: [
    refFor('dacs-4-evidence:pay-dem', payEvidenceLocator, payEvidenceHash),
    refFor('dacs-4-evidence:deliver-storage-program', deliveryEvidenceLocator, deliveryEvidenceHash),
  ],
  recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: now(),
};
const signers = [
  { party: { scheme: 'cci' as const, identifier: buyerCci }, privKey: buyerKeys.privKey },
  { party: { scheme: 'cci' as const, identifier: sellerCci }, privKey: sellerKeys.privKey },
];
const buyerBundle = emitAttestationBundleV1({ ...unsignedBase, anchoredByRole: 'buyer' }, signers);
const sellerBundle = emitAttestationBundleV1({ ...unsignedBase, anchoredByRole: 'seller' }, signers);
const buyerBundleStr = jcsString(buyerBundle);
const sellerBundleStr = jcsString(sellerBundle);
await anchorString(handles?.buyer ?? null, buyerOwner, anchorNames.bundle(jobId, 'buyer'), buyerBundleStr);
await anchorString(handles?.seller ?? null, sellerOwner, anchorNames.bundle(jobId, 'seller'), sellerBundleStr);
log('DACS-5', `both bundle copies anchored two-sided (names ${anchorNames.bundle(jobId, 'buyer')} / :seller)`);

// Verification fetch: maps the spec's jobId-derived pair addresses to the substrate-equivalent
// name-addressed anchors (§10.4.3 "or substrate-equivalent two-sided addressing"), and serves
// evidence locators directly.
const pair = computeAnchorPairV1(jobId);
async function gatewayFetch(_rpc: string, addr: string): Promise<FetchResult | null> {
  const nameFor = addr === pair.buyer
    ? { owner: buyerOwner, name: anchorNames.bundle(jobId, 'buyer') }
    : addr === pair.seller
      ? { owner: sellerOwner, name: anchorNames.bundle(jobId, 'seller') }
      : null;
  if (!LIVE) {
    const hit = nameFor ? memoryAnchors.get(`name:${nameFor.owner}:${nameFor.name}`) : memoryAnchors.get(addr);
    return hit ? { storageAddress: addr, owner: hit.owner, data: hit.data, sizeBytes: hit.data.length, createdAt: new Date().toISOString() } : null;
  }
  const { resolveByName } = await import('./anchor-naming.js');
  const { fetchAnchored } = await import('../demos/storage.js');
  return nameFor ? resolveByName(RPC, nameFor.owner, nameFor.name) : fetchAnchored(RPC, addr);
}

const verdict = await verifyBundleV1Full(buyerBundle as AttestationBundleV1, {
  rpc: RPC, fetchAnchoredImpl: gatewayFetch as never, requireSignatures: true,
});
log('DACS-5', `twoSided=${verdict.twoSided.outcome} — ${verdict.twoSided.detail.slice(0, 140)}`);
log('DACS-5', `attestation refs: ${verdict.attestationsVerified} verified, ${verdict.attestationsFailed} failed`);
log('DACS-5', `ROLLUP: ${verdict.rollup.toUpperCase()}`);

const passed = verdict.rollup === 'pass';

// Opt-in, read-only receipt export (GATEWAY_DUMP_ARTIFACTS=<path>): writes the FULL signed artifact set
// (listing, agreement, evidence, both bundle copies) + the verdict, so the deal's receipts can be
// independently inspected + re-verified off-chain. No behaviour change when unset; never runs on-chain.
// Output holds only signed public artifacts + on-chain addresses — no private keys or secrets.
// Fail-soft: a dump write error is logged and swallowed so it can NEVER change the deal's outcome or
// exit code — the deal has already settled by this point, and inspection tooling must not gate it.
if (process.env.GATEWAY_DUMP_ARTIFACTS) {
  try {
    // Store BOTH the raw anchored string (byte-faithful — this is what §7.5.2 hashes, so the receipt
    // is independently re-verifiable) and the parsed content (human-readable for inspection).
    const artifacts: Record<string, { locator: string; raw: string; content: unknown }> = {};
    for (const [k, v] of memoryAnchors) {
      if (k.startsWith('name:')) continue;  // dedup: memoryAnchors is keyed by both locator and name:*
      let content: unknown;
      try { content = JSON.parse(v.data); } catch { content = v.data; }
      artifacts[v.name] = { locator: k, raw: v.data, content };
    }
    const dump = {
      dumpFormat: 'dacs-receipt-dump:v1',  // version tag so future readers can detect incompatibility
      jobId, mode: LIVE ? 'live' : 'dry-run',
      verdict: { rollup: verdict.rollup, twoSided: verdict.twoSided.outcome, attestationsVerified: verdict.attestationsVerified, attestationsFailed: verdict.attestationsFailed },
      discovery: { logical_address: listingLogical, native_address: resolvedListing.nativeAddress, indexHash: discovery.indexHash },
      anchors: { listing: listingLocator, agreement: agreementLocator, payEvidence: payEvidenceLocator, deliverable: deliverableLocator, deliveryEvidence: deliveryEvidenceLocator },
      artifacts,
    };
    const { writeFileSync } = await import('node:fs');
    const { resolve } = await import('node:path');
    const dumpPath = resolve(process.env.GATEWAY_DUMP_ARTIFACTS);  // normalize operator-supplied path
    writeFileSync(dumpPath, JSON.stringify(dump, null, 2));
    console.log(`[dump] wrote full receipt set (${Object.keys(artifacts).length} artifacts) → ${dumpPath}`);
  } catch (err) {
    console.warn(`[dump] receipt export failed (deal outcome unaffected): ${err instanceof Error ? err.message : String(err)}`);
  }
}

console.log(JSON.stringify({
  jobId, mode: LIVE ? 'live' : 'dry-run', rollup: verdict.rollup,
  twoSided: verdict.twoSided.outcome,
  attestationsVerified: verdict.attestationsVerified,
  organAnswer: organ.answer,
  paramHash,
  // Advertise the authorize line ONLY on a PASSING dry-run — so possessing the hash means the
  // dry-run of these exact parameters actually passed (the match-gate then binds live to it).
  ...(LIVE || !passed ? {} : { authorizeLiveWith: `GATEWAY_LIVE_APPROVED=1 GATEWAY_DRYRUN_HASH=${paramHash} LIVE=1` }),
  discovery: { logical_address: listingLogical, native_address: resolvedListing.nativeAddress, indexHash: discovery.indexHash },
  anchors: { listing: listingLocator, agreement: agreementLocator, payEvidence: payEvidenceLocator, deliverable: deliverableLocator, deliveryEvidence: deliveryEvidenceLocator },
  // LOCAL-ONLY (never anchored): opens the deliverable's input commitment when disclosed with the raw record.
  commitmentNonce,
}, null, 2));

process.exit(passed ? 0 : 1);
