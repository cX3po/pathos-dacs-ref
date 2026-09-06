/**
 * ap2-test-agent.mts — a DACS TEST agent that settles via the pay-ap2 rail (§9.5.6).
 *
 * Answers @randomblocker's "anyone wanna build an AP2 Test agent" — it exercises the
 * DACS-4 v0.3 pay-ap2 ATTESTED-PROVIDER-RECEIPT verification (DACS-Standard #221/#222)
 * WITHOUT real Google/FIDO AP2 infra or a live PSP. It drives a full DACS-1→5 session on
 * the pay-ap2 rail and verifies the DACS-5 bundle checks pass under MOCK/SIMULATION assurance.
 *
 * Shape (modelled on organ-gateway.mts's self-deal, but rail='pay-ap2'):
 *   DACS-1  seller anchors a signed §6.3.4 Listing presenting its identity bundle (acceptedRails: [pay-ap2]; named in the pinned dacs-sdk's form)
 *   DACS-2  buyer verifies the listing as a counterparty would: signature, presented identity, presenter = signer
 *   DACS-3  fixed-price agreement (USD), signed by both parties, anchored
 *   DACS-4  pay-ap2 settlement:
 *             AP2-1  create provider payment session, binding dacs_job_id (MUST) +
 *                    dacs_agreement_hash (SHOULD) into provider metadata
 *             (mock)  facilitator captures + signs the provider receipt
 *             AP2-2  attested-fetch the provider status endpoint, cross-check
 *                    captured-status + amount/currency vs agreement + AP2-1 binding →
 *                    receiptAttestation (REQUIRED on success)
 *             §9.7   emit + sign the pay-ap2 payment SettlementEvidence
 *                    (finalityModel: 'provider-receipt' — AP2-4: capture, not irreversibility)
 *             emit + sign the AP2 attested-receipt record (carries the mock provider receipt
 *                    + receiptAttestation), anchored as a bundle-referenced evidence artifact
 *           deliver-storage-program: a synthetic test deliverable, anchored
 *   DACS-5  both parties emit + anchor AttestationBundleV1; verifyBundleV1Full runs
 *           ENFORCING (requireSignatures:true) over the injected fetch. Its core rollup is only
 *           one input to an explicitly MOCK/SIMULATION terminal verdict.
 *
 * ── MOCK DISCLOSURE ─────────────────────────────────────────────────────────────────────
 * This is a TEST agent: the AP2 provider/facilitator and the SR-3 attestation layer are
 * MOCKED and LABELLED (see ap2-provider-receipt.ts). The provider-receipt is signed by a
 * per-run stub key (`mock-ap2-facilitator`); the receiptAttestation carries the honest-stub
 * label `dahr-stub-single-fetch`. What is REAL: the DACS-4 evidence SHAPE, the AP2-1 binding
 * round-trip, the amount/currency/status cross-checks, the ed25519 signing discipline, and
 * the DACS-5 roll-up. There is NO live/on-chain path in this file — dry-run only.
 *
 * Run:  npx tsx src/live/ap2-test-agent.mts            (dry-run; no chain writes, no funds)
 * Exit 0 iff all checks pass; success is always labelled SIMULATION, never verified settlement.
 */

import { generateKeypair, sign, verify } from '../lib/sign.js';
import { agentDidForPubkey, agentDidSignatureVerifier, publishProducerListing } from './producer-listing.js';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { signatureExcludedHash } from '../lib/content-hash.js';
import { bytesToHex } from '../lib/verify-bundle.js';
import { canonicalPrice } from '../types/settle.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../jcs.js';
import {
  emitSettlementEvidenceV1,
  evidenceHashV1,
  signSettlementEvidenceV1,
} from '../lib/emit-settlement-evidence-v1.js';
import { emitAttestationBundleV1 } from '../lib/emit-bundle-v1.js';
import { verifyBundleV1Full, computeAnchorPairV1 } from '../lib/verify-bundle-v1.js';
import type { AttestationBundleV1, BundlePhaseEntry } from '../types/bundle.js';
import type { AttestationRef } from '../types/verify-result.js';
import type { FetchResult } from '../demos/storage.js';
import { anchorNames } from './anchor-naming.js';
import {
  PAY_AP2_RAIL_ID,
  createMockFacilitator,
  createAp2PaymentSession,
  signMockProviderReceipt,
  attestAp2Receipt,
  verifyAp2AgreementArtifact,
  signAp2AttestedReceiptRecord,
  ap2RecordHashHex,
  ap2SimulationDisposition,
  verifyMockAp2AttestedReceiptRecord,
  AP2_SIMULATION_ASSURANCE,
  AP2_SIMULATION_VERDICT,
  type Ap2AttestedReceiptRecord,
  type MockAp2PaymentEvidence, ap2RecordLogicalAddress } from './ap2-provider-receipt.js';

const hex = (b: Uint8Array) => bytesToHex(b);
const jcsString = (v: unknown) => new TextDecoder().decode(jcsCanonical(v));
const now = () => Date.now();
const log = (stage: string, line: string) => console.log(`[${stage}] ${line}`);

// CD-1: the amount carried on §9.7 evidence MUST be canonical (minimal-digit) — the DACS-4
// verifier rejects "1.50". Canonicalise the operator input so a natural fiat amount like "1.50"
// becomes the canonical "1.5" before it ever reaches an evidence hash.
const CURRENCY = process.env.AP2_CURRENCY ?? 'USD';
const PRICE_AP2 = canonicalPrice({ amount: process.env.AP2_PRICE ?? '1.50', asset: CURRENCY });
const STATUS_ENDPOINT = 'https://api.stripe.invalid/v1/payment_intents'; // read-only status scope (AP2-3), mock host
const simulationDisposition = ap2SimulationDisposition();

// ── dry-run anchoring layer: in-memory name-addressed map (identical contract to organ-gateway) ──
const memoryAnchors = new Map<string, { data: string; owner: string; name: string }>();
function anchorString(ownerLabel: string, programName: string, data: string): string {
  const locator = `dry-${jcsHashHex({ programName, ownerLabel }).slice(0, 40)}`;
  memoryAnchors.set(locator, { data, owner: ownerLabel, name: programName });
  memoryAnchors.set(`name:${ownerLabel}:${programName}`, { data, owner: ownerLabel, name: programName });
  return locator;
}

const jobId = process.env.JOB_ID ?? `ap2-test-dry-${now()}`;

// Per-run ed25519 keys. The listing presents the seller under its self-certifying agent DID (DACS-1 §6.3.1); the AP2
// agreement and its attested-receipt verifier (ap2-provider-receipt.ts) still carry the parties in the cci object form.
const sellerKeys = generateKeypair();
const buyerKeys = generateKeypair();
const sellerCci = hex(sellerKeys.pubKey);
const buyerCci = hex(buyerKeys.pubKey);
const sellerDid = agentDidForPubkey(sellerKeys.pubKey);
const sellerOwner = 'dry-seller';
const buyerOwner = 'dry-buyer';

log('session', `jobId=${jobId} mode=dry-run rail=pay-ap2 (TEST agent — provider+attestation MOCKED)`);

// ── DACS-1 — the seller publishes a §6.3.4 Listing (acceptedRails: pay-ap2) presenting its identity bundle under its
// agent DID, verified by the coordinator's own listing rules before it leaves the process, anchored under the pinned
// dacs-sdk's program-name form ────────────────────────────────────────────────────────────────────────────────────
const AP2_PIPELINE = [
  { kind: 'vet-credentials' }, { kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' },
  { kind: 'pay-ap2', parameters: { rail: PAY_AP2_RAIL_ID } }, { kind: 'deliver-storage-program' },
] as const;
const published = await publishProducerListing({
  jobId, seller: sellerKeys, displayName: 'PATH-OS AP2 test seller',
  offering: {
    title: 'ap2-test-deliverable', category: 'test', tags: ['ap2', 'simulation'],
    description: 'a synthetic test payload settled over the pay-ap2 fiat rail (mock provider, stub attestation)',
    deliverable: { kind: 'storage-program', accessModel: 'public' },
  },
  price: { amount: PRICE_AP2, currency: CURRENCY }, railId: PAY_AP2_RAIL_ID, pipeline: AP2_PIPELINE, now: now(),
  anchor: (programName, bytes) => anchorString(sellerOwner, programName, bytes),
});
const { listingId, listing: listingSigned, contentHash: listingHash, locator: listingLocator, programName: listingProgramName } = published;
log('DACS-1', `listing ${listingHash.slice(0, 16)}… (acceptedRails=[pay-ap2]) anchored @ ${listingLocator}`);

// ── DACS-2 — the buyer reads the anchored listing back through the coordinator's rules and pins the signer ──────
const anchoredListing = JSON.parse(memoryAnchors.get(listingLocator)!.data) as Record<string, unknown>;
try { await verifyBundleListing(anchoredListing, { verifySignature: agentDidSignatureVerifier as never }); }
catch (e) { throw new Error(`DACS-2 vet FAILED: ${e instanceof Error ? e.message : String(e)}`); }
if ((anchoredListing.signature as { signer?: unknown } | undefined)?.signer !== sellerDid) throw new Error('DACS-2 vet FAILED: listing signer is not the configured seller');
log('DACS-2', `seller ${sellerDid.slice(0, 28)}… verified over the anchored listing ✓`);

// ── DACS-3 — fixed-price agreement signed by BOTH parties, anchored (verifier recovers it) ─────
const agreementBody = {
  v: 'dacs-agreement:0.1',
  jobId,
  listingRef: { listingId, contentHash: listingHash },
  terms: { price: { amount: PRICE_AP2, currency: CURRENCY }, rail: PAY_AP2_RAIL_ID, deliverableType: 'storage-program' },
  buyer: { scheme: 'cci', identifier: buyerCci },
  seller: { scheme: 'cci', identifier: sellerCci },
};
const agreementHash = jcsHashHex(agreementBody);
const agreementHashBytes = new TextEncoder().encode(agreementHash);
const buyerAgreementSig = Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, agreementHashBytes, buyerKeys.privKey)).toString('base64');
const sellerAgreementSig = Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, agreementHashBytes, sellerKeys.privKey)).toString('base64');
const agreementSignedObj = {
  ...agreementBody,
  signatures: [
    { party: { scheme: 'cci', identifier: buyerCci }, algorithm: 'ed25519', value: buyerAgreementSig },
    { party: { scheme: 'cci', identifier: sellerCci }, algorithm: 'ed25519', value: sellerAgreementSig },
  ],
};
const agreementAnchoredStr = jcsString(agreementSignedObj);
const agreementAnchoredHash = jcsHashHex(agreementSignedObj);
const agreementLocator = anchorString(sellerOwner, anchorNames.agreement(jobId), agreementAnchoredStr);
log('DACS-3', `agreement ${agreementHash.slice(0, 16)}… (rail=pay-ap2, ${PRICE_AP2} ${CURRENCY}) signed by both; anchored @ ${agreementLocator}`);

// Fetch the agreement back through the anchoring layer, hash-match the exact fetched artifact,
// verify both party signatures, and derive the only agreement facts AP2 semantic verification uses.
// The AP2 record and receipt cannot self-supply or override this trust anchor.
const fetchedAgreementAnchor = memoryAnchors.get(agreementLocator);
if (!fetchedAgreementAnchor) throw new Error('DACS-3 agreement fetch FAILED');
const fetchedAgreementArtifact: unknown = JSON.parse(fetchedAgreementAnchor.data);
if (jcsHashHex(fetchedAgreementArtifact) !== agreementAnchoredHash) {
  throw new Error('DACS-3 fetched agreement does not match agreementRef content hash');
}
const verifiedAgreement = verifyAp2AgreementArtifact(fetchedAgreementArtifact);
log('DACS-3', `fetched agreement signatures verified; AP2 terms independently pinned to ${verifiedAgreement.agreementHash.slice(0, 16)}…`);

// ── DACS-4a — pay-ap2 settlement (MOCK provider + attestation; §9.7 evidence is real) ──────────
const PAY_PHASE_INDEX = 3;

// AP2-1 — create the provider payment session, binding jobId (MUST) + agreementHash (SHOULD).
const session = createAp2PaymentSession({
  jobId: verifiedAgreement.jobId,
  agreementHash: verifiedAgreement.agreementHash,
  amount: verifiedAgreement.amount,
  currency: verifiedAgreement.currency,
});
log('DACS-4', `AP2-1 provider session ${session.providerTxId} created; metadata bound {${Object.keys(session.metadata).join(', ')}}`);

// (mock) facilitator captures + signs the provider receipt.
const facilitator = createMockFacilitator();
const capturedAt = now();
const providerReceipt = signMockProviderReceipt(session, facilitator, capturedAt);
log('DACS-4', `MOCK facilitator (${facilitator.facilitatorKind}) captured ${PRICE_AP2} ${CURRENCY}; receipt signed by stub key ${facilitator.facilitatorPubKey.slice(0, 12)}…`);

// AP2-2 — attested-fetch the provider status endpoint; cross-check status/amount/currency/binding.
// Throws (fail-closed) if any check fails — a bare provider reference MUST NOT pass.
const receiptAttestation = attestAp2Receipt({
  receipt: providerReceipt, verifiedAgreement,
  statusEndpoint: STATUS_ENDPOINT, fetchedAt: now(),
});
log('DACS-4', `AP2-2 attested fetch (${receiptAttestation.type}, scope=${receiptAttestation.credentialScope}) → status=captured, amount+currency+binding cross-checks PASS ✓`);

// §9.7 — the pay-ap2 payment SettlementEvidence (finality: provider-receipt, AP2-4).
// txHash = the rail's canonical reference (SB-1 discipline): ap2:{providerTxId}.
const emittedPayEvidence = emitSettlementEvidenceV1({
  kind: 'payment', jobId, phase: PAY_AP2_RAIL_ID, outcome: 'success',
  paymentTxRefs: [{ rail: PAY_AP2_RAIL_ID, txHash: `ap2:${providerReceipt.providerTxId}`, kind: 'payment' }],
  paymentAmount: PRICE_AP2, paymentCurrency: CURRENCY,
  finalityModel: 'provider-receipt', finalityObservedAt: capturedAt, observedAt: now(),
});
// Open-world extension fields are signed and hash-significant. A detached payment record therefore
// still discloses that it is mock/simulation evidence, even if consumed outside this bundle.
let payEvidence: MockAp2PaymentEvidence = {
  ...emittedPayEvidence,
  ...simulationDisposition,
} as MockAp2PaymentEvidence;
payEvidence = signSettlementEvidenceV1(
  payEvidence,
  `cci:${buyerCci}`,
  buyerKeys.privKey,
) as MockAp2PaymentEvidence;
const payEvidenceStr = jcsString(payEvidence);
const payEvidenceHash = jcsHashHex(payEvidence);
const payEvidenceLocator = anchorString(buyerOwner, anchorNames.paymentEvidence(jobId, PAY_AP2_RAIL_ID, PAY_PHASE_INDEX), payEvidenceStr);
log('DACS-4', `pay-ap2 §9.7 evidence ${payEvidenceHash.slice(0, 16)}… (finality=provider-receipt) signed by buyer; anchored @ ${payEvidenceLocator}`);

// AP2 attested-receipt record — carries the MOCK provider receipt + AP2-2 receiptAttestation,
// buyer-signed, anchored as a bundle-referenced evidence artifact (verifier fetches + hash-checks +
// confirms an authorized deal party signed it). This is where the provider-receipt lands in the bundle.
let ap2Record: Ap2AttestedReceiptRecord = {
  v: 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1',
  simulation: true,
  assurance: AP2_SIMULATION_ASSURANCE,
  jobId: verifiedAgreement.jobId,
  phase: verifiedAgreement.rail,
  phaseIndex: PAY_PHASE_INDEX,
  agreementHash: verifiedAgreement.agreementHash,
  paymentEvidenceHash: evidenceHashV1(payEvidence),
  finalityModel: 'provider-receipt',
  providerReceipt, receiptAttestation, observedAt: now(),
};
const ap2AnchorContext = { paymentEvidenceLogicalAddress: anchorNames.paymentEvidence(jobId, PAY_AP2_RAIL_ID, PAY_PHASE_INDEX), recordLogicalAddress: ap2RecordLogicalAddress(jobId, PAY_PHASE_INDEX) };
ap2Record = signAp2AttestedReceiptRecord(
  ap2Record,
  payEvidence,
  verifiedAgreement,
  `cci:${buyerCci}`,
  buyerKeys.privKey,
  ap2AnchorContext,
);
const ap2RecordStr = jcsString(ap2Record);
const ap2RecordHash = jcsHashHex(ap2Record);
const ap2RecordLocator = anchorString(buyerOwner, `dacs4:ap2-receipt:${jobId}:${PAY_PHASE_INDEX}`, ap2RecordStr);
log('DACS-4', `AP2 attested-receipt record ${ap2RecordHash.slice(0, 16)}… signed by buyer; anchored @ ${ap2RecordLocator}`);

// ── DACS-4b — deliver-storage-program: a synthetic test deliverable, anchored ──────────────────
const DELIVER_PHASE_INDEX = 4;
const deliverableObj = {
  v: 'ap2-test-deliverable:0.1', jobId, agreementHash,
  payload: { note: 'synthetic pay-ap2 test-agent deliverable', settledRail: PAY_AP2_RAIL_ID },
  producedAt: now(),
};
const deliverableContentHash = jcsHashHex(deliverableObj);
const deliverableLocator = anchorString(sellerOwner, anchorNames.deliverable(jobId), jcsString(deliverableObj));
const deliveryEvidence = signSettlementEvidenceV1(emitSettlementEvidenceV1({
  kind: 'delivery', jobId, phase: 'deliver-storage-program', outcome: 'success',
  deliverableContentHash, deliverableAnchorKind: 'storage-program', deliverableAnchorLocator: deliverableLocator,
  observedAt: now(),
}), `cci:${sellerCci}`, sellerKeys.privKey);
const deliveryEvidenceStr = jcsString(deliveryEvidence);
const deliveryEvidenceHash = jcsHashHex(deliveryEvidence);
const deliveryEvidenceLocator = anchorString(sellerOwner, anchorNames.deliveryEvidence(jobId, DELIVER_PHASE_INDEX), deliveryEvidenceStr);
log('DACS-4', `deliverable anchored @ ${deliverableLocator}; delivery evidence @ ${deliveryEvidenceLocator}`);

// ── DACS-5 — both parties emit + anchor AttestationBundleV1; verify ENFORCING ──────────────────
const refFor = (_id: string, locator: string, contentHash: string): AttestationRef => ({
  anchor: { kind: 'storage-program', locator }, contentHash,
});
const phaseSummary: BundlePhaseEntry[] = [
  { index: 0, kind: 'identify', outcome: 'ok' },
  { index: 1, kind: 'vet-credentials', outcome: 'ok' },
  { index: 2, kind: 'negotiate-fixed-price', outcome: 'ok' },
  { index: PAY_PHASE_INDEX, kind: 'pay-ap2', outcome: 'ok' },
  { index: DELIVER_PHASE_INDEX, kind: 'deliver-storage-program', outcome: 'ok' },
];
const unsignedBase = {
  bundleVersion: '1' as const, jobId, outcome: 'completed' as const,
  listingRef: { listingId, version: 1, contentHash: listingHash },
  parties: [
    { role: 'buyer' as const, bundleHash: agreementHash, primaryClaim: { scheme: 'cci' as const, identifier: buyerCci } },
    { role: 'seller' as const, bundleHash: agreementHash, primaryClaim: { scheme: 'cci' as const, identifier: sellerCci } },
  ],
  agreementRef: refFor('dacs-3-agreement', agreementLocator, signatureExcludedHash(agreementSignedObj)),
  phaseSummary,
  vetRecords: [] as AttestationRef[],
  settlementEvidence: [
    refFor('dacs-4-evidence:pay-ap2:mock-simulation', payEvidenceLocator, signatureExcludedHash(payEvidence)),
    refFor('dacs-4-evidence:pay-ap2-attested-receipt:mock-simulation', ap2RecordLocator, signatureExcludedHash(ap2Record)),
    refFor('dacs-4-evidence:deliver-storage-program', deliveryEvidenceLocator, signatureExcludedHash(deliveryEvidence)),
  ],
  recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: now(),
};
const signers = [
  { party: { scheme: 'cci' as const, identifier: buyerCci }, privKey: buyerKeys.privKey },
  { party: { scheme: 'cci' as const, identifier: sellerCci }, privKey: sellerKeys.privKey },
];
const buyerBundle = emitAttestationBundleV1({ ...unsignedBase, anchoredByRole: 'buyer' }, signers);
const sellerBundle = emitAttestationBundleV1({ ...unsignedBase, anchoredByRole: 'seller' }, signers);
anchorString(buyerOwner, anchorNames.bundle(jobId, 'buyer'), jcsString(buyerBundle));
anchorString(sellerOwner, anchorNames.bundle(jobId, 'seller'), jcsString(sellerBundle));
log('DACS-5', `both bundle copies anchored two-sided (${anchorNames.bundle(jobId, 'buyer')} / :seller)`);

const pair = computeAnchorPairV1(jobId);
function gatewayFetch(_rpc: string, addr: string): FetchResult | null {
  const nameFor = addr === pair.buyer
    ? { owner: buyerOwner, name: anchorNames.bundle(jobId, 'buyer') }
    : addr === pair.seller
      ? { owner: sellerOwner, name: anchorNames.bundle(jobId, 'seller') }
      : null;
  const hit = nameFor ? memoryAnchors.get(`name:${nameFor.owner}:${nameFor.name}`) : memoryAnchors.get(addr);
  return hit ? { storageAddress: addr, owner: hit.owner, data: hit.data, sizeBytes: hit.data.length, createdAt: new Date().toISOString() } : null;
}

const verdict = await verifyBundleV1Full(buyerBundle as AttestationBundleV1, {
  rpc: 'dry-run', fetchAnchoredImpl: gatewayFetch as never, requireSignatures: true,
});
log('DACS-5', `twoSided=${verdict.twoSided.outcome} — ${verdict.twoSided.detail.slice(0, 140)}`);
log('DACS-5', `attestation refs: ${verdict.attestationsVerified} verified, ${verdict.attestationsFailed} failed`);

const passed = verdict.rollup === 'pass';

// Self-checks (independent of the bundle walk): the mock provider signature verifies, and the
// AP2-1 binding round-tripped through provider metadata; the buyer signature over the record verifies.
const ap2SemanticVerification = verifyMockAp2AttestedReceiptRecord(
  ap2Record,
  payEvidence,
  verifiedAgreement,
  ap2AnchorContext,
);
const ap2SelfChecks = {
  ap2_1_binding_jobId: providerReceipt.metadata['dacs_job_id'] === jobId,
  ap2_1_binding_agreementHash: providerReceipt.metadata['dacs_agreement_hash'] === agreementHash,
  ap2_2_receiptAttestation_present: !!ap2Record.receiptAttestation && ap2Record.receiptAttestation.observedStatus === 'captured',
  ap2_2_credential_readonly: receiptAttestation.credentialScope === 'payment-status:read-only',
  ap2_4_finality_provider_receipt: (payEvidence as { settlementFinality?: { model?: string } }).settlementFinality?.model === 'provider-receipt',
  simulation_marker_signed_on_payment_evidence:
    payEvidence.simulation === true && payEvidence.assurance === AP2_SIMULATION_ASSURANCE,
  ap2_extension_semantics_verified:
    Object.values(ap2SemanticVerification.checks).every(Boolean),
  buyer_record_sig_verifies: verify(
    DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE,
    Uint8Array.from(Buffer.from(ap2Record.signature!.value, 'base64')),
    new TextEncoder().encode(ap2RecordHashHex(ap2Record)),
    buyerKeys.pubKey,
  ),
};
const allSelfChecks = Object.values(ap2SelfChecks).every(Boolean);
const terminalVerdict = passed && allSelfChecks
  ? AP2_SIMULATION_VERDICT
  : 'SIMULATION FAIL (mock AP2 provider + stub attestation — NOT verified settlement)';

log('DACS-5', `CORE VERIFICATION ROLLUP (mock inputs only): ${verdict.rollup.toUpperCase()}`);
log('DACS-5', `VERDICT: ${terminalVerdict}`);

console.log(JSON.stringify({
  jobId, mode: 'dry-run', rail: PAY_AP2_RAIL_ID,
  simulation: true, assurance: AP2_SIMULATION_ASSURANCE,
  verdict: terminalVerdict,
  providerReceiptMocked: true, facilitatorKind: facilitator.facilitatorKind,
  receiptAttestationType: receiptAttestation.type,
  coreVerificationRollup: verdict.rollup, twoSided: verdict.twoSided.outcome,
  attestationsVerified: verdict.attestationsVerified, attestationsFailed: verdict.attestationsFailed,
  ap2SelfChecks, allSelfChecks,
  anchors: {
    listing: listingLocator, listingProgramName, agreement: agreementLocator,
    payEvidence: payEvidenceLocator, ap2Receipt: ap2RecordLocator,
    deliverable: deliverableLocator, deliveryEvidence: deliveryEvidenceLocator,
  },
}, null, 2));

process.exit(passed && allSelfChecks ? 0 : 1);
