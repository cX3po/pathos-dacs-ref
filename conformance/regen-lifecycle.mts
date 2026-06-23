/**
 * Regenerate DACS-Standard's quarantined lifecycle vectors FROM OUR VERIFIER, in current v0.1
 * shapes AND in DACS-Standard's `validate_conformance_vectors.py` schema (#133 / D2). This
 * ADDRESSES THE DACS-3 §8.5 GAP of #133; it does NOT lift the full quarantine — the deep shape
 * validator (validate_artifact_shapes.py) still fails DACS-1/2/4/5 because the reference impl's
 * Listing / CompositeVerificationRecord / SettlementEvidence types + bundle naming have drifted
 * from the spec's current type blocks (core type convergence, tracked separately).
 * Deterministic (fixed keys/timestamps) → byte-stable.
 *
 * Emits ALL FIVE stages — DACS-1 Listing · DACS-2 CompositeVerificationRecord ·
 * DACS-3 AgreementDocument · DACS-4 SettlementEvidence · DACS-5 AttestationBundleV1. DACS-1/2/4/5
 * are produced by this repo's emitters/types; the DACS-3 AgreementDocument is constructed per §8.5
 * with this repo's signing/canonicalisation helpers (buyer + seller, ed25519, under
 * dacs-agreement:v1:) — not emitted by a production AgreementDocument builder — and self-verified
 * here (recompute agreement hash + verify both signatures). Nothing is fabricated — every signature
 * verifies and every hash is a real sha256 of real content.
 *
 * Output schema = DACS-Standard's REQUIRED_ARTIFACT contract (validate_conformance_vectors.py):
 *   top-level { vectorId, title, dacsVersion:"0.1", description, artifacts[], expectedResult }
 *   artifact  { id, stage, kind, specRefs[], domainSeparator, artifact, contentHash }
 * `contentHash` mirrors the validator's own canonicalisation EXACTLY:
 *   "sha256:" + sha256( json.dumps(artifact, sort_keys=True, separators=(",",":"), ensure_ascii=False) )
 * (recursive key-sort + compact separators; our artifacts are all-ASCII integers/strings so JS
 * JSON.stringify of the key-sorted value is byte-identical to Python's canonical_json.)
 *
 *   npx tsx conformance/regen-lifecycle.mts            # emit + self-verify
 *   npx tsx conformance/regen-lifecycle.mts --check    # re-emit + assert byte-identical (tombstone)
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { emitAttestationBundleV1 } from '../src/lib/emit-bundle-v1.js';
import { verifyBundleV1 } from '../src/lib/verify-bundle-v1.js';
import { buildHtlcSettlementEvidence, verifyHtlcSettlementEvidence } from '../src/lib/htlc-evidence.js';
import { sign, verify } from '../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../src/domain-sep.js';
import { jcsHashHex } from '../src/jcs.js';
import type { Listing } from '../src/types/listing.js';
import type { CompositeVerificationRecord, VerifyResult } from '../src/types/verify-result.js';
import type { SettlementEvidence, HtlcLockTxRef, HtlcRevealTxRef } from '../src/types/settle.js';
import { RailAvailability } from '../src/types/settle.js';
import type { AttestationBundleV1 } from '../src/types/bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const enc = new TextEncoder();
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const mk = (f: number) => { const priv = new Uint8Array(32).fill(f); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; };

// fixed, deterministic inputs → byte-stable output
const buyer = mk(0x41), seller = mk(0x42);
const JOB = 'regen-lifecycle-0001';
const T = '2026-01-01T00:00:00.000Z';
const Tn = Date.parse(T); // epoch-ms for finalisedAt — derived from T so they can never drift apart

// §B.1 ClaimReference canonical wire form is the STRING "Scheme:Identifier".
const buyerClaim = `cci:${buyer.pubHex}`;
const sellerClaim = `cci:${seller.pubHex}`;
// per-party anchored-identity digest (real, distinct, non-circular — excludes any bundleHash itself).
const partyHash = (role: string, claim: string) => jcsHashHex({ jobId: JOB, role, primaryClaim: claim });

// ── validator-mirroring contentHash ──────────────────────────────────────────
// Mirrors DACS-Standard's canonical_json: recursive key-sort + compact separators, UTF-8.
const sortDeep = (val: unknown): unknown => {
  if (Array.isArray(val)) return val.map(sortDeep);
  if (val && typeof val === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(val as Record<string, unknown>).sort()) out[k] = sortDeep((val as Record<string, unknown>)[k]);
    return out;
  }
  return val;
};
const contentHashOf = (val: unknown) => 'sha256:' + hex(sha256(enc.encode(JSON.stringify(sortDeep(val)))));

// ── DACS-1: Listing ──────────────────────────────────────────────────────────
const listing: Listing = {
  v: 'dacs-1-listing:0.1', id: 'lst-regen-0001', version: 1,
  seller: { identity: { primary: { scheme: 'cci', identifier: seller.pubHex } } },
  capability: { key: 'analyze-csv', description: 'CSV row classification', input: 'text/csv', output: 'application/json' },
  price: { amount: '1.50', currency: 'USDC', perUnit: 'row' },
  requiredCapabilities: [],
  buyerRequirements: {
    primaryAcceptable: ['cci'],
    requiredClaims: [],
    verificationRecipes: { cci: 'cci-self-signed@1' } as Record<string, string>,
  },
  acceptedRails: ['pay-x402@1'],
  acceptedNegotiation: ['negotiate-fixed-price'],
  publishedAt: T,
};

// ── DACS-2: CompositeVerificationRecord (wraps a VerifyResult) ────────────────
const vr: VerifyResult = {
  v: 'dacs-2-verify-result:0.1', jobId: JOB,
  claim: { scheme: 'cci', identifier: buyer.pubHex }, recipe: 'cci-self-signed@1',
  decision: 'pass', reason: 'buyer CCI self-signature verified', runAt: T,
};
const composite: CompositeVerificationRecord = {
  v: 'dacs-2-composite-verify:0.1', jobId: JOB, results: [vr], aggregateDecision: 'pass', aggregatedAt: T,
};

// ── DACS-3: AgreementDocument (fixed-price) — REAL, signed by buyer + seller ──
// §8.5 signing: agreement_hash = sha256(JCS(agreement WITHOUT `signatures`)); each
// AgreementSignature.value signs "dacs-agreement:v1:" || agreement_hash. CONVENTION CAVEAT: this
// repo signs the UTF-8 bytes of the hex hash STRING (matching emit-bundle-v1's
// "sep || enc.encode(bundleHash)"), not the raw 32-byte digest — the spec does not pin hex-text vs
// raw bytes, so this is the reference impl's current hash-string convention (flagged to RB).
// Fixed-price requires BOTH buyer + seller signers (§8.5 "required signers by pattern").
const deliverableSpec = { kind: 'attested-payload', format: 'application/json', schema: 'csv-row-classification@1' };
const deliverable = { deliverableType: 'attested-payload', hash: jcsHashHex(deliverableSpec) };
// vetRecordRef → the DACS-2 composite verification record (AttestationRef: anchor + contentHash).
const vetRecordRef = { anchor: { kind: 'storage-program', locator: `demos:vet:${JOB}` }, contentHash: jcsHashHex(composite) };
// NOTE (flagged to RB): this lifecycle does not separately materialise a post-Vet IdentityBundle,
// so AgreementParty.bundleHash is bound to the SAME real per-party anchored-identity digest the
// DACS-5 bundle uses (jcsHashHex{jobId,role,primaryClaim}) — a real digest, not a fabricated
// IdentityBundle hash. Documented in expectedResult.perArtifact below.
const agreementUnsigned = {
  agreementVersion: '1',
  jobId: JOB,
  listingRef: { listingId: listing.id, version: listing.version, contentHash: jcsHashHex(listing) },
  parties: [
    { role: 'buyer', bundleHash: partyHash('buyer', buyerClaim), primaryClaim: buyerClaim, vetRecordRef },
    { role: 'seller', bundleHash: partyHash('seller', sellerClaim), primaryClaim: sellerClaim, vetRecordRef },
  ],
  terms: {
    deliverable,
    // CD-1 (CORE §B.2) minimal-digit canonical decimal: "1.5" (no trailing zero), value == listing 1.50.
    price: { amount: '1.5', currency: 'USDC', unit: 'per-row' },
    rail: { railId: 'evm-erc20:8453:USDC' },
    deadline: Date.parse('2026-01-02T00:00:00.000Z'), // unix ms settle-by deadline
  },
  derivedFromPattern: 'fixed-price',
  generatedAt: Tn,
};
const agreementHash = jcsHashHex(agreementUnsigned);
const agSig = (claim: string, priv: Uint8Array) => ({
  party: claim,
  algorithm: 'ed25519' as const,
  value: Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, enc.encode(agreementHash), priv)).toString('base64'),
});
const agreement = { ...agreementUnsigned, signatures: [agSig(buyerClaim, buyer.priv), agSig(sellerClaim, seller.priv)] };
// self-verify (§8.5 verification): recompute hash from agreement-minus-signatures + verify BOTH sigs.
const { signatures: _omit, ...agreementReHash } = agreement;
const agreementOk =
  jcsHashHex(agreementReHash) === agreementHash &&
  verify(DOMAIN_SEPARATORS.AGREEMENT, Buffer.from(agreement.signatures[0].value, 'base64'), enc.encode(agreementHash), ed25519.getPublicKey(buyer.priv)) &&
  verify(DOMAIN_SEPARATORS.AGREEMENT, Buffer.from(agreement.signatures[1].value, 'base64'), enc.encode(agreementHash), ed25519.getPublicKey(seller.priv));

// ── DACS-4: SettlementEvidence — built by OUR builder, must verify PASS ───────
// real preimage→hashlock binding (hashlock = sha256(preimage)); reveal < timelock.
const preimage = new Uint8Array(32).fill(0xcd);
const hashlock = hex(sha256(preimage));
const lock: HtlcLockTxRef = {
  phase: 'htlc-lock', chain: 'eip155:8453', txHash: 'a1'.repeat(32), hashlock,
  observedAt: T, timelockExpiry: '2026-01-02T00:00:00.000Z', amount: { amount: '1.50', asset: 'USDC', decimals: 6 },
};
const reveal: HtlcRevealTxRef = {
  phase: 'htlc-reveal', chain: 'eip155:8453', txHash: 'c3'.repeat(32), hashlock,
  observedAt: '2026-01-01T06:00:00.000Z', preimage: hex(preimage), revealDeadline: '2026-01-01T12:00:00.000Z',
};
const settlement: SettlementEvidence = buildHtlcSettlementEvidence({
  jobId: JOB, rail: RailAvailability.Mocked, price: { amount: '1.50', asset: 'USDC', decimals: 6 },
  settler: 'buyer', settlerPrivKey: buyer.priv, settlerPubkey: ed25519.getPublicKey(buyer.priv),
  lock, reveal, settledAt: T,
});
const settleV = verifyHtlcSettlementEvidence(settlement);
const settleOk = settleV.decision === 'pass';

// ── DACS-5: AttestationBundleV1 (signed, two-sided) → must verify ACCEPT ──────
const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
  bundleVersion: '1', jobId: JOB, outcome: 'completed', anchoredByRole: 'buyer',
  listingRef: { listingId: listing.id, version: listing.version, contentHash: jcsHashHex(listing) },
  parties: [
    { role: 'buyer', bundleHash: partyHash('buyer', buyerClaim), primaryClaim: buyerClaim },
    { role: 'seller', bundleHash: partyHash('seller', sellerClaim), primaryClaim: sellerClaim },
  ],
  phaseSummary: [
    { index: 0, kind: 'vet-credentials', outcome: 'ok' },
    { index: 1, kind: 'settle', outcome: 'ok' },
  ],
  vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: Tn,
};
const bundle: AttestationBundleV1 = emitAttestationBundleV1(unsigned, [
  { party: buyerClaim, privKey: buyer.priv },
  { party: sellerClaim, privKey: seller.priv },
]);

// ── self-verify: every artifact our impl can verify must pass ────────────────
const v = verifyBundleV1(bundle);
const bundleOk = v.decision === 'accept' && v.signatureChecks.every((c) => c.decision === 'pass');
// DACS-2 §7.7.1 aggregation invariant (this vector is all-pass): every result pass AND aggregate pass.
const compositeOk = composite.results.every((r) => r.decision === 'pass') && composite.aggregateDecision === 'pass';
const allOk = bundleOk && settleOk && compositeOk && agreementOk;

// ── per-stage artifact wrappers (DACS-Standard REQUIRED_ARTIFACT schema) ──────
// specRefs reuse RB's quarantined-vector references (known-good for the validator + spec-accurate).
type Wrapped = { id: string; stage: string; kind: string; specRefs: string[]; domainSeparator: string; artifact: unknown; contentHash: string };
const wrap = (w: Omit<Wrapped, 'contentHash'>): Wrapped => ({ ...w, contentHash: contentHashOf(w.artifact) });

const happyArtifacts: Wrapped[] = [
  wrap({ id: 'listing-analyze-csv', stage: 'DACS-1', kind: 'Listing', specRefs: ['§6.3', '§14.2'], domainSeparator: DOMAIN_SEPARATORS.LISTING, artifact: listing }),
  wrap({ id: 'composite-verify-cci', stage: 'DACS-2', kind: 'CompositeVerificationRecord', specRefs: ['§7.7', '§14.3'], domainSeparator: DOMAIN_SEPARATORS.COMPOSITE_VERIFY, artifact: composite }),
  wrap({ id: 'agreement-fixed-price', stage: 'DACS-3', kind: 'AgreementDocument', specRefs: ['§8.5', '§14.4'], domainSeparator: DOMAIN_SEPARATORS.AGREEMENT, artifact: agreement }),
  wrap({ id: 'settlement-htlc-release', stage: 'DACS-4', kind: 'SettlementEvidence', specRefs: ['§9.7', '§14.5'], domainSeparator: DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, artifact: settlement }),
  wrap({ id: 'attestation-bundle-happy', stage: 'DACS-5', kind: 'AttestationBundleV1', specRefs: ['§10.4', '§14.6'], domainSeparator: DOMAIN_SEPARATORS.BUNDLE, artifact: bundle }),
];

const happy = {
  vectorId: 'dacs-v0.1-happy-path',
  title: 'Happy-path lifecycle (regenerated from pathos-dacs-ref, current v0.1 shapes)',
  dacsVersion: '0.1',
  description: 'Machine-regenerated by pathos-dacs-ref (real signatures/hashes), now covering all '
    + 'five stages incl. a real signed DACS-3 AgreementDocument (§8.5). Addresses the DACS-3 §8.5 '
    + 'gap of #133; full quarantine lift pending core type convergence (DACS-1/2/4/5 impl↔spec drift).',
  artifacts: happyArtifacts,
  expectedResult: {
    verifies: true,
    perArtifact: {
      'DACS-1 Listing': 'structurally valid (no listing signature verifier in this impl)',
      'DACS-2 CompositeVerificationRecord': 'aggregation invariant holds: all results pass → aggregateDecision pass (§7.7.1)',
      'DACS-3 AgreementDocument': 'fixed-price agreement; buyer+seller ed25519 signatures over "dacs-agreement:v1:"||agreement_hash verify (§8.5). bundleHash = real per-party anchored-identity digest (jobId,role,primaryClaim); this lifecycle does not separately materialise an IdentityBundle.',
      'DACS-4 SettlementEvidence': 'verifyHtlcSettlementEvidence → pass (real preimage→hashlock, reveal<timelock, signature checks)',
      'DACS-5 AttestationBundleV1': 'verifyBundleV1 → accept (both party signatures verify)',
    },
  },
};

// ── NEGATIVE-PATHS vector — tampered DACS-4/5 the verifiers REJECT ────────────
// flip the FIRST base64 char (not padding) → still decodes to 64 bytes, but the signature is
// cryptographically wrong: tests real signature-mismatch, not parse failure.
const flipFirst = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
const negBundle: AttestationBundleV1 = { ...bundle, signatures: [{ ...bundle.signatures[0], value: flipFirst(bundle.signatures[0].value) }, bundle.signatures[1]] };
const negBundleV = verifyBundleV1(negBundle);
const negBundleRejected = negBundleV.decision !== 'accept';
// settlement with a tampered reveal preimage → breaks preimage→hashlock AND the signature
const tamperedReveal: HtlcRevealTxRef = { ...reveal, preimage: hex(new Uint8Array(32).fill(0xee)) };
const negSettlement: SettlementEvidence = { ...settlement, txRefs: [settlement.txRefs[0], tamperedReveal] };
const negSettleV = verifyHtlcSettlementEvidence(negSettlement);
const negSettleRejected = negSettleV.decision !== 'pass';
const negOk = negBundleRejected && negSettleRejected;

// The validator requires EVERY vector file to cover DACS-1..5 in order. The negative vector reuses
// the VALID DACS-1/2/3 artifacts (context the verifier accepts) and tampers ONLY DACS-4 + DACS-5.
const negativeArtifacts: Wrapped[] = [
  wrap({ id: 'neg-listing-analyze-csv', stage: 'DACS-1', kind: 'Listing', specRefs: ['§6.3', '§14.2'], domainSeparator: DOMAIN_SEPARATORS.LISTING, artifact: listing }),
  wrap({ id: 'neg-composite-verify-cci', stage: 'DACS-2', kind: 'CompositeVerificationRecord', specRefs: ['§7.7', '§14.3'], domainSeparator: DOMAIN_SEPARATORS.COMPOSITE_VERIFY, artifact: composite }),
  wrap({ id: 'neg-agreement-fixed-price', stage: 'DACS-3', kind: 'AgreementDocument', specRefs: ['§8.5', '§14.4'], domainSeparator: DOMAIN_SEPARATORS.AGREEMENT, artifact: agreement }),
  wrap({ id: 'neg-settlement-tampered-preimage', stage: 'DACS-4', kind: 'SettlementEvidence', specRefs: ['§9.7', '§14.5'], domainSeparator: DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, artifact: negSettlement }),
  wrap({ id: 'neg-bundle-tampered-signature', stage: 'DACS-5', kind: 'AttestationBundleV1', specRefs: ['§10.4', '§14.6'], domainSeparator: DOMAIN_SEPARATORS.BUNDLE, artifact: negBundle }),
];

const negative = {
  vectorId: 'dacs-v0.1-negative-paths',
  title: 'Negative paths (regenerated) — tampered DACS-4/5 artifacts the reference verifiers REJECT',
  dacsVersion: '0.1',
  description: 'DACS-1/2/3 are the valid happy-path artifacts (accepted context); DACS-4 and DACS-5 are '
    + 'each a valid artifact that was then tampered, and the pathos-dacs-ref verifiers reject them. '
    + 'Conformance use: a compliant verifier MUST NOT accept the tampered stages.',
  artifacts: negativeArtifacts,
  expectedResult: {
    verifies: false,
    expectedFailures: [
      { artifactId: 'neg-settlement-tampered-preimage', stage: 'DACS-4', reason: `verifyHtlcSettlementEvidence → ${negSettleV.decision} (reveal preimage replaced; no longer hashes to hashlock, signature breaks)` },
      { artifactId: 'neg-bundle-tampered-signature', stage: 'DACS-5', reason: `verifyBundleV1 → ${negBundleV.decision} (one party signature byte flipped; does not verify)` },
    ],
    perArtifact: {
      'DACS-1 Listing': 'valid (context)',
      'DACS-2 CompositeVerificationRecord': 'valid (context)',
      'DACS-3 AgreementDocument': 'valid (context); signatures verify',
      'DACS-4 SettlementEvidence': `REJECTED — ${negSettleV.decision}`,
      'DACS-5 AttestationBundleV1': `REJECTED — ${negBundleV.decision}`,
    },
  },
};

// SELF-VERIFY GATE — enforced in BOTH emit and --check modes (fail-closed):
// if a dependency change makes the happy artifacts reject (incl. the agreement signatures) or the
// negatives accept, neither emitting nor the tombstone check may succeed.
if (!allOk || !negOk) {
  console.error(`SELF-VERIFY FAIL — happy(bundle=${v.decision} settle=${settleV.decision} composite=${compositeOk} agreement=${agreementOk}) `
    + `neg(bundle=${negBundleV.decision} settle=${negSettleV.decision} bothRejected=${negOk})`);
  process.exit(1);
}

const emit = (file: string, obj: unknown): { bytes: number } => {
  const body = JSON.stringify(obj, null, 2) + '\n';
  const dest = path.join(HERE, 'regen', file);
  if (process.argv.includes('--check')) {
    const prev = existsSync(dest) ? readFileSync(dest, 'utf8') : '';
    if (prev !== body) { console.error(`TOMBSTONE FAIL — ${file} re-emit is NOT byte-identical`); process.exit(1); }
    return { bytes: body.length };
  }
  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, body);
  return { bytes: body.length };
};

const h = emit('dacs-v0.1-happy-path.regen.json', happy);
const n = emit('dacs-v0.1-negative-paths.regen.json', negative);
if (process.argv.includes('--check')) { console.log('TOMBSTONE OK — both re-emit byte-identical (self-verify passed)'); process.exit(0); }
console.log(`regen happy : bundle=${v.decision} settlement=${settleV.decision} composite-invariant=${compositeOk} agreement=${agreementOk} (${h.bytes}B)`);
console.log(`regen negs  : bundle=${negBundleV.decision} settlement=${negSettleV.decision} (both rejected=${negOk}) (${n.bytes}B)`);
console.log(`DACS-3 AgreementDocument: REAL §8.5 fixed-price agreement, buyer+seller signatures verify (agreement_hash=${agreementHash.slice(0, 16)}…).`);
