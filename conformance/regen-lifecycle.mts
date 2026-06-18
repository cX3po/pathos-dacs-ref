/**
 * Regenerate DACS-Standard's quarantined lifecycle vectors FROM OUR VERIFIER, in current v0.1
 * shapes (RB's ask, #137/#143; lifts his quarantine). Deterministic (fixed keys/timestamps) →
 * byte-stable. Emits ONLY the artifacts our reference impl authoritatively produces:
 *   DACS-1 Listing · DACS-2 CompositeVerificationRecord · DACS-4 SettlementEvidence · DACS-5 AttestationBundleV1
 * DACS-3 AgreementDocument is DELIBERATELY OMITTED — out of pathos-dacs-ref's scope (CONTRIBUTING:
 * "DACS-3/DACS-4 out of scope until SR-3/SR-4"); we do not fabricate it. Flagged to RB in the PR.
 *
 *   npx tsx conformance/regen-lifecycle.mts            # emit + self-verify
 *   npx tsx conformance/regen-lifecycle.mts --check    # re-emit + assert byte-identical (tombstone)
 */
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { emitAttestationBundleV1 } from '../src/lib/emit-bundle-v1.js';
import { verifyBundleV1 } from '../src/lib/verify-bundle-v1.js';
import { buildHtlcSettlementEvidence, verifyHtlcSettlementEvidence } from '../src/lib/htlc-evidence.js';
import { jcsHashHex } from '../src/jcs.js';
import type { Listing } from '../src/types/listing.js';
import type { CompositeVerificationRecord, VerifyResult } from '../src/types/verify-result.js';
import type { SettlementEvidence, HtlcLockTxRef, HtlcRevealTxRef } from '../src/types/settle.js';
import { RailAvailability } from '../src/types/settle.js';
import type { AttestationBundleV1 } from '../src/types/bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const mk = (f: number) => { const priv = new Uint8Array(32).fill(f); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; };

// fixed, deterministic inputs → byte-stable output
const buyer = mk(0x41), seller = mk(0x42);
const JOB = 'regen-lifecycle-0001';
const T = '2026-01-01T00:00:00.000Z';
const Tn = Date.parse(T); // epoch-ms for finalisedAt — derived from T so they can never drift apart

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
// every hash below is a REAL sha256(JCS(...)) of real content — no placeholders.
const buyerClaim = { scheme: 'cci' as const, identifier: buyer.pubHex };
const sellerClaim = { scheme: 'cci' as const, identifier: seller.pubHex };
// per-party anchored-identity digest (real, distinct, non-circular — excludes bundleHash itself).
const partyHash = (role: string, claim: { scheme: string; identifier: string }) => jcsHashHex({ jobId: JOB, role, primaryClaim: claim });
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
// signed via the reference impl's own emitter (not a duplicated signing path).
const bundle: AttestationBundleV1 = emitAttestationBundleV1(unsigned, [
  { party: buyerClaim, privKey: buyer.priv },
  { party: sellerClaim, privKey: seller.priv },
]);

// ── self-verify: every artifact our impl can verify must pass ────────────────
const v = verifyBundleV1(bundle);
const bundleOk = v.decision === 'accept' && v.signatureChecks.every((c) => c.decision === 'pass');
// DACS-2 §7.7.1 aggregation invariant (this vector is all-pass): every result pass AND aggregate pass.
const compositeOk = composite.results.every((r) => r.decision === 'pass') && composite.aggregateDecision === 'pass';
const allOk = bundleOk && settleOk && compositeOk;

// ── the regenerated HAPPY-PATH vector (DACS-Standard MANIFEST shape) ──────────
const happy = {
  vectorId: 'dacs-v0.1-happy-path',
  title: 'Happy-path lifecycle (regenerated from pathos-dacs-ref, current v0.1 shapes)',
  dacsVersion: '0.1',
  description: 'Machine-regenerated by pathos-dacs-ref (real signatures/hashes, current shapes). '
    + 'DACS-3 AgreementDocument OMITTED — out of this impl\'s scope (DACS-1/2/4/5 only); source it from the SDK.',
  artifacts: [
    { stage: 'DACS-1', kind: 'Listing', artifact: listing },
    { stage: 'DACS-2', kind: 'CompositeVerificationRecord', artifact: composite },
    { stage: 'DACS-4', kind: 'SettlementEvidence', artifact: settlement },
    { stage: 'DACS-5', kind: 'AttestationBundleV1', artifact: bundle },
  ],
  expectedResult: {
    verifies: true,
    perArtifact: {
      'DACS-1 Listing': 'structurally valid (no signature verifier in this impl)',
      'DACS-2 CompositeVerificationRecord': 'aggregation invariant holds: all results pass → aggregateDecision pass (§7.7.1)',
      'DACS-4 SettlementEvidence': 'verifyHtlcSettlementEvidence → pass (real preimage→hashlock, reveal<timelock, signature checks)',
      'DACS-5 AttestationBundleV1': 'verifyBundleV1 → accept (both party signatures verify)',
    },
    note: 'DACS-3 AgreementDocument omitted — out of this impl\'s scope; do not treat its absence as a failure.',
  },
};

// ── NEGATIVE-PATHS vector — tampered artifacts our verifiers must REJECT ──────
// (real verifier rejections, not hand-labelled — the conformance value is "bad input fails")
// flip the FIRST base64 char (not padding) → still decodes to 64 bytes, but the
// signature is cryptographically wrong: tests real signature-mismatch, not parse failure.
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

const negative = {
  vectorId: 'dacs-v0.1-negative-paths',
  title: 'Negative paths (regenerated) — tampered artifacts the reference verifiers REJECT',
  dacsVersion: '0.1',
  description: 'Each artifact is a valid one that was then tampered; the pathos-dacs-ref verifiers '
    + 'reject it. Conformance use: a compliant verifier MUST NOT accept these.',
  artifacts: [
    { stage: 'DACS-5', kind: 'AttestationBundleV1', tamper: 'one party signature byte flipped', artifact: negBundle },
    { stage: 'DACS-4', kind: 'SettlementEvidence', tamper: 'reveal preimage replaced (no longer hashes to hashlock)', artifact: negSettlement },
  ],
  expectedResult: {
    verifies: false,
    perArtifact: {
      'DACS-5 AttestationBundleV1': `verifyBundleV1 → ${negBundleV.decision} (tampered signature does not verify)`,
      'DACS-4 SettlementEvidence': `verifyHtlcSettlementEvidence → ${negSettleV.decision} (preimage no longer matches hashlock; signature breaks)`,
    },
  },
};

// SELF-VERIFY GATE — enforced in BOTH emit and --check modes (fail-closed):
// if a dependency change makes the happy artifacts reject or the negatives accept,
// neither emitting nor the tombstone check may succeed, even if the JSON bytes are unchanged.
if (!allOk || !negOk) {
  console.error(`SELF-VERIFY FAIL — happy(bundle=${v.decision} settle=${settleV.decision} composite=${compositeOk}) `
    + `neg(bundle=${negBundleV.decision} settle=${negSettleV.decision} bothRejected=${negOk})`);
  process.exit(1);
}

import { mkdirSync } from 'node:fs';
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
console.log(`regen happy : bundle=${v.decision} settlement=${settleV.decision} composite-invariant=${compositeOk} (${h.bytes}B)`);
console.log(`regen negs  : bundle=${negBundleV.decision} settlement=${negSettleV.decision} (both rejected=${negOk}) (${n.bytes}B)`);
console.log(`DACS-3 AgreementDocument omitted by scope (not fabricated).`);
