/**
 * §10.4 AttestationBundleV1 — CHAIN-side verification tests.
 *
 * Covers the two correctness regressions Codex BLOCKED the v0.1 cutover on:
 *
 *   BLOCKER 1 — §10.4.2/§10.4.3 two-sided anchoring on the v0.1 path:
 *       - both anchors present + consistent + local bound to a side → pass
 *       - neither anchor present (unanchored) → indeterminate (NOT a default pass)
 *       - exactly one anchor present → §10.4.3(b) signature-set classification:
 *           fully-signed → pass (anchoring omission); single-signed abort → pass
 *           (§10.11 suppression); single-signed non-abort → indeterminate (rejected,
 *           no valid bundle)
 *       - both present but divergent outcome (§10.4.3(d)) → fail (dispute)
 *       - local bundle not byte-equal to either anchored copy (ride-along) → fail
 *       - RPC error on an anchor fetch → indeterminate (not a false absence/dispute)
 *
 *   BLOCKER 2 — §7.5.2 AttestationRef walk on the v0.1 path:
 *       - real ref (fetched, content-hash matches) → verified count increments
 *       - missing ref (anchor not found) → fail
 *       - hash-mismatch ref → fail
 *
 * No real network — fetchAnchored is mocked. The two-sided anchors are derived deterministically
 * from jobId, so the mock map keys are computed via computeAnchorPairV1.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';
import { verifyBundleV1Full, computeAnchorPairV1 } from '../../src/lib/verify-bundle-v1.js';
import { emitAttestationBundleV1 } from '../../src/lib/emit-bundle-v1.js';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS, ADDITIVE_DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical } from '../../src/jcs.js';
import { resolveByOwnerListing, OWNER_LISTING_COMPLETENESS_BOUND, type fetchAnchored as FetchAnchored, type FetchResult } from '../../src/demos/storage.js';

const enc = new TextEncoder();
// Hermetic: absence at the derived address must not fall through to the node's owner listing or name index.
const offline = { resolveByNameImpl: async () => null };
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const sha256Hex = (s: string) => hexOf(sha256(enc.encode(s)));
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };

/** Mock fetchAnchored serving a fixed {address → data} map (string or object anchors). Missing → null. */
function mockFetch(map: Map<string, unknown>, errAddrs: Set<string> = new Set()): typeof FetchAnchored {
  return (async (_rpc: string, addr: string) => {
    if (errAddrs.has(addr)) throw new Error(`simulated RPC error for ${addr}`);
    const data = map.get(addr);
    if (data === undefined) return null;
    return { storageAddress: addr, owner: '0xowner', data, sizeBytes: JSON.stringify(data).length, createdAt: '2026-06-07T00:00:00Z' };
  }) as unknown as typeof FetchAnchored;
}

/** Build a signed, real-key v0.1 bundle for a jobId/outcome with optional refs. */
function makeV1(opts: {
  jobId: string;
  outcome?: AttestationBundleV1['outcome'];
  anchoredByRole?: AttestationBundleV1['anchoredByRole'];
  vetRecords?: AttestationBundleV1['vetRecords'];
  settlementEvidence?: AttestationBundleV1['settlementEvidence'];
  buyerFill?: number;
  sellerFill?: number;
}): AttestationBundleV1 {
  const buyer = mk(opts.buyerFill ?? 0x21), seller = mk(opts.sellerFill ?? 0x22);
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId: opts.jobId, outcome: opts.outcome ?? 'completed', anchoredByRole: opts.anchoredByRole ?? 'buyer',
    listingRef: { listingId: 'lst-x', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: opts.vetRecords ?? [], settlementEvidence: opts.settlementEvidence ?? [],
    recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  return emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci', identifier: seller.pubHex }, privKey: seller.priv },
  ]);
}

/**
 * Build the two-sided anchor map for a job: a buyer-role copy at the buyer address and a
 * seller-role copy at the seller address (FIX 1 — the copy at each role address MUST declare
 * the matching anchoredByRole). The two copies are identical EXCEPT anchoredByRole, so the
 * local `buyerCopy` is byte-equal to the buyer-anchored copy (binds to the buyer side).
 * Returns { buyerCopy, sellerCopy, map } where map can be extended (e.g. evidence locators).
 */
function twoSidedMap(opts: Parameters<typeof makeV1>[0]): {
  buyerCopy: AttestationBundleV1; sellerCopy: AttestationBundleV1; map: Map<string, string>;
} {
  const buyerCopy = makeV1({ ...opts, anchoredByRole: 'buyer' });
  const sellerCopy = makeV1({ ...opts, anchoredByRole: 'seller' });
  const pair = computeAnchorPairV1(opts.jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerCopy)]]);
  return { buyerCopy, sellerCopy, map };
}

// ── BLOCKER 1: two-sided anchoring ──────────────────────────────────────────

test('BLOCKER 1: v0.1 both anchors present + consistent → pass (attestationsVerified counted)', async () => {
  const jobId = 'v1-twosided-pass';
  // FIX 1 — buyer-role copy at buyer addr, seller-role copy at seller addr. Local = buyer copy.
  const { buyerCopy, map } = twoSidedMap({ jobId });
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.rollup, 'pass', JSON.stringify({ reasons: v.reasons, two: v.twoSided }));
  assert.equal(v.twoSided.outcome, 'pass');
  assert.equal(v.attestationsFailed, 0);
});

test('BLOCKER 1: v0.1 UNANCHORED (neither anchor present) → indeterminate, NOT a default pass', async () => {
  const jobId = 'v1-unanchored';
  const bundle = makeV1({ jobId });
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(new Map()) });
  assert.equal(v.twoSided.outcome, 'indeterminate');
  assert.equal(v.rollup, 'indeterminate', 'unanchored v1 must NOT pass by default');
});

test('§10.4.3(b): lone FULLY-SIGNED buyer anchor → pass (anchoring omission, not an abort)', async () => {
  const jobId = 'v1-unilateral';
  const bundle = makeV1({ jobId }); // makeV1 signs with BOTH parties → full §10.4.1 signature set
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)]]); // seller missing
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'pass');
  assert.match(v.twoSided.detail, /anchoring omission/);
  assert.equal(v.rollup, 'pass');
});

test('§10.4.3(b): lone SINGLE-SIGNED copy with ABORT outcome → pass (§10.11 bundle-suppression)', async () => {
  const jobId = 'v1-lone-abort';
  const buyer = mk(0x21);
  // Single-signed abort copy anchored at the buyer address (the signer's own copy).
  const { signatures: _drop, ...unsigned } = makeV1({ jobId, outcome: 'aborted-by-other' });
  void _drop;
  const lone = emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
  ]);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(lone)]]);
  const v = await verifyBundleV1Full(lone, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'pass');
  assert.match(v.twoSided.detail, /bundle-suppression/);
});

test('§10.4.3(b) guard: lone copy with anchoredByRole ↔ address mismatch → fail (FIX 1 applies to the lone copy too)', async () => {
  const jobId = 'v1-lone-rolemismatch';
  const bundle = makeV1({ jobId, anchoredByRole: 'seller' }); // declares seller…
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)]]); // …but anchored at the BUYER address
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /anchoredByRole mismatch/);
});

test('§10.4.3(b) guard: local bundle not byte-equal to the lone anchored copy → fail (ride-along)', async () => {
  const jobId = 'v1-lone-ridealong';
  const anchored = makeV1({ jobId });
  const local = makeV1({ jobId, buyerFill: 0x41, sellerFill: 0x42 }); // same jobId, different signers/bytes
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(anchored)]]);
  const v = await verifyBundleV1Full(local, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /not byte-equal to the lone/);
});

test('§10.4.3(b) guard: lone fully-"signed" copy with INVALID signature bytes → does NOT pass (enforcing verify)', async () => {
  const jobId = 'v1-lone-badsigs';
  const bundle = makeV1({ jobId });
  // Corrupt both signature values — full signature COUNT, invalid signature BYTES.
  const forged = { ...bundle, signatures: bundle.signatures.map((s) => ({ ...s, value: '00'.repeat(64) })) } as AttestationBundleV1;
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(forged)]]);
  const v = await verifyBundleV1Full(forged, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.notEqual(v.twoSided.outcome, 'pass');
  assert.notEqual(v.rollup, 'pass');
});

test('§10.4.3(d): errorClass-only contradiction (same phase outcome) IS a canonical divergence → fail', async () => {
  const jobId = 'v1-errorclass-div';
  // Same outcome + same phase outcome, differing ONLY in errorClass — re-signed after mutation.
  const { signatures: _b, ...bu } = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'buyer' });
  void _b;
  const { signatures: _s, ...su } = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'seller' });
  void _s;
  bu.phaseSummary = [{ index: 0, kind: 'vet-credentials', outcome: 'fail', errorClass: 'transient' }];
  su.phaseSummary = [{ index: 0, kind: 'vet-credentials', outcome: 'fail', errorClass: 'counterparty' }];
  const buyer = mk(0x21), seller = mk(0x22);
  const signers: Parameters<typeof emitAttestationBundleV1>[1] = [
    { party: { scheme: 'cci' as const, identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci' as const, identifier: seller.pubHex }, privKey: seller.priv },
  ];
  const buyerSigned = emitAttestationBundleV1(bu, signers);
  const sellerSigned = emitAttestationBundleV1(su, signers);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerSigned)], [pair.seller, JSON.stringify(sellerSigned)]]);
  const v = await verifyBundleV1Full(buyerSigned, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /errorClass/);
});

test('§10.4.3 ruling #224: phaseSummary INDEX-SET mismatch (phase in one copy only) IS a divergence → fail', async () => {
  const jobId = 'v1-indexset-div';
  // Same outcome, buyer has one phase, seller appends a phantom index-1 entry (the ST-10 gaming
  // vector the carve-out-free ruling closes). Copies must now diverge, not classify unified.
  const { signatures: _b, ...bu } = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'buyer' });
  void _b;
  const { signatures: _s, ...su } = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'seller' });
  void _s;
  bu.phaseSummary = [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }];
  su.phaseSummary = [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }, { index: 1, kind: 'commit-agreement', outcome: 'ok' }];
  const buyer = mk(0x21), seller = mk(0x22);
  const signers: Parameters<typeof emitAttestationBundleV1>[1] = [
    { party: { scheme: 'cci' as const, identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci' as const, identifier: seller.pubHex }, privKey: seller.priv },
  ];
  const buyerSigned = emitAttestationBundleV1(bu, signers);
  const sellerSigned = emitAttestationBundleV1(su, signers);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerSigned)], [pair.seller, JSON.stringify(sellerSigned)]]);
  const v = await verifyBundleV1Full(buyerSigned, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /index-set divergence/);
});

test('§10.4.3(b): lone SINGLE-SIGNED copy with NON-abort outcome → indeterminate (rejected per §10.4.1 — no valid bundle)', async () => {
  const jobId = 'v1-lone-nonabort';
  const buyer = mk(0x21);
  const { signatures: _drop2, ...unsigned } = makeV1({ jobId, outcome: 'completed' });
  void _drop2;
  const lone = emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
  ]);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(lone)]]);
  const v = await verifyBundleV1Full(lone, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'indeterminate');
  assert.match(v.twoSided.detail, /no valid bundle/);
});

test('BLOCKER 1: v0.1 buyer/seller divergence (outcome contradiction) → fail (dispute, §10.4.3(d))', async () => {
  const jobId = 'v1-divergent';
  const buyerCopy = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'buyer' });
  const sellerCopy = makeV1({ jobId, outcome: 'aborted-by-other', anchoredByRole: 'seller' });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerCopy)]]);
  // Verify the buyer copy locally (it IS byte-equal to the buyer anchor) — divergence is the reject reason.
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /divergence/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 1: v0.1 third bundle riding along the jobId → fail (not byte-equal to either anchor)', async () => {
  const jobId = 'v1-ridealong';
  // Role-matched real anchors (FIX 1): buyer copy at buyer addr, seller copy at seller addr.
  const { map } = twoSidedMap({ jobId, buyerFill: 0x31, sellerFill: 0x32 });
  // A different bundle (different signers) sharing the jobId — declares anchoredByRole buyer so it
  // passes the local-side role guard, but its bytes match NEITHER real anchor → ride-along fail.
  const third = makeV1({ jobId, anchoredByRole: 'buyer', buyerFill: 0x41, sellerFill: 0x42 });
  const v = await verifyBundleV1Full(third, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /not byte-equal to EITHER/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 1: v0.1 RPC error on an anchor fetch → indeterminate (not a false absence)', async () => {
  const jobId = 'v1-rpcerr';
  const bundle = makeV1({ jobId });
  const pair = computeAnchorPairV1(jobId);
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(new Map(), new Set([pair.buyer])) });
  assert.equal(v.twoSided.outcome, 'indeterminate');
  assert.match(v.twoSided.detail, /RPC error/);
});

test('BLOCKER 1: v0.1 --offline (skipTwoSidedLookup) → two-sided skipped, structural+sig pass', async () => {
  const jobId = 'v1-offline';
  const bundle = makeV1({ jobId });
  const v = await verifyBundleV1Full(bundle, { skipTwoSidedLookup: true, fetchAnchoredImpl: mockFetch(new Map()) });
  assert.equal(v.twoSided.outcome, 'skipped');
  assert.equal(v.rollup, 'pass', 'offline structural+sig-valid bundle passes; two-sided is skipped scope');
});

// ── BLOCKER 2: §7.5.2 AttestationRef walk ───────────────────────────────────

test('dacs-sdk#38: unsigned hash-matching referenced artifact fails closed', async () => {
  const jobId = 'v1-ref-ok';
  const evidence = JSON.stringify({ evidenceVersion: '1', jobId, phase: 'pay-dem', outcome: 'success', observedAt: 1735689600000 });
  const locator = 'stor-' + sha256Hex('evidence-anchor');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: sha256Hex(evidence) };
  const { buyerCopy, map } = twoSidedMap({ jobId, settlementEvidence: [ref] });
  map.set(locator, evidence);
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsVerified, 0, JSON.stringify(v.attestationSteps));
  assert.equal(v.attestationsFailed, 1);
  assert.match(v.attestationSteps[0]!.detail, /unsigned.*integrity, not authorship/);
  assert.equal(v.rollup, 'fail');
});

test('dacs-sdk#38: properly signed referenced artifact still passes', async () => {
  const jobId = 'v1-ref-signed-ok';
  const buyer = mk(0x21);
  const unsigned = { evidenceVersion: '1', jobId, phase: 'pay-dem', outcome: 'success', observedAt: 1735689600000 };
  const artifactHash = hexOf(sha256(jcsCanonical(unsigned)));
  const value = Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, enc.encode(artifactHash), buyer.priv)).toString('base64');
  const evidence = JSON.stringify({ ...unsigned, signature: { algorithm: 'ed25519', signer: `cci:${buyer.pubHex}`, value } });
  const locator = 'stor-' + sha256Hex('signed-evidence-anchor');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: sha256Hex(evidence) };
  const { buyerCopy, map } = twoSidedMap({ jobId, settlementEvidence: [ref] });
  map.set(locator, evidence);
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsVerified, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.attestationsFailed, 0);
  assert.equal(v.rollup, 'pass', JSON.stringify(v.attestationSteps));
});

test('BLOCKER 2: v0.1 AttestationRef whose anchor is MISSING → fail (cited evidence does not exist)', async () => {
  const jobId = 'v1-ref-missing';
  const locator = 'stor-' + sha256Hex('missing-anchor');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: sha256Hex('whatever') };
  const bundle = makeV1({ jobId, settlementEvidence: [ref] });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)]]); // locator absent
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsFailed, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 2: v0.1 AttestationRef content-hash MISMATCH → fail (§7.5.2)', async () => {
  const jobId = 'v1-ref-mismatch';
  const locator = 'stor-' + sha256Hex('tampered-anchor');
  // contentHash claims one thing; the anchored bytes hash to another.
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: sha256Hex('the-real-evidence') };
  const bundle = makeV1({ jobId, vetRecords: [ref] });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([
    [pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)],
    [locator, 'SOMETHING-ELSE-ENTIRELY'], // hashes to a different value than contentHash
  ]);
  const v = await verifyBundleV1Full(bundle, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsFailed, 1, JSON.stringify(v.attestationSteps));
  assert.match(v.attestationSteps[0]!.detail, /content-hash mismatch/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 2: v0.1 bundle with NO refs → attestationsVerified=0/failed=0, still passes when anchored', async () => {
  const jobId = 'v1-no-refs';
  const { buyerCopy, map } = twoSidedMap({ jobId });
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsVerified, 0);
  assert.equal(v.attestationsFailed, 0);
  assert.equal(v.rollup, 'pass');
});

// ── FIX 1 — anchor-address ↔ anchoredByRole integrity cross-check ─────────────
test('FIX 1: buyer-address anchor declaring anchoredByRole "seller" → fail (address↔role mismatch)', async () => {
  const jobId = 'fix1-buyer-addr-seller-role';
  // Put a SELLER-role copy at the BUYER address (and a correct seller copy at the seller address).
  const buyerImpostor = makeV1({ jobId, anchoredByRole: 'seller' }); // wrong role for the buyer addr
  const sellerCopy = makeV1({ jobId, anchoredByRole: 'seller' });
  const local = makeV1({ jobId, anchoredByRole: 'buyer' });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerImpostor)], [pair.seller, JSON.stringify(sellerCopy)]]);
  const v = await verifyBundleV1Full(local, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail', JSON.stringify(v.twoSided));
  assert.match(v.twoSided.detail, /anchoredByRole mismatch/);
  assert.match(v.twoSided.detail, /buyer address/);
  assert.equal(v.rollup, 'fail');
});

test('FIX 1: seller-address anchor declaring anchoredByRole "buyer" → fail (address↔role mismatch)', async () => {
  const jobId = 'fix1-seller-addr-buyer-role';
  const buyerCopy = makeV1({ jobId, anchoredByRole: 'buyer' });
  const sellerImpostor = makeV1({ jobId, anchoredByRole: 'buyer' }); // wrong role for the seller addr
  const local = makeV1({ jobId, anchoredByRole: 'buyer' });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerImpostor)]]);
  const v = await verifyBundleV1Full(local, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail', JSON.stringify(v.twoSided));
  assert.match(v.twoSided.detail, /anchoredByRole mismatch/);
  assert.match(v.twoSided.detail, /seller address/);
  assert.equal(v.rollup, 'fail');
});

test('FIX 1: role-matched copies at the right addresses → pass (positive control)', async () => {
  const jobId = 'fix1-role-matched-pass';
  const { buyerCopy, map } = twoSidedMap({ jobId });
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'pass', JSON.stringify(v.twoSided));
  assert.equal(v.rollup, 'pass');
});

// ── FIX 3 — anchored counterparty copies are ENFORCING by default ─────────────
//
// To isolate FIX 3 we need an UNVERIFIABLE (not hard-fail) counterparty: a hard-fail sig is
// rejected in BOTH modes (anyHardFail), so it wouldn't distinguish enforcing from fixture. A
// seller copy whose parties present placeholder DIDs (not raw cci keys) yields `unverifiable`
// signatures — accepted in fixture mode (requireSignatures:false), REJECTED in enforcing mode
// (the default). That is exactly the surface FIX 3 closes.

/**
 * Build a seller-role copy whose signers are placeholder DIDs ⇒ every signature is `unverifiable`
 * (structurally valid + signer-rule satisfied, but no resolvable ed25519 key). It is verifiable
 * `accept` ONLY under fixture mode. Mirrors the cross-impl contributor fixtures' DID signers.
 */
function makeUnverifiableSellerCopy(jobId: string): AttestationBundleV1 {
  // Bare-DID claims (the verifier accepts these at runtime; the TS type is the object form, so the
  // illustrative fixtures cast — exactly the placeholder-DID shape the cross-impl #117 fixtures use).
  type Claim = AttestationBundleV1['parties'][number]['primaryClaim'];
  const buyerDid = 'did:dacs:buyer-placeholder-001' as unknown as Claim;
  const sellerDid = 'did:dacs:seller-placeholder-001' as unknown as Claim;
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId, outcome: 'completed', anchoredByRole: 'seller',
    listingRef: { listingId: 'lst-x', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: buyerDid },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: sellerDid },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  // A syntactically-valid 64-byte ed25519 sig value, but the DID party resolves to NO key ⇒
  // verifyBundleV1 marks it `unverifiable` (not `fail`). One sig per listed DID party.
  const placeholderSig = Buffer.alloc(64, 0x01).toString('base64');
  return {
    ...unsigned,
    signatures: [
      { party: buyerDid, algorithm: 'ed25519', value: placeholderSig },
      { party: sellerDid, algorithm: 'ed25519', value: placeholderSig },
    ],
  };
}

test('FIX 3: counterparty (seller) anchor with UNVERIFIABLE signatures → indeterminate, NOT accepted (enforcing default, §7.5.1)', async () => {
  const jobId = 'fix3-unverifiable-counterparty';
  const buyerCopy = makeV1({ jobId, anchoredByRole: 'buyer' }); // local binds here (real keys)
  const sellerUnverifiable = makeUnverifiableSellerCopy(jobId);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerUnverifiable)]]);
  // DEFAULT (enforcing) — the unverifiable seller anchor must NOT be accepted. §7.5.1 do-not-collapse:
  // an unresolvable-key anchor is UNDECIDABLE → indeterminate, not a hard fail (fixed 2026-06-19; was 'fail').
  // FIX 3's security property ("not accepted") is preserved — indeterminate ≠ pass.
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'indeterminate', JSON.stringify(v.twoSided));
  assert.match(v.twoSided.detail, /undecidable/);
  assert.equal(v.rollup, 'indeterminate');
  assert.notEqual(v.rollup, 'pass'); // never silently pass an unverifiable counterparty
});

test('FIX 3: caller may OPT IN to fixture mode (requireSignatures:false) → unverifiable counterparty accepted', async () => {
  const jobId = 'fix3-unverifiable-counterparty'; // SAME inputs as above — only the mode differs
  const buyerCopy = makeV1({ jobId, anchoredByRole: 'buyer' });
  const sellerUnverifiable = makeUnverifiableSellerCopy(jobId);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerUnverifiable)]]);
  // Caller EXPLICITLY opts into fixture mode → the unverifiable counterparty anchor is accepted.
  const v = await verifyBundleV1Full(buyerCopy, { requireSignatures: false, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'pass', JSON.stringify(v.twoSided));
  assert.equal(v.rollup, 'pass');
});

// ── LIVE attempt 6 (2026-09-06): the published verifier could not read the coordinator's own bundles ──

test('Demos-assigned addresses: party copies absent at the derived address resolve by (owner, derived name) → pass; wrong owner or transport failure never passes', async () => {
  const jobId = 'v1-name-resolved';
  const { buyerCopy, sellerCopy } = twoSidedMap({ jobId });
  const pair = computeAnchorPairV1(jobId);
  // The node assigned these addresses; the derived §10.4.2 address is only the program NAME.
  const native = { buyer: 'stor-' + sha256Hex('native-buyer'), seller: 'stor-' + sha256Hex('native-seller') };
  const map = new Map<string, unknown>([[native.buyer, JSON.stringify(buyerCopy)], [native.seller, JSON.stringify(sellerCopy)]]);
  const buyerOwner = '0x' + mk(0x21).pubHex, sellerOwner = '0x' + mk(0x22).pubHex;
  const asked: string[] = [];
  const found = (addr: string, owner: string): FetchResult => ({ storageAddress: addr, owner, data: map.get(addr), sizeBytes: 1, createdAt: '2026-06-07T00:00:00Z' } as unknown as FetchResult);
  const resolveByNameImpl = async (_rpc: string, owner: string, name: string): Promise<FetchResult | null> => {
    asked.push(`${owner === buyerOwner ? 'buyer-owner' : owner === sellerOwner ? 'seller-owner' : owner}:${name === pair.buyer ? 'buyer-name' : name === pair.seller ? 'seller-name' : name}`);
    if (owner === buyerOwner && name === pair.buyer) return found(native.buyer, owner);
    if (owner === sellerOwner && name === pair.seller) return found(native.seller, owner);
    return null;
  };
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map), resolveByNameImpl });
  assert.equal(v.twoSided.outcome, 'pass', JSON.stringify(v.twoSided));
  assert.equal(v.rollup, 'pass', JSON.stringify(v.reasons));
  assert.deepEqual(asked.sort(), ['buyer-owner:buyer-name', 'seller-owner:seller-name']);
  // Nothing under the party's own key (a name squatter under another owner is absent for this party) → indeterminate, not a pass.
  const none = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map), resolveByNameImpl: async () => null });
  assert.equal(none.twoSided.outcome, 'indeterminate');
  assert.match(none.twoSided.detail, /by address or by owner-bound name/);
  // A resolver transport failure is an error, never absence.
  const down = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map), resolveByNameImpl: async () => { throw new Error('search transport down'); } });
  assert.equal(down.twoSided.outcome, 'indeterminate');
  assert.match(down.twoSided.detail, /name resolution for (buyer|seller)/);
  // Copies present at the derived addresses never consult the resolver.
  const legacy = twoSidedMap({ jobId: 'v1-derived-present' });
  let consulted = 0;
  const l = await verifyBundleV1Full(legacy.buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(legacy.map), resolveByNameImpl: async () => { consulted++; return null; } });
  assert.equal(l.twoSided.outcome, 'pass'); assert.equal(consulted, 0);
});

test('object-anchored referenced artifacts hash by JCS: a signed evidence OBJECT verifies, a tampered object fails', async () => {
  const jobId = 'v1-object-ref';
  const buyer = mk(0x21);
  const unsigned = { evidenceVersion: '1', jobId, phase: 'pay-dem', outcome: 'success', observedAt: 1735689600000 };
  const artifactHash = hexOf(sha256(jcsCanonical(unsigned)));
  const value = Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, enc.encode(artifactHash), buyer.priv)).toString('base64');
  const evidence = { ...unsigned, signature: { algorithm: 'ed25519', signer: `cci:${buyer.pubHex}`, value } };
  const locator = 'stor-' + sha256Hex('object-evidence-anchor');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: hexOf(sha256(jcsCanonical(evidence))) };
  const { buyerCopy, map } = twoSidedMap({ jobId, settlementEvidence: [ref] });
  const objectMap = new Map<string, unknown>(map); objectMap.set(locator, evidence);
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(objectMap) });
  assert.equal(v.attestationsVerified, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.attestationsFailed, 0);
  assert.equal(v.rollup, 'pass', JSON.stringify(v.attestationSteps));
  // The same object with one field changed no longer matches the cited content hash.
  const tampered = new Map<string, unknown>(map); tampered.set(locator, { ...evidence, outcome: 'failed' });
  const t = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(tampered) });
  assert.equal(t.attestationsFailed, 1, JSON.stringify(t.attestationSteps));
  assert.match(t.attestationSteps[0]!.detail, /content-hash mismatch/);
  assert.equal(t.rollup, 'fail');
  // An anchored record with no data at all is indeterminate, not a pass.
  const empty = new Map<string, unknown>(map); empty.set(locator, null);
  const n = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(empty) });
  assert.equal(n.attestationSteps[0]!.outcome, 'indeterminate');
});

test('finality-commitment referenced artifact: pinned orchestrator signs this job\'s commitment → verified; foreign signer, other job, missing pin, bad pin or repeated party never pass', async () => {
  const jobId = 'v1-commitment-ref';
  const buyer = mk(0x21), seller = mk(0x22), stranger = mk(0x33);
  const signCommitment = (unsigned: Record<string, unknown>, signerKey: { priv: Uint8Array; pubHex: string }) => {
    const scope = hexOf(sha256(jcsCanonical(unsigned)));
    const value = Buffer.from(sign(ADDITIVE_DOMAIN_SEPARATORS.FINALITY_COMMITMENT, enc.encode(scope), signerKey.priv)).toString('base64');
    return { ...unsigned, signature: { algorithm: 'ed25519', signer: `cci:${signerKey.pubHex}`, value } };
  };
  const commitmentFor = (job: string, signerKey: { priv: Uint8Array; pubHex: string }, parties = [`cci:${buyer.pubHex}`, `cci:${seller.pubHex}`]) =>
    signCommitment({ finalityCommitmentVersion: '1', jobId: job, agreementHash: 'ab'.repeat(32), listingRef: { listingId: 'lst-x', version: 1, contentHash: 'cd'.repeat(32) },
      parties, pattern: 'fixed-price', createdAt: 1735689600000 }, signerKey);
  const refFor = (artifact: object, locator: string, signer?: string) => ({ anchor: { kind: 'storage-program' as const, locator }, contentHash: hexOf(sha256(jcsCanonical(artifact))), ...(signer ? { signer } : {}) });
  const run = async (artifact: object, signer?: string) => {
    const locator = 'stor-' + sha256Hex(JSON.stringify(artifact) + String(signer));
    const c = twoSidedMap({ jobId, settlementEvidence: [refFor(artifact, locator, signer)] });
    const m = new Map<string, unknown>(c.map); m.set(locator, artifact);
    return verifyBundleV1Full(c.buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(m) });
  };
  // The seller (orchestrator in the reference topology) signs this job's commitment and the reference pins it: verified.
  const good = commitmentFor(jobId, seller);
  const v = await run(good, `cci:${seller.pubHex}`);
  assert.equal(v.attestationsVerified, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.rollup, 'pass', JSON.stringify(v.attestationSteps));
  // A key outside the bundle's parties signed it: hash matches, authorship fails.
  const f = await run(commitmentFor(jobId, stranger), `cci:${seller.pubHex}`);
  assert.equal(f.attestationsFailed, 1, JSON.stringify(f.attestationSteps));
  assert.match(f.attestationSteps[0]!.detail, /not authorized/);
  assert.equal(f.rollup, 'fail');
  // Another job's commitment, correctly signed and pinned: fail.
  const o = await run(commitmentFor('some-other-job', seller), `cci:${seller.pubHex}`);
  assert.equal(o.attestationsFailed, 1); assert.match(o.attestationSteps[0]!.detail, /for job some-other-job/);
  // No pinned signer and no distinct orchestrator party: the authority cannot be established → indeterminate, never a pass.
  const u = await run(good);
  assert.equal(u.attestationSteps[0]!.outcome, 'indeterminate', JSON.stringify(u.attestationSteps));
  assert.match(u.attestationSteps[0]!.detail, /authority is not resolvable/);
  assert.notEqual(u.rollup, 'pass');
  // A pin naming a key that is not a listed party is a fail, not an authority.
  const b = await run(good, `cci:${stranger.pubHex}`);
  assert.equal(b.attestationsFailed, 1); assert.match(b.attestationSteps[0]!.detail, /pinned signer is not the authority/);
  // A commitment listing the buyer twice does not bind both parties, even when correctly signed and pinned.
  const d = await run(commitmentFor(jobId, seller, [`cci:${buyer.pubHex}`, `cci:${buyer.pubHex}`]), `cci:${seller.pubHex}`);
  assert.equal(d.attestationsFailed, 1, JSON.stringify(d.attestationSteps)); assert.match(d.attestationSteps[0]!.detail, /exactly the bundle's buyer and seller/);
});

test('owner-bound resolution discipline: a record under another owner is absent for the party; ambiguous, malformed or possibly truncated listings are errors, never absence', async () => {
  const jobId = 'v1-owner-discipline';
  const { buyerCopy, sellerCopy } = twoSidedMap({ jobId });
  const pair = computeAnchorPairV1(jobId);
  const buyerOwner = '0x' + mk(0x21).pubHex;
  const native = { buyer: 'stor-' + sha256Hex('nd-buyer'), seller: 'stor-' + sha256Hex('nd-seller') };
  const map = new Map<string, unknown>([[native.buyer, JSON.stringify(buyerCopy)], [native.seller, JSON.stringify(sellerCopy)]]);
  // The resolver hands back a record that carries a different owner: absent for this party → nothing anchored → indeterminate.
  const wrongOwner = async (_rpc: string, _owner: string, name: string): Promise<FetchResult | null> =>
    name === pair.buyer ? ({ storageAddress: native.buyer, owner: '0x' + 'ee'.repeat(32), data: map.get(native.buyer), sizeBytes: 1, createdAt: 'x' } as unknown as FetchResult) : null;
  const w = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(map), resolveByNameImpl: wrongOwner });
  assert.equal(w.twoSided.outcome, 'indeterminate'); assert.match(w.twoSided.detail, /neither party anchor present/);
  // resolveByOwnerListing itself, over a fake node transport.
  const listing = (entries: unknown, result = 200) => (async () => ({ ok: true, status: 200, json: async () => ({ result, response: entries }) })) as unknown as typeof fetch;
  // The address read returns the record with its on-chain owner (the buyer wallet), as the node does.
  const read = (async (_rpc: string, addr: string) => addr === native.buyer ? { storageAddress: addr, owner: buyerOwner, data: JSON.stringify(buyerCopy), sizeBytes: 1, createdAt: 'x' } : null) as unknown as typeof FetchAnchored;
  const found = await resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([{ storageAddress: native.buyer, programName: pair.buyer, owner: buyerOwner }]), fetchAnchoredImpl: read });
  assert.equal(found?.storageAddress, native.buyer);
  const none = await resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([{ storageAddress: 'stor-other', programName: 'something-else', owner: buyerOwner }]), fetchAnchoredImpl: read });
  assert.equal(none, null);
  await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([{ storageAddress: native.buyer, programName: pair.buyer }, { storageAddress: 'stor-second', programName: pair.buyer }]), fetchAnchoredImpl: read }), /ambiguous/);
  await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing({ not: 'an array' }), fetchAnchoredImpl: read }), /malformed listing/);
  await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([null]), fetchAnchoredImpl: read }), /malformed/);
  // Entries that cannot be read as a program are errors too, even when another entry could have matched: an unreadable entry could be the copy.
  for (const bad of [[{}], [[]], [{ storageAddress: 'stor-x', programName: 42 }], [{ programName: pair.buyer }], [{ storageAddress: native.buyer, programName: pair.buyer, owner: 7 }]]) {
    await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing(bad), fetchAnchoredImpl: read }), /malformed/, JSON.stringify(bad));
  }
  await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([], 500), fetchAnchoredImpl: read }), /result=500/);
  const crowded = Array.from({ length: OWNER_LISTING_COMPLETENESS_BOUND }, (_, i) => ({ storageAddress: `stor-${i}`, programName: `other-${i}`, owner: buyerOwner }));
  await assert.rejects(resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing(crowded), fetchAnchoredImpl: read }), /completeness not established/);
  // The listing is a hint: a listed entry whose record carries another owner resolves to nothing.
  const foreignRead = (async () => ({ storageAddress: native.buyer, owner: '0x' + 'ee'.repeat(32), data: 'x', sizeBytes: 1, createdAt: 'x' })) as unknown as typeof FetchAnchored;
  assert.equal(await resolveByOwnerListing('rpc', buyerOwner, pair.buyer, { fetchImpl: listing([{ storageAddress: native.buyer, programName: pair.buyer, owner: buyerOwner }]), fetchAnchoredImpl: foreignRead }), null);
});

test('an anchored object that cannot be canonicalized fails the attestation instead of escaping the walk', async () => {
  const jobId = 'v1-uncanonical';
  const locator = 'stor-' + sha256Hex('uncanonical');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: 'ab'.repeat(32) };
  const { buyerCopy, map } = twoSidedMap({ jobId, settlementEvidence: [ref] });
  const weird = new Map<string, unknown>(map);
  // A self-returning toJSON never terminates canonically; a lone surrogate is not UTF-8-encodable.
  weird.set(locator, { evidenceVersion: '1', text: '\ud800', toJSON() { return this; } });
  const v = await verifyBundleV1Full(buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(weird) });
  assert.equal(v.attestationsFailed, 1, JSON.stringify(v.attestationSteps));
  assert.match(v.attestationSteps[0]!.detail, /not canonicalizable|content-hash mismatch/);
  assert.equal(v.rollup, 'fail');
});

test('a lone single-signing abort party cannot pin itself as the commitment authority: the fallback pin needs both deal parties verified on the bundle', async () => {
  const jobId = 'v1-abort-selfpin';
  const buyer = mk(0x21), seller = mk(0x22);
  const unsignedCommitment = { finalityCommitmentVersion: '1', jobId, agreementHash: 'ab'.repeat(32), listingRef: { listingId: 'lst-x', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [`cci:${buyer.pubHex}`, `cci:${seller.pubHex}`], pattern: 'fixed-price', createdAt: 1735689600000 };
  const value = Buffer.from(sign(ADDITIVE_DOMAIN_SEPARATORS.FINALITY_COMMITMENT, enc.encode(hexOf(sha256(jcsCanonical(unsignedCommitment)))), buyer.priv)).toString('base64');
  const commitment = { ...unsignedCommitment, signature: { algorithm: 'ed25519', signer: `cci:${buyer.pubHex}`, value } };
  const locator = 'stor-' + sha256Hex('abort-selfpin-commitment');
  const ref = { anchor: { kind: 'storage-program' as const, locator }, contentHash: hexOf(sha256(jcsCanonical(commitment))), signer: `cci:${buyer.pubHex}` };
  // The buyer alone signs an abort bundle whose reference pins the buyer as the commitment's authority.
  const { signatures: _drop, ...unsigned } = makeV1({ jobId, outcome: 'aborted-by-other', settlementEvidence: [ref] });
  void _drop;
  const lone = emitAttestationBundleV1(unsigned, [{ party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv }]);
  const pair = computeAnchorPairV1(jobId);
  const map = new Map<string, unknown>([[pair.buyer, JSON.stringify(lone)], [locator, commitment]]);
  const v = await verifyBundleV1Full(lone, { ...offline, fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'pass'); // §10.11 suppression still stands for the bundle itself…
  assert.equal(v.attestationSteps[0]!.outcome, 'indeterminate', JSON.stringify(v.attestationSteps)); // …but the self-pinned commitment is not authority.
  assert.match(v.attestationSteps[0]!.detail, /authority is not resolvable/);
  assert.notEqual(v.rollup, 'pass');
  // With both parties' signatures on the bundle, the same pin is authority and the commitment verifies.
  const both = makeV1({ jobId, settlementEvidence: [ref] });
  const bothMap = new Map<string, unknown>([[pair.buyer, JSON.stringify(both)], [pair.seller, JSON.stringify(makeV1({ jobId, settlementEvidence: [ref], anchoredByRole: 'seller' }))], [locator, commitment]]);
  const ok = await verifyBundleV1Full(both, { ...offline, fetchAnchoredImpl: mockFetch(bothMap) });
  assert.equal(ok.attestationsVerified, 1, JSON.stringify(ok.attestationSteps));
});

test('agreement referenced artifact: this job\'s document naming the bundle\'s buyer and seller, signed by both → verified; another job, another party or a missing party signature never pass', async () => {
  const jobId = 'v1-agreement-ref';
  const buyer = mk(0x21), seller = mk(0x22), stranger = mk(0x33);
  const signAgreement = (unsigned: Record<string, unknown>, signers: Array<{ priv: Uint8Array; pubHex: string }>) => {
    const scope = hexOf(sha256(jcsCanonical(unsigned)));
    return { ...unsigned, signatures: signers.map((k) => ({ party: `cci:${k.pubHex}`, algorithm: 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, enc.encode(scope), k.priv)).toString('base64') })) };
  };
  const agreementFor = (job: string, parties: Array<{ role: string; key: { pubHex: string } }>, signers: Array<{ priv: Uint8Array; pubHex: string }>) =>
    signAgreement({ agreementVersion: '1', jobId: job, listingRef: { listingId: 'lst-x', version: 1, contentHash: 'cd'.repeat(32) },
      parties: parties.map((p) => ({ role: p.role, bundleHash: 'aa'.repeat(32), primaryClaim: `cci:${p.key.pubHex}`, vetRecordRef: { anchor: { kind: 'storage-program', locator: 'vet' }, contentHash: 'ef'.repeat(32) } })),
      terms: { price: { amount: '1', currency: 'DEM' }, deliverable: { deliverableType: 'storage-program', hash: 'de'.repeat(32) }, deadline: 1735689600000 },
      derivedFromPattern: 'fixed-price', generatedAt: 1735689600000 }, signers);
  const refFor = (artifact: object, locator: string, signer?: string) => ({ anchor: { kind: 'storage-program' as const, locator }, contentHash: hexOf(sha256(jcsCanonical(artifact))), ...(signer ? { signer } : {}) });
  const run = async (artifact: object, signer?: string) => {
    const locator = 'stor-' + sha256Hex(JSON.stringify(artifact) + String(signer));
    const c = twoSidedMap({ jobId, settlementEvidence: [refFor(artifact, locator, signer)] });
    const m = new Map<string, unknown>(c.map); m.set(locator, artifact);
    return verifyBundleV1Full(c.buyerCopy, { ...offline, fetchAnchoredImpl: mockFetch(m) });
  };
  const pair = [{ role: 'buyer', key: buyer }, { role: 'seller', key: seller }];
  const v = await run(agreementFor(jobId, pair, [buyer, seller]));
  assert.equal(v.attestationsVerified, 1, JSON.stringify(v.attestationSteps)); assert.equal(v.rollup, 'pass');
  const o = await run(agreementFor('some-other-job', pair, [buyer, seller]));
  assert.equal(o.attestationsFailed, 1, JSON.stringify(o.attestationSteps)); assert.match(o.attestationSteps[0]!.detail, /for job some-other-job/);
  const s = await run(agreementFor(jobId, [{ role: 'buyer', key: stranger }, { role: 'seller', key: seller }], [stranger, seller]));
  assert.equal(s.attestationsFailed, 1, JSON.stringify(s.attestationSteps)); assert.match(s.attestationSteps[0]!.detail, /buyer and seller/);
  const h = await run(agreementFor(jobId, pair, [seller]));
  assert.equal(h.attestationsFailed, 1, JSON.stringify(h.attestationSteps)); assert.match(h.attestationSteps[0]!.detail, /missing authorized party signature/);
  // A pin never replaces the parties' authority: a document naming the right job and parties but signed only by a pinned stranger fails.
  const p = await run(agreementFor(jobId, pair, [stranger]), `cci:${stranger.pubHex}`);
  assert.equal(p.attestationsFailed, 1, JSON.stringify(p.attestationSteps)); assert.match(p.attestationSteps[0]!.detail, /not authorized/);
  // A pin naming a party does not excuse the other party's signature.
  const q = await run(agreementFor(jobId, pair, [seller]), `cci:${seller.pubHex}`);
  assert.equal(q.attestationsFailed, 1, JSON.stringify(q.attestationSteps)); assert.match(q.attestationSteps[0]!.detail, /missing authorized party signature/);
});
