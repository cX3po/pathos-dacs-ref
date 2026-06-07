/**
 * §10.4 AttestationBundleV1 — CHAIN-side verification tests.
 *
 * Covers the two correctness regressions Codex BLOCKED the v0.1 cutover on:
 *
 *   BLOCKER 1 — §10.4.2/§10.4.3 two-sided anchoring on the v0.1 path:
 *       - both anchors present + consistent + local bound to a side → pass
 *       - neither anchor present (unanchored) → indeterminate (NOT a default pass)
 *       - exactly one anchor present (unilateral) → fail (aborted-by-self)
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
import type { fetchAnchored as FetchAnchored } from '../../src/demos/storage.js';

const enc = new TextEncoder();
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const sha256Hex = (s: string) => hexOf(sha256(enc.encode(s)));
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };

/** Mock fetchAnchored serving a fixed {address → string-data} map. Missing → null. */
function mockFetch(map: Map<string, string>, errAddrs: Set<string> = new Set()): typeof FetchAnchored {
  return (async (_rpc: string, addr: string) => {
    if (errAddrs.has(addr)) throw new Error(`simulated RPC error for ${addr}`);
    const data = map.get(addr);
    if (data === undefined) return null;
    return { storageAddress: addr, owner: '0xowner', data, sizeBytes: data.length, createdAt: '2026-06-07T00:00:00Z' };
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

// ── BLOCKER 1: two-sided anchoring ──────────────────────────────────────────

test('BLOCKER 1: v0.1 both anchors present + consistent → pass (attestationsVerified counted)', async () => {
  const jobId = 'v1-twosided-pass';
  const bundle = makeV1({ jobId });
  const pair = computeAnchorPairV1(jobId);
  // The same finalised bundle is anchored at BOTH role addresses (canonical-equality happy path).
  const map = new Map([[pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)]]);
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.rollup, 'pass', JSON.stringify({ reasons: v.reasons, two: v.twoSided }));
  assert.equal(v.twoSided.outcome, 'pass');
  assert.equal(v.attestationsFailed, 0);
});

test('BLOCKER 1: v0.1 UNANCHORED (neither anchor present) → indeterminate, NOT a default pass', async () => {
  const jobId = 'v1-unanchored';
  const bundle = makeV1({ jobId });
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(new Map()) });
  assert.equal(v.twoSided.outcome, 'indeterminate');
  assert.equal(v.rollup, 'indeterminate', 'unanchored v1 must NOT pass by default');
});

test('BLOCKER 1: v0.1 unilateral (only buyer anchor present) → fail (aborted-by-self for seller)', async () => {
  const jobId = 'v1-unilateral';
  const bundle = makeV1({ jobId });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)]]); // seller missing
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /seller anchor absent/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 1: v0.1 buyer/seller divergence (outcome contradiction) → fail (dispute, §10.4.3(d))', async () => {
  const jobId = 'v1-divergent';
  const buyerCopy = makeV1({ jobId, outcome: 'completed', anchoredByRole: 'buyer' });
  const sellerCopy = makeV1({ jobId, outcome: 'aborted-by-other', anchoredByRole: 'seller' });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(buyerCopy)], [pair.seller, JSON.stringify(sellerCopy)]]);
  // Verify the buyer copy locally (it IS byte-equal to the buyer anchor) — divergence is the reject reason.
  const v = await verifyBundleV1Full(buyerCopy, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /divergence/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 1: v0.1 third bundle riding along the jobId → fail (not byte-equal to either anchor)', async () => {
  const jobId = 'v1-ridealong';
  const realBuyer = makeV1({ jobId, buyerFill: 0x31, sellerFill: 0x32 });
  const realSeller = realBuyer; // canonical-equality happy path
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(realBuyer)], [pair.seller, JSON.stringify(realSeller)]]);
  // A different bundle (different signers) sharing the jobId.
  const third = makeV1({ jobId, buyerFill: 0x41, sellerFill: 0x42 });
  const v = await verifyBundleV1Full(third, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.twoSided.outcome, 'fail');
  assert.match(v.twoSided.detail, /not byte-equal to EITHER/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 1: v0.1 RPC error on an anchor fetch → indeterminate (not a false absence)', async () => {
  const jobId = 'v1-rpcerr';
  const bundle = makeV1({ jobId });
  const pair = computeAnchorPairV1(jobId);
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(new Map(), new Set([pair.buyer])) });
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

test('BLOCKER 2: v0.1 real AttestationRef (content-hash matches) → attestationsVerified counted', async () => {
  const jobId = 'v1-ref-ok';
  const evidence = JSON.stringify({ kind: 'settlement', amount: '42' });
  const locator = 'stor-' + sha256Hex('evidence-anchor');
  const ref = { anchor: { substrate: 'demos' as const, locator }, contentHash: sha256Hex(evidence), type: 'dahr:settlement', producedAt: '2026-06-07T00:00:00Z' };
  const bundle = makeV1({ jobId, settlementEvidence: [ref] });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([
    [pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)],
    [locator, evidence],
  ]);
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsVerified, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.attestationsFailed, 0);
  assert.equal(v.rollup, 'pass');
});

test('BLOCKER 2: v0.1 AttestationRef whose anchor is MISSING → fail (cited evidence does not exist)', async () => {
  const jobId = 'v1-ref-missing';
  const locator = 'stor-' + sha256Hex('missing-anchor');
  const ref = { anchor: { substrate: 'demos' as const, locator }, contentHash: sha256Hex('whatever'), type: 'dahr:settlement', producedAt: '2026-06-07T00:00:00Z' };
  const bundle = makeV1({ jobId, settlementEvidence: [ref] });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)]]); // locator absent
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsFailed, 1, JSON.stringify(v.attestationSteps));
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 2: v0.1 AttestationRef content-hash MISMATCH → fail (§7.5.2)', async () => {
  const jobId = 'v1-ref-mismatch';
  const locator = 'stor-' + sha256Hex('tampered-anchor');
  // contentHash claims one thing; the anchored bytes hash to another.
  const ref = { anchor: { substrate: 'demos' as const, locator }, contentHash: sha256Hex('the-real-evidence'), type: 'dahr:vet', producedAt: '2026-06-07T00:00:00Z' };
  const bundle = makeV1({ jobId, vetRecords: [ref] });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([
    [pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)],
    [locator, 'SOMETHING-ELSE-ENTIRELY'], // hashes to a different value than contentHash
  ]);
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsFailed, 1, JSON.stringify(v.attestationSteps));
  assert.match(v.attestationSteps[0]!.detail, /content-hash mismatch/);
  assert.equal(v.rollup, 'fail');
});

test('BLOCKER 2: v0.1 bundle with NO refs → attestationsVerified=0/failed=0, still passes when anchored', async () => {
  const jobId = 'v1-no-refs';
  const bundle = makeV1({ jobId });
  const pair = computeAnchorPairV1(jobId);
  const map = new Map([[pair.buyer, JSON.stringify(bundle)], [pair.seller, JSON.stringify(bundle)]]);
  const v = await verifyBundleV1Full(bundle, { fetchAnchoredImpl: mockFetch(map) });
  assert.equal(v.attestationsVerified, 0);
  assert.equal(v.attestationsFailed, 0);
  assert.equal(v.rollup, 'pass');
});
