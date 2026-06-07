/**
 * Cross-version acceptance (re-pin step 6 / spec §3).
 *
 * Proves the dual-accept posture (§10.4.2 backwards-compat) at the verifier layer:
 *   1. A freshly EMITTED v0.1 AttestationBundleV1 round-trips: emit -> verifyBundleV1 = accept.
 *   2. A GENUINE pre-cutover legacy `dacs-5-bundle:0.1` bundle still READS: it is signed under the
 *      OLD `dacs5-bundle:v1:` separator (the literal string that pre-cutover artifacts were sealed
 *      under, NOT the post-cutover canonical `dacs-bundle:v1:`), and the legacy verifyBundle path
 *      still verifies it via the read-only legacy-separator fallback (Codex BLOCKER 3, §10.4.2
 *      backwards-compat). This proves a real backwards-compatible READ, not a re-seal.
 *
 * This mirrors exactly what src/cli/verify.ts dispatches on (bundleVersion vs v).
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { ed25519 } from '@noble/curves/ed25519';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';
import type { AttestationBundle } from '../../src/types/bundle.js';
import { emitAttestationBundleV1 } from '../../src/lib/emit-bundle-v1.js';
import { verifyBundleV1 } from '../../src/lib/verify-bundle-v1.js';
import { verifyBundle } from '../../src/lib/verify-bundle.js';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS, buildSignedBytes } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHash } from '../../src/jcs.js';

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };

test('cross-version: v0.1 emit round-trips (emitAttestationBundleV1 -> verifyBundleV1 accept)', () => {
  const buyer = mk(0x71), seller = mk(0x72);
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId: 'xver-v1-001', outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst-xver', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  const emitted = emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci', identifier: seller.pubHex }, privKey: seller.priv },
  ]);
  const v = verifyBundleV1(emitted);
  assert.equal(v.decision, 'accept', JSON.stringify(v.reasons));
  assert.ok(v.cryptographicallyVerified, 'every emitted signature verifies (single-hash dacs-bundle:v1:)');
  assert.ok(v.signatureChecks.every((c) => c.decision === 'pass'));

  // Tamper after emit -> verifier rejects (binding to bundle content).
  const tampered: AttestationBundleV1 = { ...emitted, outcome: 'failed-perm' };
  assert.equal(verifyBundleV1(tampered).decision, 'reject');
});

test('cross-version: a GENUINE pre-cutover dacs-5-bundle:0.1 (signed under the OLD dacs5-bundle:v1: separator) still READS', async () => {
  const self = mk(0x73);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId: 'xver-legacy-001',
    role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: self.pubHex }, claims: [], issuedAt: '2026-06-02T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed',
    phases: [],
    finalisedAt: '2026-06-02T00:00:02Z',
  };
  // GENUINE pre-cutover artifact: sign under the literal OLD separator `dacs5-bundle:v1:`.
  // This is the string real legacy bundles were sealed under BEFORE the §B.7 fold — NOT the
  // post-cutover canonical `dacs-bundle:v1:`. Sanity-assert the two separators differ so this
  // test cannot silently degrade into a re-seal under the new separator.
  assert.notEqual(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, DOMAIN_SEPARATORS.BUNDLE,
    'guard: the legacy read separator MUST differ from the canonical emission separator');
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  // Produce a GENUINE pre-cutover signature the way OLD code did — by signing the legacy-separator
  // signed-bytes with the raw ed25519 primitive. We DELIBERATELY bypass sign() here: post-FIX-4,
  // sign() refuses LEGACY_READ_SEPARATORS (emission under a retired separator is forbidden). The
  // legacy separator survives ONLY on the verify/read path, which is exactly what this test proves.
  const legacySignedBytes = buildSignedBytes(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, canonical, bundleHash);
  const sig = ed25519.sign(legacySignedBytes, self.priv);
  // Guard: confirm sign() now REFUSES to emit under the legacy separator (FIX 4 hardening).
  assert.throws(() => sign(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, canonical, self.priv, bundleHash),
    /read-only legacy separator/, 'sign() must refuse emission under a LEGACY_READ_SEPARATOR (FIX 4)');
  const legacy: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };

  // Read offline (skip the chain two-sided lookup) — the OLD-separator signature must STILL verify
  // via the read-only legacy-separator fallback. This is the real backwards-compatible read.
  const verdict = await verifyBundle(legacy, { skipTwoSidedLookup: true });
  const sigStep = verdict.steps.find((s) => s.step === 'verify-signature');
  assert.equal(sigStep?.outcome, 'pass', `genuine pre-cutover legacy signature should verify: ${JSON.stringify(verdict.steps)}`);
  assert.ok(sigStep?.detail.includes('legacy separator'), `should report the legacy-separator fallback path; got: ${sigStep?.detail}`);
  assert.equal(verdict.decision, 'pass');
});

test('cross-version: a bundle signed under the NEW canonical separator ALSO still reads (post-cutover artifact)', async () => {
  const self = mk(0x74);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'xver-new-sep-001', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: self.pubHex }, claims: [], issuedAt: '2026-06-07T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ee'.repeat(32) } },
    state: 'completed', phases: [], finalisedAt: '2026-06-07T00:00:02Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, self.priv, bundleHash);
  const newSep: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };
  const verdict = await verifyBundle(newSep, { skipTwoSidedLookup: true });
  const sigStep = verdict.steps.find((s) => s.step === 'verify-signature');
  assert.equal(sigStep?.outcome, 'pass');
  assert.equal(verdict.decision, 'pass');
});

test('cross-version: a bundle signed under NEITHER separator FAILS (no false-accept)', async () => {
  const self = mk(0x75);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'xver-wrong-sep-001', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: self.pubHex }, claims: [], issuedAt: '2026-06-07T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'dd'.repeat(32) } },
    state: 'completed', phases: [], finalisedAt: '2026-06-07T00:00:02Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  // Sign under an unrelated (but registry-known) separator → must NOT verify as a bundle.
  const sig = sign(DOMAIN_SEPARATORS.LISTING, canonical, self.priv, bundleHash);
  const wrong: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };
  const verdict = await verifyBundle(wrong, { skipTwoSidedLookup: true });
  const sigStep = verdict.steps.find((s) => s.step === 'verify-signature');
  assert.equal(sigStep?.outcome, 'fail', 'a bundle signed under a non-bundle separator MUST fail (no separator-confusion accept)');
  assert.equal(verdict.decision, 'fail');
});
