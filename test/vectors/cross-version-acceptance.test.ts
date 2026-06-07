/**
 * Cross-version acceptance (re-pin step 6 / spec §3).
 *
 * Proves the dual-accept posture (§10.4.2 backwards-compat) at the verifier layer:
 *   1. A freshly EMITTED v0.1 AttestationBundleV1 round-trips: emit -> verifyBundleV1 = accept.
 *   2. A legacy `dacs-5-bundle:0.1` bundle still READS: the legacy verifyBundle path accepts it
 *      (re-sealed under the canonical `dacs-bundle:v1:` separator after the §B.7 fold).
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
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
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

test('cross-version: a legacy dacs-5-bundle:0.1 still READS under dual-accept (legacy verifyBundle)', async () => {
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
  // Re-seal under the canonical dacs-bundle:v1: separator (the §B.7 fold) — legacy bundle, current separator.
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, self.priv, bundleHash);
  const legacy: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };

  // Read offline (skip the chain two-sided lookup) — the legacy SIGNATURE must still verify.
  const verdict = await verifyBundle(legacy, { skipTwoSidedLookup: true });
  // Signature step passes; rollup is pass (two-sided is skipped, no attestations).
  const sigStep = verdict.steps.find((s) => s.step === 'verify-signature');
  assert.equal(sigStep?.outcome, 'pass', `legacy signature should verify: ${JSON.stringify(verdict.steps)}`);
  assert.equal(verdict.decision, 'pass');
});
