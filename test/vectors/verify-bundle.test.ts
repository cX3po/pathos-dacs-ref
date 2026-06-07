/**
 * DACS-5 envelope-receipt verifier — unit tests
 *
 * Locks in the §7.5.1 + §7.5.2 + §10.4 invariants under controlled inputs.
 * No network — bundles are crafted in-test, signed with generated keys,
 * and verified offline (skipTwoSidedLookup=true).
 *
 * Critical invariants this file PROVES:
 *   - Valid signature + intact payload + no attestations → pass
 *   - Tampered signature → fail (never pass)
 *   - Mutated payload → fail (never pass)
 *   - Missing signature → fail (never pass)
 *   - Non-cci primary scheme → indeterminate (never pass — v0.2 scope)
 *   - dahr-stub: attestation type → indeterminate (never pass — no validator quorum)
 *   - computeAnchorPair determinism
 *   - resolvePrimaryClaimPubkey returns null for unsupported schemes
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import type { AttestationBundle } from '../../src/types/index.js';
import { verifyBundle, computeAnchorPair, resolvePrimaryClaimPubkey, hexToBytes, bytesToHex } from '../../src/lib/verify-bundle.js';
import { sign, generateKeypair } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHash } from '../../src/jcs.js';

/** Build a valid signed bundle for testing. */
function makeSignedBundle(opts: { jobId?: string; role?: 'buyer' | 'seller' | 'orchestrator' } = {}): { bundle: AttestationBundle; pubKey: Uint8Array; privKey: Uint8Array } {
  const { privKey, pubKey } = generateKeypair();
  const pubKeyHex = bytesToHex(pubKey);

  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId: opts.jobId ?? 'test-job-0001',
    role: opts.role ?? 'buyer',
    party: {
      v: 'dacs-1:0.1',
      primary: { scheme: 'cci', identifier: pubKeyHex },
      claims: [],
      issuedAt: '2026-05-28T00:00:00Z',
      presentation: { kind: 'siwd' },
    },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed',
    phases: [],
    finalisedAt: '2026-05-28T01:00:00Z',
  };

  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, privKey, bundleHash);

  // base64-encode the signature for the on-wire format
  const sigB64 = Buffer.from(sig).toString('base64');

  return {
    bundle: { ...unsigned, signature: sigB64 },
    pubKey,
    privKey,
  };
}

test('valid bundle (no attestations) → pass', async () => {
  const { bundle } = makeSignedBundle();
  const verdict = await verifyBundle(bundle, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'pass', `expected pass, got ${verdict.decision} with steps: ${JSON.stringify(verdict.steps, null, 2)}`);
  assert.equal(verdict.signersVerified.length, 1);
});

test('tampered signature → fail (never pass — §7.5.1)', async () => {
  const { bundle } = makeSignedBundle();
  const sigBytes = Buffer.from(bundle.signature!, 'base64');
  sigBytes[0] = sigBytes[0]! ^ 0xff;
  const tamperedBundle: AttestationBundle = { ...bundle, signature: sigBytes.toString('base64') };
  const verdict = await verifyBundle(tamperedBundle, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'fail', '§7.5.1 invariant: bad signature MUST fail, never coerced to pass');
});

test('mutated payload → fail (signature won\'t match recomputed bundleHash)', async () => {
  const { bundle } = makeSignedBundle();
  const tamperedBundle: AttestationBundle = { ...bundle, jobId: 'tampered-job-id' };
  const verdict = await verifyBundle(tamperedBundle, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'fail');
});

test('missing signature → fail', async () => {
  const { bundle } = makeSignedBundle();
  const noSig: AttestationBundle = { ...bundle, signature: undefined };
  const verdict = await verifyBundle(noSig, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'fail');
});

test('non-cci primary scheme → indeterminate (never pass — v0.2 scope limit)', async () => {
  const { bundle } = makeSignedBundle();
  const erc8004Bundle: AttestationBundle = {
    ...bundle,
    party: { ...bundle.party, primary: { scheme: 'erc8004', identifier: '0xabc...' } },
  };
  const verdict = await verifyBundle(erc8004Bundle, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'indeterminate', '§7.5.1: unsupported scheme must be indeterminate, NOT pass');
});

test('non-cci scheme: resolvePrimaryClaimPubkey returns null', () => {
  const bundle: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'x', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'lei', identifier: '984500ABCDEF1234567890' }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff' } },
    state: 'completed', phases: [], finalisedAt: '',
  };
  assert.equal(resolvePrimaryClaimPubkey(bundle), null);
});

test('cci with malformed identifier returns null (not crash)', () => {
  const bundle: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'x', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: 'too-short' }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff' } },
    state: 'completed', phases: [], finalisedAt: '',
  };
  assert.equal(resolvePrimaryClaimPubkey(bundle), null);
});

test('computeAnchorPair determinism: same jobId → same pair', () => {
  const pair1 = computeAnchorPair('deal-2026-05-28-001');
  const pair2 = computeAnchorPair('deal-2026-05-28-001');
  assert.deepEqual(pair1, pair2);
  assert.match(pair1.buyer, /^stor-[0-9a-f]{64}$/);
  assert.match(pair1.seller, /^stor-[0-9a-f]{64}$/);
  assert.notEqual(pair1.buyer, pair1.seller, 'buyer + seller anchors MUST differ');
});

test('computeAnchorPair: different jobIds yield different pairs', () => {
  const pair1 = computeAnchorPair('job-A');
  const pair2 = computeAnchorPair('job-B');
  assert.notEqual(pair1.buyer, pair2.buyer);
  assert.notEqual(pair1.seller, pair2.seller);
});

test('dahr-stub: attestation → indeterminate even with matching content-hash prefix (§7.5.2 stub semantics)', async () => {
  const { privKey, pubKey } = generateKeypair();
  const fakeHash = 'a'.repeat(64);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId: 'stub-attestation-test',
    role: 'buyer',
    party: {
      v: 'dacs-1:0.1',
      primary: { scheme: 'cci', identifier: bytesToHex(pubKey) },
      claims: [],
      issuedAt: '2026-05-28T00:00:00Z',
      presentation: { kind: 'siwd' },
    },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed',
    phases: [{
      phaseId: 'vet-credentials',
      startedAt: '2026-05-28T00:00:00Z',
      endedAt: '2026-05-28T00:00:01Z',
      outcome: 'pass',
      attestations: [{
        anchor: { substrate: 'demos', locator: `stor-stub-${fakeHash.slice(0, 32)}` },
        contentHash: fakeHash,
        type: 'dahr-stub:gleif-cbp:1',
        producedAt: '2026-05-28T00:00:00.500Z',
      }],
    }],
    finalisedAt: '2026-05-28T01:00:00Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, privKey, bundleHash);
  const signed: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };

  const verdict = await verifyBundle(signed, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'indeterminate',
    `stub attestation MUST keep verdict as indeterminate; got ${verdict.decision} steps=${JSON.stringify(verdict.steps, null, 2)}`);
});

test('stub locator with mismatched prefix → fail (catches forged stub)', async () => {
  const { privKey, pubKey } = generateKeypair();
  const bundle: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'forged-stub-test', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: bytesToHex(pubKey) }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed',
    phases: [{
      phaseId: 'vet', startedAt: '', endedAt: '', outcome: 'pass',
      attestations: [{
        anchor: { substrate: 'demos', locator: 'stor-stub-00000000000000000000000000000000' }, // does NOT match the contentHash below
        contentHash: 'ff'.repeat(32), // hash prefix would be ff...; locator is 00...; mismatch
        type: 'dahr-stub:gleif-cbp:1',
        producedAt: '',
      }],
    }],
    finalisedAt: '',
  };
  const canonical = jcsCanonical(bundle);
  const bundleHash = jcsHash(bundle);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, privKey, bundleHash);
  const signed: AttestationBundle = { ...bundle, signature: Buffer.from(sig).toString('base64') };
  const verdict = await verifyBundle(signed, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'fail', 'mismatched stub locator MUST fail — catches forged stubs');
});

test('hexToBytes + bytesToHex round-trip', () => {
  const input = 'deadbeefcafe1234';
  const bytes = hexToBytes(input);
  assert.equal(bytesToHex(bytes), input);

  // Also handle 0x prefix
  const prefixed = '0x' + input;
  const bytes2 = hexToBytes(prefixed);
  assert.equal(bytesToHex(bytes2), input);
});
