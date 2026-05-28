/**
 * DACS-5 verifier — edge case regression tests for Codex M2 review findings
 *
 * Locks in:
 *   #1 hexToBytes rejects non-hex characters (no NaN-becomes-zero silent acceptance)
 *   #3 Signatures with wrong byte length fail loudly (not silently)
 *   #4 Object-anchored attestations resolve to indeterminate (not fail) in v0.2
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { hexToBytes, resolvePrimaryClaimPubkey } from '../../src/lib/verify-bundle.js';
import type { AttestationBundle } from '../../src/types/index.js';

test('Codex M2 #1: hexToBytes rejects non-hex characters', () => {
  assert.throws(() => hexToBytes('zz'.repeat(32)), /invalid hex/,
    'must reject "zz" repeated to 64 chars — would silently produce all-zero pubkey otherwise');
});

test('Codex M2 #1: resolvePrimaryClaimPubkey rejects "zz"-string CCI identifier (no zero-key acceptance)', () => {
  const bundle: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'edge-1', role: 'buyer',
    party: {
      v: 'dacs-1:0.1',
      primary: { scheme: 'cci', identifier: 'zz'.repeat(32) }, // 64 chars, non-hex
      claims: [], issuedAt: '', presentation: { kind: 'siwd' },
    },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff' } },
    state: 'completed', phases: [], finalisedAt: '',
  };
  assert.equal(resolvePrimaryClaimPubkey(bundle), null,
    'non-hex identifier must NOT be coerced to zero-byte pubkey');
});

test('Codex M2 #1: hexToBytes accepts mixed case and 0x prefix', () => {
  const a = hexToBytes('aBcDef01');
  const b = hexToBytes('0xABCDEF01');
  assert.equal(Array.from(a, x => x).toString(), Array.from(b, x => x).toString());
});

test('Codex M2 #1: hexToBytes rejects odd-length input', () => {
  assert.throws(() => hexToBytes('abc'), /invalid hex length/);
});

test('Codex M2 #3 / Gemini LOW: signature with valid base64 but WRONG byte length → fail with "malformed signature length"', async () => {
  // Build a valid bundle, then replace the signature with a base64-clean but
  // wrong-length value. The verifier MUST fail with the precise diagnostic
  // (not silently call edVerify with a corrupted-length sig).
  const { generateKeypair, sign } = await import('../../src/lib/sign.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { jcsCanonical, jcsHash } = await import('../../src/jcs.js');
  const { verifyBundle, bytesToHex } = await import('../../src/lib/verify-bundle.js');

  const { privKey, pubKey } = generateKeypair();
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'sig-len-test', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: bytesToHex(pubKey) }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed', phases: [], finalisedAt: '',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  // Build a real signature, then truncate to a wrong-but-base64-clean length
  const realSig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, privKey, bundleHash);
  const truncated = realSig.slice(0, 32); // 32 bytes instead of 64
  const bundle: AttestationBundle = { ...unsigned, signature: Buffer.from(truncated).toString('base64') };

  const verdict = await verifyBundle(bundle, { skipTwoSidedLookup: true });
  assert.equal(verdict.decision, 'fail');
  const sigStep = verdict.steps.find(s => s.step === 'verify-signature');
  assert.match(sigStep?.detail ?? '', /malformed signature length/);
});

test('Codex M2 #4 / Gemini LOW: AttestationRef with non-string anchored data → indeterminate (v0.2 scope)', async () => {
  const { generateKeypair, sign } = await import('../../src/lib/sign.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { jcsCanonical, jcsHash } = await import('../../src/jcs.js');
  const { verifyBundle, bytesToHex } = await import('../../src/lib/verify-bundle.js');
  const { fetchAnchored } = await import('../../src/demos/storage.js');
  void fetchAnchored;

  const { privKey, pubKey } = generateKeypair();
  // Build a bundle with an attestation pointing at a "real" anchor (not stub)
  const realAnchor = 'stor-' + 'a'.repeat(64);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId: 'nonstring-data-test', role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: bytesToHex(pubKey) }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'ff'.repeat(32) } },
    state: 'completed',
    phases: [{
      phaseId: 'vet', startedAt: '', endedAt: '', outcome: 'pass',
      attestations: [{
        anchor: { substrate: 'demos', locator: realAnchor },
        contentHash: 'a'.repeat(64),
        type: 'gleif-cbp:1', // not stub — would require real chain fetch
        producedAt: '',
      }],
    }],
    finalisedAt: '',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, privKey, bundleHash);
  const bundle: AttestationBundle = { ...unsigned, signature: Buffer.from(sig).toString('base64') };

  // Mock fetchAnchored to return non-string data
  const mockFetch = async () => ({
    storageAddress: realAnchor,
    owner: '0xowner',
    data: { someField: 'someValue', nested: { x: 1 } } as Record<string, unknown>, // OBJECT not string
    sizeBytes: 50,
    createdAt: '',
  });

  const verdict = await verifyBundle(bundle, {
    skipTwoSidedLookup: true,
    fetchAnchoredImpl: mockFetch as unknown as typeof fetchAnchored,
  });
  // Should be indeterminate (not fail, not pass) — object-anchored data is out of scope v0.2
  assert.equal(verdict.decision, 'indeterminate', `expected indeterminate, got ${verdict.decision}; steps=${JSON.stringify(verdict.steps)}`);
  const attStep = verdict.steps.find(s => s.step.startsWith('attestation['));
  assert.match(attStep?.detail ?? '', /not a string|v0\.2 verifier only handles string-anchored/);
});
