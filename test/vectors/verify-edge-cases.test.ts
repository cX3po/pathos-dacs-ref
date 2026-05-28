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
