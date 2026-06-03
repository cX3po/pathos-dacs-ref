/**
 * Domain-separator closure tests (§7.7 closure rule)
 *
 * DACS v1 defines a closed registry of 17 separators. Implementations MUST
 * reject any caller passing a separator outside that registry. This test
 * locks in that invariant.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { DOMAIN_SEPARATORS, assertKnownSeparator } from '../../src/domain-sep.js';
import { sign, verify, generateKeypair } from '../../src/lib/sign.js';

test('§7.7 — every registered separator passes assertKnownSeparator', () => {
  for (const sep of Object.values(DOMAIN_SEPARATORS)) {
    assert.doesNotThrow(() => assertKnownSeparator(sep), `separator ${sep} should be known`);
  }
});

test('§7.7 — unknown separator throws on assertKnownSeparator', () => {
  assert.throws(
    () => assertKnownSeparator('dacs-something-made-up:v1:'),
    /Unknown domain separator/
  );
});

test('§7.7 — sign() rejects unknown separator at runtime', () => {
  const { privKey } = generateKeypair();
  const body = new TextEncoder().encode('test payload');
  assert.throws(
    () => sign('dacs-fake:v1:' as never, body, privKey),
    /Unknown domain separator/
  );
});

test('§7.7 — verify() returns false for unknown separator (does NOT throw)', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('test payload');
  // sign with a real separator
  const sig = sign(DOMAIN_SEPARATORS.LISTING, body, privKey);
  // verify with a fake separator — must return false, not throw, so the verifier
  // walk can continue and report "signature invalid" rather than crashing
  const result = verify('dacs-fake:v1:' as never, sig, body, pubKey);
  assert.equal(result, false);
});

test('§7.7 — registry separator count (mid-migration: legacy 17 + dacs-bundle:v1:)', () => {
  // Migration 2026-06-03: added the §10.4.1 spec separator `dacs-bundle:v1:` alongside the
  // legacy set. Current spec §7.7 lists 19 (closed); the full registry-name reconciliation
  // (renaming legacy names to the spec's + dropping the legacy bundle sep) is a later step —
  // see memory/reports/dacs-baseline-review-2026-06-03.md §C.
  const count = Object.keys(DOMAIN_SEPARATORS).length;
  assert.equal(count, 18, `expected 18 separators (17 legacy + dacs-bundle:v1:), got ${count}`);
});
