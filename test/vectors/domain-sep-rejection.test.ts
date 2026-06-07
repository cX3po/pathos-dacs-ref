/**
 * Domain-separator closure tests (§B.7 / SIG-1..4 closure rule)
 *
 * DACS v0.1 defines a closed §B.7 registry; experimental kinds use the `dacs-x-<kind>:v1:`
 * extension form (SIG-4). Implementations MUST reject any caller passing a separator that is
 * neither in the registry nor in the admitted extension maps. This test locks in that invariant.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  DOMAIN_SEPARATORS,
  DACS_X_EXTENSION_SEPARATORS,
  PATHOS_EXTENSION_SEPARATORS,
  assertKnownSeparator,
} from '../../src/domain-sep.js';
import { sign, verify, generateKeypair } from '../../src/lib/sign.js';

test('§B.7 — every registered separator passes assertKnownSeparator', () => {
  for (const sep of [
    ...Object.values(DOMAIN_SEPARATORS),
    ...Object.values(DACS_X_EXTENSION_SEPARATORS),
    ...Object.values(PATHOS_EXTENSION_SEPARATORS),
  ]) {
    assert.doesNotThrow(() => assertKnownSeparator(sep), `separator ${sep} should be known`);
  }
});

test('§B.7 — every §B.7 registry separator is a canonical v0.1 string (no legacy drift)', () => {
  // v0.1 §B.7 alignment 2026-06-07: these are the canonical strings from CORE.md:237-259.
  // None of the pre-v0.1 drifted strings (dacs-composite-verify, dacs-commit-agreement,
  // dacs-settlement-evidence, dacs-reputation, dacs5-bundle, dacs-session-key-auth) survive.
  const drifted = [
    'dacs-composite-verify:v1:', 'dacs-commit-agreement:v1:', 'dacs-settlement-evidence:v1:',
    'dacs-reputation:v1:', 'dacs5-bundle:v1:', 'dacs-session-key-auth:v1:',
  ];
  const live = Object.values(DOMAIN_SEPARATORS) as string[];
  for (const d of drifted) assert.ok(!live.includes(d), `drifted separator "${d}" must not appear in the v0.1 registry`);
  // Canonical replacements ARE present.
  for (const c of ['dacs-composite:v1:', 'dacs-commitment:v1:', 'dacs-evidence:v1:', 'dacs-rating:v1:', 'dacs-bundle:v1:', 'dacs-session-binding:v1:']) {
    assert.ok(live.includes(c), `canonical v0.1 separator "${c}" must be present`);
  }
});

test('§B.7 — residual non-registry kinds use the SIG-4 dacs-x- extension prefix', () => {
  for (const sep of Object.values(DACS_X_EXTENSION_SEPARATORS) as string[]) {
    assert.ok(sep.startsWith('dacs-x-'), `extension separator "${sep}" must use the dacs-x- prefix (SIG-4)`);
  }
});

test('§B.7 — unknown separator throws on assertKnownSeparator', () => {
  assert.throws(
    () => assertKnownSeparator('dacs-something-made-up:v1:'),
    /Unknown domain separator/
  );
});

test('§B.7 — sign() rejects unknown separator at runtime', () => {
  const { privKey } = generateKeypair();
  const body = new TextEncoder().encode('test payload');
  assert.throws(
    () => sign('dacs-fake:v1:' as never, body, privKey),
    /Unknown domain separator/
  );
});

test('§B.7 — verify() returns false for unknown separator (does NOT throw)', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('test payload');
  // sign with a real separator
  const sig = sign(DOMAIN_SEPARATORS.LISTING, body, privKey);
  // verify with a fake separator — must return false, not throw, so the verifier
  // walk can continue and report "signature invalid" rather than crashing
  const result = verify('dacs-fake:v1:' as never, sig, body, pubKey);
  assert.equal(result, false);
});

test('§B.7 — registry separator count (v0.1 cutover: 10 registry + 7 dacs-x extension)', () => {
  // v0.1 §B.7 alignment 2026-06-07 (dacs-repin cutover): the 6 drifted strings were renamed
  // to their canonical §B.7 form, the legacy `dacs5-bundle:v1:` was folded into `dacs-bundle:v1:`,
  // and the 7 residual non-registry kinds moved to the SIG-4 `dacs-x-` extension map.
  // See memory/reports/dacs-repin-v01-cutover-spec-2026-06-07.md §2.
  assert.equal(Object.keys(DOMAIN_SEPARATORS).length, 10,
    `expected 10 §B.7-registry separators, got ${Object.keys(DOMAIN_SEPARATORS).length}`);
  assert.equal(Object.keys(DACS_X_EXTENSION_SEPARATORS).length, 7,
    `expected 7 dacs-x extension separators, got ${Object.keys(DACS_X_EXTENSION_SEPARATORS).length}`);
  assert.equal(Object.keys(PATHOS_EXTENSION_SEPARATORS).length, 4,
    `expected 4 PATH-OS extension separators, got ${Object.keys(PATHOS_EXTENSION_SEPARATORS).length}`);
});
