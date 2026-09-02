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
  LEGACY_READ_SEPARATORS,
  assertKnownSeparator,
  assertEmittableSeparator,
  isLegacyReadSeparator,
  buildSignedBytes,
} from '../../src/domain-sep.js';
import { sign, verify, generateKeypair } from '../../src/lib/sign.js';
import { ed25519 } from '@noble/curves/ed25519';

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

test('§B.7 — registry separator count (13 registry + 13 dacs-x extension)', () => {
  // v0.1 §B.7 alignment 2026-06-07 (dacs-repin cutover): the 6 drifted strings were renamed
  // to their canonical §B.7 form, the legacy `dacs5-bundle:v1:` was folded into `dacs-bundle:v1:`,
  // and the 7 residual non-registry kinds moved to the SIG-4 `dacs-x-` extension map.
  // See memory/reports/dacs-repin-v01-cutover-spec-2026-06-07.md §2.
  // 2026-06-07 dacs-disclose P1: +2 dacs-x kinds (CLAIM_COMMIT, CLAIM_REVEAL) for the
  // selective-disclosure follow-on (DACS-1 §11.2.7) → 7 → 9. See src/lib/disclose.ts +
  // dacs-consent-selective-disclosure-spec-2026-06-07.md §3.
  // 2026-06-07 dacs-disclose P2: +1 dacs-x kind (CONSENT) for consent/revocation records
  // (spec §3 "consent + revocation", §5 P2) → 9 → 10. See src/lib/consent.ts.
  // 2026-06-08 dacs-disclose P3: +1 dacs-x kind (DISPUTE_BUNDLE) for the dispute-evidence bundle
  // (spec §3 dispute evidence, §5 P3; presenter===grantor binding) → 10 → 11. See src/lib/dispute.ts.
  // 2026-07-23 pay-ap2 test agent: +1 dacs-x kind (AP2_MOCK_RECEIPT) for the MOCK AP2 facilitator
  // receipt signature (DACS-Standard #221/#222 §9.5.6) → 11 → 12. See src/live/ap2-provider-receipt.ts.
  // 2026-07-24 #248 registry alignment: +3 §B.7 registry kinds (BUNDLE_BINDING, FAULT_BUNDLE,
  // FAULT_BUNDLE_POINTER) — added to the CORE §B.7 table by #248 and previously only defined locally
  // in src/lib/bundle-binding-v1.ts; now centralized into DOMAIN_SEPARATORS → 10 → 13.
  // 2026-09-01 CCI agent identity adapter: +1 dacs-x kind (AGENT_IDENTITY) binding agent payloads
  // signed through the CCI adapter (src/adapters/demos/identity.ts) → 12 → 13.
  // 2026-09-02 maintenance rule: the next dacs-x extension addition bumps this count to 14.
  assert.equal(Object.keys(DOMAIN_SEPARATORS).length, 13,
    `expected 13 §B.7-registry separators, got ${Object.keys(DOMAIN_SEPARATORS).length}`);
  assert.equal(Object.keys(DACS_X_EXTENSION_SEPARATORS).length, 13,
    `expected 13 dacs-x extension separators, got ${Object.keys(DACS_X_EXTENSION_SEPARATORS).length}`);
  assert.equal(Object.keys(PATHOS_EXTENSION_SEPARATORS).length, 4,
    `expected 4 PATH-OS extension separators, got ${Object.keys(PATHOS_EXTENSION_SEPARATORS).length}`);
  // Pin the exact canonical strings — a count check alone can't catch a remove-one/add-one substitution.
  assert.equal(DOMAIN_SEPARATORS.BUNDLE_BINDING, 'dacs-bundle-binding:v1:');
  assert.equal(DOMAIN_SEPARATORS.FAULT_BUNDLE, 'dacs-fault-bundle:v1:');
  assert.equal(DOMAIN_SEPARATORS.FAULT_BUNDLE_POINTER, 'dacs-fault-bundle-pointer:v1:');
  assert.equal(DACS_X_EXTENSION_SEPARATORS.AGENT_IDENTITY, 'dacs-x-agent-identity:v1:');
});

test('dacs-disclose — CLAIM_COMMIT/CLAIM_REVEAL are known AND emittable (SIG-4 dacs-x)', () => {
  for (const sep of [
    DACS_X_EXTENSION_SEPARATORS.CLAIM_COMMIT,
    DACS_X_EXTENSION_SEPARATORS.CLAIM_REVEAL,
  ]) {
    assert.doesNotThrow(() => assertKnownSeparator(sep), `${sep} must be a known separator`);
    assert.doesNotThrow(() => assertEmittableSeparator(sep), `${sep} must be emittable`);
    assert.match(sep, /^dacs-x-.*:v1:$/, `${sep} must follow the SIG-4 dacs-x-<kind>:v1: form`);
  }
});

// ── FIX 4 — LEGACY_READ_SEPARATORS are truly read-only (verify/read OK, sign/emit rejected) ───
test('FIX 4 — sign() REFUSES to emit under a read-only legacy separator (dacs5-bundle:v1:)', () => {
  const kp = generateKeypair();
  const body = new TextEncoder().encode('legacy-emission-attempt');
  // assertKnownSeparator still admits it (the read path needs it)...
  assert.doesNotThrow(() => assertKnownSeparator(LEGACY_READ_SEPARATORS.BUNDLE_DACS5));
  assert.doesNotThrow(() => assertKnownSeparator('dacs5-bundle:v1:'));
  // ...but the EMISSION path (sign) must reject it.
  assert.throws(() => sign(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, body, kp.privKey),
    /read-only legacy separator/,
    'sign() must reject the legacy read-only separator (no emission under a retired separator)');
  assert.throws(() => assertEmittableSeparator(LEGACY_READ_SEPARATORS.BUNDLE_DACS5),
    /read-only legacy separator/);
});

test('FIX 4 — legacy READ/verify under dacs5-bundle:v1: still works (round-trip via raw signer)', () => {
  const kp = generateKeypair();
  const body = new TextEncoder().encode('a genuine pre-cutover artifact body');
  // Simulate a pre-cutover artifact: produce the legacy signed-bytes the way old code did, signing
  // with the raw primitive (sign() now refuses the legacy separator). verify() — on the READ path —
  // must STILL accept it under the legacy separator.
  const signedBytes = buildSignedBytes(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, body);
  const sig = ed25519.sign(signedBytes, kp.privKey);
  assert.equal(verify(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, sig, body, kp.pubKey), true,
    'legacy READ/verify under the legacy separator must still succeed (§10.4.2 backwards-compat)');
});

test('FIX 4 — isLegacyReadSeparator flags the legacy set only', () => {
  assert.equal(isLegacyReadSeparator(LEGACY_READ_SEPARATORS.BUNDLE_DACS5), true);
  assert.equal(isLegacyReadSeparator(DOMAIN_SEPARATORS.BUNDLE), false);
  assert.equal(isLegacyReadSeparator('dacs-x-attestation-ref:v1:'), false);
});
