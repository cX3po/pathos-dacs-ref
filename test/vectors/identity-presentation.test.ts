/**
 * DACS-1 IdentityBundle presentation — v0.1 §6.3.2 single-hash signed_bytes round-trip.
 *
 * Spec source: DACS-1 v0.1 §6.3.2 (DACS-1-IDENTIFY.md:147-159).
 *   bundle_hash  := sha256(JCS(bundle with `presentation` omitted)), hex
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash      (SINGLE-HASH)
 *
 * Locks in:
 *   - bundle_hash omits ONLY the presentation field
 *   - signed_bytes is the single-hash form (hash only — NOT the v0.7 composite sep||hash||JCS(payload))
 *   - per-claim + session-key presentations round-trip (sign -> verify pass)
 *   - tamper detection, presentedBy-resolution, session-key rootBinding composite
 *   - siwd resource URI shape (dacs:<hex(signed_bytes)>)
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import type { IdentityBundle, ClaimReference } from '../../src/types/identity.js';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import { jcsHash } from '../../src/jcs.js';
import {
  bundleHashHex,
  presentationSignedBytes,
  siwdResourceUri,
  signPerClaimPresentation,
  signSessionKeyPresentation,
  verifyBundlePresentation,
} from '../../src/lib/identity-presentation.js';

const SEP = 'dacs-bundle-presentation:v1:';

function unsignedBundle(primaryHex: string, otherHex?: string): Omit<IdentityBundle, 'presentation'> {
  const claims = [{ ref: { scheme: 'cci' as const, identifier: primaryHex } }];
  if (otherHex) claims.push({ ref: { scheme: 'cci' as const, identifier: otherHex } });
  return {
    bundleVersion: '1',
    presentedBy: { scheme: 'cci', identifier: primaryHex },
    presentedAt: 1717800000000,
    claims,
  };
}

test('§6.3.2 — signed_bytes is SINGLE-HASH (sep || bundle_hash hex), not composite', () => {
  const { pubKey } = generateKeypair();
  const u = unsignedBundle(bytesToHex(pubKey));
  const full: IdentityBundle = { ...u, presentation: { kind: 'per-claim', signatures: [] } };

  // bundle_hash = sha256(JCS(bundle with presentation omitted)), hex
  const expectedHashHex = bytesToHex(jcsHash(u));
  assert.equal(bundleHashHex(full), expectedHashHex);

  // signed_bytes = utf8(SEP) || utf8(hashHex) — single-hash, hash only.
  const expected = new TextEncoder().encode(SEP + expectedHashHex);
  assert.deepEqual(presentationSignedBytes(full), expected);

  // Explicitly assert it is NOT the v0.7 composite form (sep || hash || JCS(payload)).
  const composite = new TextEncoder().encode(SEP + expectedHashHex + new TextDecoder().decode(jcsHash(u)));
  assert.notDeepEqual(presentationSignedBytes(full), composite);
});

test('§6.3.2 — bundle_hash omits ONLY the presentation field', () => {
  const { pubKey } = generateKeypair();
  const u = unsignedBundle(bytesToHex(pubKey));
  const a: IdentityBundle = { ...u, presentation: { kind: 'per-claim', signatures: [{ ref: u.presentedBy, signature: 'AAAA' }] } };
  const b: IdentityBundle = { ...u, presentation: { kind: 'session-key', key: 'ff'.repeat(32), signature: 'BBBB' } };
  // Different presentation, SAME bundle_hash (presentation is omitted).
  assert.equal(bundleHashHex(a), bundleHashHex(b));
  // Changing a NON-presentation field changes the hash.
  const c: IdentityBundle = { ...u, presentedAt: 1, presentation: a.presentation };
  assert.notEqual(bundleHashHex(a), bundleHashHex(c));
});

test('§6.3.2 — per-claim presentation round-trips (sign -> verify pass)', () => {
  const primary = generateKeypair();
  const u = unsignedBundle(bytesToHex(primary.pubKey));
  const presentation = signPerClaimPresentation(u, [{ ref: u.presentedBy, privKey: primary.privKey }]);
  const bundle: IdentityBundle = { ...u, presentation };
  const r = verifyBundlePresentation(bundle);
  assert.equal(r.decision, 'pass', JSON.stringify(r));
});

test('§6.3.2 — per-claim tampered bundle fails verification', () => {
  const primary = generateKeypair();
  const u = unsignedBundle(bytesToHex(primary.pubKey));
  const presentation = signPerClaimPresentation(u, [{ ref: u.presentedBy, privKey: primary.privKey }]);
  // Tamper a non-presentation field after signing -> bundle_hash changes -> signature no longer verifies.
  const bundle: IdentityBundle = { ...u, presentedAt: u.presentedAt + 1, presentation };
  const r = verifyBundlePresentation(bundle);
  assert.equal(r.decision, 'fail', JSON.stringify(r));
});

test('§6.3.2 — presentedBy not in claims is rejected', () => {
  const primary = generateKeypair();
  const stranger = generateKeypair();
  const u = unsignedBundle(bytesToHex(primary.pubKey));
  const bad: IdentityBundle = {
    ...u,
    presentedBy: { scheme: 'cci', identifier: bytesToHex(stranger.pubKey) }, // not a member of claims
    presentation: signPerClaimPresentation(u, [{ ref: u.presentedBy, privKey: primary.privKey }]),
  };
  const r = verifyBundlePresentation(bad);
  assert.equal(r.decision, 'fail');
  assert.match(r.reason ?? '', /presentedBy/);
});

test('§6.3.2 — session-key presentation round-trips, incl. rootBinding composite', () => {
  const root = generateKeypair();
  const session = generateKeypair();
  const u = unsignedBundle(bytesToHex(root.pubKey));
  const presentation = signSessionKeyPresentation(u, session.privKey, bytesToHex(session.pubKey), root.privKey);
  const bundle: IdentityBundle = { ...u, presentation };
  // rootBinding present -> must supply rootKeyHex to fully verify.
  const r = verifyBundlePresentation(bundle, { rootKeyHex: bytesToHex(root.pubKey) });
  assert.equal(r.decision, 'pass', JSON.stringify(r));
  // rootBinding present but no root key supplied -> unverifiable (not fail).
  const r2 = verifyBundlePresentation(bundle);
  assert.equal(r2.decision, 'unverifiable');
});

test('§6.3.2 — siwd/sr1-root are unverifiable here but signed_bytes binding is exposed', () => {
  const { pubKey } = generateKeypair();
  const u = unsignedBundle(bytesToHex(pubKey));
  const siwd: IdentityBundle = { ...u, presentation: { kind: 'siwd', message: 'msg', signature: 'sig', address: '0xabc' } };
  const r = verifyBundlePresentation(siwd);
  assert.equal(r.decision, 'unverifiable');
  // §6.3.2 :154 — dacs:<hex(signed_bytes)>
  const uri = siwdResourceUri(siwd);
  assert.match(uri, /^dacs:[0-9a-f]+$/);
  assert.equal(uri, 'dacs:' + bytesToHex(presentationSignedBytes(siwd)));
});
