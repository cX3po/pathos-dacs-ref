/**
 * §10.4 AttestationBundleV1 acceptance verifier — cross-impl + crypto tests.
 *
 * Runs verifyBundleV1 against the reference-impl contributor's vendored #117 fixtures (cross-impl convergence:
 * we reproduce his bundleHash + accept the §10.4 shape), and against a locally-signed
 * real-key bundle (to positively exercise the signature crypto path his placeholder-DID
 * fixtures can't).
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { verifyBundleV1 } from '../../src/lib/verify-bundle-v1.js';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { bundleSignedScopeHashV1 } from '../../src/lib/bundle-signed-scope-v1.js';
import { ed25519 } from '@noble/curves/ed25519';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (n: string) => path.join(HERE, 'dacs-x-fixtures', n);
const load = (n: string) => JSON.parse(readFileSync(FX(n), 'utf8')) as AttestationBundleV1;
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

test('§10.4 — the reference-impl contributor DACS-VERIFY-0004 accepts + reproduces his bundleHash (cross-impl)', () => {
  const v = verifyBundleV1(load('attestation-bundle-0004.json'), { requireSignatures: false });
  assert.equal(v.bundleHash, '9e5ea58d198b459a2929d38019807c465ce9988dcb89c847cce8e80210df39ba', 'cross-impl bundleHash match (v0.1 R5-1 exclude — upstream golden.json)');
  assert.equal(v.signerRuleSatisfied, true, 'completed bundle has buyer+seller signatures');
  assert.equal(v.decision, 'accept');
  // placeholder DID signers → unverifiable (not a hard fail)
  assert.ok(v.signatureChecks.every((c) => c.decision === 'unverifiable'), 'DID signers are unverifiable, not failed');
});

test('§10.4 — divergent seller-side (failed-counterparty) is a well-formed, accepted single-side bundle', () => {
  const v = verifyBundleV1(load('attestation-bundle-0004-seller.json'), { requireSignatures: false });
  assert.equal(v.decision, 'accept');
  assert.equal(v.signerRuleSatisfied, true);
  assert.notEqual(v.bundleHash, '', 'has a computable bundleHash');
});

test('§10.4 — HTLC-9 (failed-counterparty) bundle is accepted', () => {
  const v = verifyBundleV1(load('attestation-bundle-htlc9.json'), { requireSignatures: false });
  assert.equal(v.decision, 'accept');
  assert.equal(v.signerRuleSatisfied, true);
});

test('§10.4 — divergent pair: same jobId, canonically distinct bundles (§10.4.3(d))', () => {
  const a = verifyBundleV1(load('attestation-bundle-0004.json'), { requireSignatures: false });
  const b = verifyBundleV1(load('attestation-bundle-0004-seller.json'), { requireSignatures: false });
  const ja = load('attestation-bundle-0004.json').jobId;
  const jb = load('attestation-bundle-0004-seller.json').jobId;
  assert.equal(ja, jb, 'same jobId');
  assert.notEqual(a.bundleHash, b.bundleHash, 'divergent bundles hash differently → the two-sided divergence trigger');
});

test('§10.4 — real-key bundle: signatures verify (accept), tamper rejects', () => {
  const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; };
  const buyer = mk(0x41), seller = mk(0x42);
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId: 'local-realkey-0001', outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst-1', version: 1, contentHash: 'ab'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  const enc = new TextEncoder();
  const sigOf = (k: { priv: Uint8Array; pubHex: string }) => ({
    party: { scheme: 'cci', identifier: k.pubHex } as const, algorithm: 'ed25519' as const,
    value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), k.priv)).toString('base64'),
  });
  const good: AttestationBundleV1 = { ...unsigned, signatures: [sigOf(buyer), sigOf(seller)] };
  const v = verifyBundleV1(good);
  assert.equal(v.decision, 'accept');
  assert.ok(v.signatureChecks.every((c) => c.decision === 'pass'), 'real-key signatures verify');

  const tampered: AttestationBundleV1 = { ...good, outcome: 'failed-perm' };
  const vt = verifyBundleV1(tampered);
  assert.equal(vt.decision, 'reject');
  assert.ok(vt.signatureChecks.some((c) => c.decision === 'fail'), 'tampering breaks signature verification');
});

test('§B.1 — spec string-form ClaimReference ("cci:<hex>") verifies (accept) and converges with object form (#145/#146)', () => {
  const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; };
  const buyer = mk(0x43), seller = mk(0x44);
  // string-form claims per spec §B.1 — what a spec-conformant verifier-emitted bundle carries
  const buyerClaim = `cci:${buyer.pubHex}`, sellerClaim = `cci:${seller.pubHex}`;
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId: 'string-claimref-0001', outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst-1', version: 1, contentHash: 'ab'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: buyerClaim },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: sellerClaim },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  const enc = new TextEncoder();
  const sigOf = (k: { priv: Uint8Array; pubHex: string }, claim: string) => ({
    party: claim, algorithm: 'ed25519' as const,
    value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), k.priv)).toString('base64'),
  });
  const v = verifyBundleV1({ ...unsigned, signatures: [sigOf(buyer, buyerClaim), sigOf(seller, sellerClaim)] });
  assert.equal(v.decision, 'accept', 'string-form cci claims verify-accept');
  assert.equal(v.cryptographicallyVerified, true, 'string-form party resolves to the ed25519 key + sig verifies');
  assert.ok(v.signatureChecks.every((c) => c.decision === 'pass'));
  // the string form and the object form of the SAME key are ONE logical signer (no party-set split)
  const objForm = verifyBundleV1({
    ...unsigned,
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    signatures: [sigOf(buyer, buyerClaim), sigOf(seller, sellerClaim)],
  });
  assert.equal(objForm.signerRuleSatisfied, true, 'object-form parties + string-form signers resolve to the same signer set');
});

// ── hardening / edge cases ──────────────────────────────────────────────────
function realKey(fill: number) { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; }
function baseUnsigned(over: Partial<AttestationBundleV1> = {}): Omit<AttestationBundleV1, 'signatures'> {
  const buyer = realKey(0x51), seller = realKey(0x52);
  return {
    bundleVersion: '1', jobId: 'edge-0001', outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst', version: 1, contentHash: 'ab'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
    ...over,
  };
}
function signBy(unsigned: Omit<AttestationBundleV1, 'signatures'>, keys: { priv: Uint8Array; pubHex: string }[], algo = 'ed25519'): AttestationBundleV1 {
  const bundleHash = bundleSignedScopeHashV1(unsigned); const e = new TextEncoder();
  return { ...unsigned, signatures: keys.map((k) => ({ party: { scheme: 'cci' as const, identifier: k.pubHex }, algorithm: algo as 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, e.encode(bundleHash), k.priv)).toString('base64') })) };
}

test('§10.4 — unknown outcome is rejected (not treated as abort)', () => {
  const u = baseUnsigned({ outcome: 'approved' as unknown as AttestationBundleV1['outcome'] });
  const v = verifyBundleV1(signBy(u, [realKey(0x51)]));
  assert.equal(v.structurallyValid, false);
  assert.equal(v.decision, 'reject');
});

test('§10.4 — non-abort bundle missing the seller party is rejected', () => {
  const u = baseUnsigned();
  u.parties = [u.parties[0]!]; // buyer only
  const v = verifyBundleV1(signBy(u, [realKey(0x51)]));
  assert.equal(v.decision, 'reject');
  assert.ok(v.reasons.some((r) => /buyer \+ seller|required signer/.test(r)));
});

test('§10.4 — a signature from an unlisted party is rejected', () => {
  const u = baseUnsigned();
  const v = verifyBundleV1(signBy(u, [realKey(0x51), realKey(0x52), realKey(0x99)])); // 0x99 not a party
  assert.equal(v.decision, 'reject');
  assert.ok(v.reasons.some((r) => /unlisted/.test(r)));
});

test('§10.4 — aborted-by-self MAY be single-signed (accept)', () => {
  const u = baseUnsigned({ outcome: 'aborted-by-self' });
  const v = verifyBundleV1(signBy(u, [realKey(0x51)])); // one signer, a listed party
  assert.equal(v.signerRuleSatisfied, true);
  assert.equal(v.decision, 'accept');
});

test('§10.4 — non-ed25519 algorithm is unverifiable, not silently accepted as ed25519', () => {
  const u = baseUnsigned();
  const b = signBy(u, [realKey(0x51), realKey(0x52)], 'ecdsa-secp256k1');
  const v = verifyBundleV1(b);
  assert.ok(v.signatureChecks.every((c) => c.decision === 'unverifiable' && /unsupported algorithm/.test(c.reason!)));
});

test('§10.4 — malformed / wrong-length signature value fails', () => {
  const u = baseUnsigned();
  const b = signBy(u, [realKey(0x51), realKey(0x52)]);
  b.signatures[0]!.value = 'not-base64!!'; // invalid charset
  b.signatures[1]!.value = Buffer.from(new Uint8Array(10)).toString('base64'); // valid b64, wrong length
  const v = verifyBundleV1(b);
  assert.equal(v.decision, 'reject');
  assert.ok(v.signatureChecks.every((c) => c.decision === 'fail'));
});

test('§10.4 — orchestrator sharing the buyer claim is not an extra required signer', () => {
  const u = baseUnsigned();
  const buyerClaim = u.parties[0]!.primaryClaim;
  u.parties.push({ role: 'orchestrator', bundleHash: 'cc'.repeat(32), primaryClaim: buyerClaim });
  const v = verifyBundleV1(signBy(u, [realKey(0x51), realKey(0x52)])); // buyer+seller only
  assert.equal(v.signerRuleSatisfied, true, 'shared-claim orchestrator needs no extra signature');
  assert.equal(v.decision, 'accept');
});

test('§10.4 — enforcing mode: placeholder-DID fixture is INDETERMINATE, not accepted (unverifiable signatures, §7.5.1)', () => {
  const v = verifyBundleV1(load('attestation-bundle-0004.json')); // default requireSignatures:true
  assert.equal(v.cryptographicallyVerified, false);
  // §7.5.1 do-not-collapse: an unresolvable/placeholder-DID key is UNDECIDABLE → `indeterminate`, NOT a hard
  // `reject` (which means the signature is invalid). It is still NOT accepted. (Fixed 2026-06-19 — was
  // wrongly collapsed to 'reject'; surfaced by the cross-impl convergence harness vs dacs-verify.)
  assert.equal(v.decision, 'indeterminate', 'enforcing mode → indeterminate for unverifiable signatures');
  assert.notEqual(v.decision, 'accept', 'must never be accepted');
  assert.equal(v.structurallyValid, true, 'still structurally valid + hash reproduced');
});

test('§10.4 — null / array / primitive roots are rejected without throwing', () => {
  for (const bad of [null, undefined, 42, 'x', [], true]) {
    const v = verifyBundleV1(bad as unknown as AttestationBundleV1);
    assert.equal(v.decision, 'reject');
    assert.equal(v.structurallyValid, false);
  }
});

test('§10.4 — malformed claim params (non-string value) is rejected structurally', () => {
  const buyer = realKey(0x61), seller = realKey(0x62);
  const u = baseUnsigned();
  u.parties[0]!.primaryClaim = { scheme: 'cci', identifier: buyer.pubHex, params: { a: 5 } } as unknown as typeof u.parties[0]['primaryClaim'];
  const m = verifyBundleV1(signBy(u, [buyer, seller]));
  assert.equal(m.decision, 'reject');
  assert.ok(m.reasons.some((r) => /primaryClaim invalid/.test(r)));
});

test('§10.4 — claim params order does not change identity (a party+signer with same params, different order, match)', () => {
  const buyer = realKey(0x65), seller = realKey(0x66);
  const u = baseUnsigned();
  // party carries params in one order; signer carries the SAME params in the other order
  u.parties[0]!.primaryClaim = { scheme: 'cci', identifier: buyer.pubHex, params: { a: '1', b: '2' } };
  u.parties[1]!.primaryClaim = { scheme: 'cci', identifier: seller.pubHex };
  const bundleHash = bundleSignedScopeHashV1(u);
  const e = new TextEncoder();
  const b: AttestationBundleV1 = { ...u, signatures: [
    { party: { scheme: 'cci', identifier: buyer.pubHex, params: { b: '2', a: '1' } }, algorithm: 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, e.encode(bundleHash), buyer.priv)).toString('base64') },
    { party: { scheme: 'cci', identifier: seller.pubHex }, algorithm: 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, e.encode(bundleHash), seller.priv)).toString('base64') },
  ] };
  const v = verifyBundleV1(b);
  assert.equal(v.signerRuleSatisfied, true, 'param order is canonicalised so the signer matches the party');
  assert.equal(v.decision, 'accept');
});

test('§10.4 — two DISTINCT orchestrators are both required signers', () => {
  const buyer = realKey(0x71), seller = realKey(0x72), o1 = realKey(0x73), o2 = realKey(0x74);
  const u = baseUnsigned();
  u.parties = [
    { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
    { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    { role: 'orchestrator', bundleHash: 'cc'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o1.pubHex } },
    { role: 'orchestrator', bundleHash: 'dd'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o2.pubHex } },
  ];
  // sign buyer+seller+o1 but NOT o2 → must be missing a required signer
  const v = verifyBundleV1(signBy(u, [buyer, seller, o1]));
  assert.equal(v.signerRuleSatisfied, false, 'the second distinct orchestrator must also sign');
  // sign all four → accept (enforcing, real keys)
  const v2 = verifyBundleV1(signBy(u, [buyer, seller, o1, o2]));
  assert.equal(v2.decision, 'accept');
  assert.equal(v2.cryptographicallyVerified, true);
});


test('§10.4 — scheme confusion: a 64-hex identifier under a non-cci scheme is NOT crypto-verified', () => {
  const k = realKey(0x81), seller = realKey(0x82);
  const u = baseUnsigned();
  // buyer party uses scheme evm-key with a 64-hex value (an ed25519 key smuggled under the wrong scheme)
  u.parties[0]!.primaryClaim = { scheme: 'evm-key', identifier: k.pubHex };
  u.parties[1]!.primaryClaim = { scheme: 'cci', identifier: seller.pubHex };
  const bundleHash = bundleSignedScopeHashV1(u); const e = new TextEncoder();
  const b: AttestationBundleV1 = { ...u, signatures: [
    { party: { scheme: 'evm-key', identifier: k.pubHex }, algorithm: 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, e.encode(bundleHash), k.priv)).toString('base64') },
    { party: { scheme: 'cci', identifier: seller.pubHex }, algorithm: 'ed25519', value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, e.encode(bundleHash), seller.priv)).toString('base64') },
  ] };
  const v = verifyBundleV1(b);
  const evm = v.signatureChecks.find((c) => c.party.includes('evm-key'));
  assert.equal(evm?.decision, 'unverifiable', 'non-cci scheme is not resolved to an ed25519 key (no scheme confusion)');
  assert.equal(v.cryptographicallyVerified, false);
});

test('§10.4 — cci identifier is case/0x-insensitive (party 0x-UPPER matches lowercase signer)', () => {
  const buyer = realKey(0x85), seller = realKey(0x86);
  const u = baseUnsigned();
  u.parties[0]!.primaryClaim = { scheme: 'cci', identifier: '0x' + buyer.pubHex.toUpperCase() };
  u.parties[1]!.primaryClaim = { scheme: 'cci', identifier: seller.pubHex };
  const v = verifyBundleV1(signBy(u, [buyer, seller])); // signers use lowercase no-0x
  assert.equal(v.signerRuleSatisfied, true);
  assert.equal(v.decision, 'accept');
  assert.equal(v.cryptographicallyVerified, true);
});

test('§10.4 — malformed nested entries are rejected (phaseSummary:[null], vetRecords:[42])', () => {
  const u1 = baseUnsigned(); (u1 as { phaseSummary: unknown }).phaseSummary = [null];
  assert.equal(verifyBundleV1(signBy(u1, [realKey(0x51), realKey(0x52)])).decision, 'reject');
  const u2 = baseUnsigned(); (u2 as { vetRecords: unknown }).vetRecords = [42];
  assert.equal(verifyBundleV1(signBy(u2, [realKey(0x51), realKey(0x52)])).decision, 'reject');
});

test('§10.4 — non-canonical base64 signature (non-zero unused bits) is rejected', () => {
  const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const u = baseUnsigned();
  const b = signBy(u, [realKey(0x51), realKey(0x52)]);
  const v = b.signatures[0]!.value; // canonical base64, 88 chars ending "=="
  const i = 85; // last significant char (before "==")
  const val = ALPH.indexOf(v[i]!);
  assert.equal(val % 4, 0, 'canonical trailing char has zero low-2-bits');
  const nonCanon = v.slice(0, i) + ALPH[val + 1]! + v.slice(i + 1); // same 64 bytes, non-zero unused bits
  b.signatures[0]!.value = nonCanon;
  const verdict = verifyBundleV1(b);
  assert.equal(verdict.signatureChecks[0]!.decision, 'fail', 'non-canonical encoding must not pass the canonical guard');
});

test('§10.4 — malformed signature value for a DID signer FAILS even in fixture mode (decode before key)', () => {
  const u = baseUnsigned();
  u.parties[0]!.primaryClaim = 'did:demos:buyer' as unknown as typeof u.parties[0]['primaryClaim'];
  u.parties[1]!.primaryClaim = 'did:demos:seller' as unknown as typeof u.parties[1]['primaryClaim'];
  const b: AttestationBundleV1 = { ...u, signatures: [
    { party: 'did:demos:buyer' as unknown as never, algorithm: 'ed25519', value: 'not-a-signature' },
    { party: 'did:demos:seller' as unknown as never, algorithm: 'ed25519', value: 'not-a-signature' },
  ] };
  const v = verifyBundleV1(b, { requireSignatures: false });
  assert.ok(v.signatureChecks.every((c) => c.decision === 'fail'), 'malformed sig value fails regardless of key resolution');
  assert.equal(v.decision, 'reject');
});

test('§10.4 — malformed hashes and claims are rejected structurally', () => {
  const u1 = baseUnsigned(); (u1.listingRef as { contentHash: string }).contentHash = 'x';
  assert.equal(verifyBundleV1(signBy(u1, [realKey(0x51), realKey(0x52)])).structurallyValid, false);
  const u2 = baseUnsigned(); u2.parties[0]!.bundleHash = 'x';
  assert.equal(verifyBundleV1(signBy(u2, [realKey(0x51), realKey(0x52)])).structurallyValid, false);
  const u3 = baseUnsigned(); u3.parties[0]!.primaryClaim = { scheme: 'cci', identifier: 'x' };
  assert.equal(verifyBundleV1(signBy(u3, [realKey(0x51), realKey(0x52)])).structurallyValid, false);
  const u4 = baseUnsigned(); u4.parties[0]!.primaryClaim = 'not-a-did' as unknown as typeof u4.parties[0]['primaryClaim'];
  assert.equal(verifyBundleV1(signBy(u4, [realKey(0x51), realKey(0x52)])).structurallyValid, false);
});

test('§10.4 R4-B — anchoredByRole is required and must match a listed party role', () => {
  const u = baseUnsigned();
  delete (u as { anchoredByRole?: unknown }).anchoredByRole; // missing → reject
  assert.equal(verifyBundleV1(signBy(u, [realKey(0x51), realKey(0x52)])).structurallyValid, false);
  const u2 = baseUnsigned(); (u2 as { anchoredByRole: string }).anchoredByRole = 'orchestrator'; // no orchestrator party
  const v2 = verifyBundleV1(signBy(u2, [realKey(0x51), realKey(0x52)]));
  assert.equal(v2.structurallyValid, false);
  assert.ok(v2.reasons.some((r) => /anchoredByRole/.test(r)));
});

test('§10.4 R5-1 — re-vendored v0.1 fixtures reproduce the exclude-rule bundleHashes (upstream golden.json)', () => {
  const exp: Record<string, string> = {
    'attestation-bundle-0004': '9e5ea58d198b459a2929d38019807c465ce9988dcb89c847cce8e80210df39ba',
    'attestation-bundle-0004-seller': '83b180d7a2a00109e96fe099df6c1ef14271b5c0d43c24da78051238cee580bd',
    'attestation-bundle-htlc9': 'ba1889b7d86e37b98cd2f7b4a053f328ab33e7137b0edff8efb4645f24fd4096',
  };
  for (const [f, h] of Object.entries(exp)) {
    const v = verifyBundleV1(load(`${f}.json`), { requireSignatures: false });
    assert.equal(v.bundleHash, h, `${f} reproduces R4-B hash`);
    assert.equal(v.decision, 'accept');
  }
});

// ── R5-1 — anchoredByRole is EXCLUDED from the signed hash; integrity via anchor-address ─────
test('R5-1 — anchoredByRole is excluded from the signed hash (flip does NOT change bundleHash or break the signature)', () => {
  // anchoredByRole is per-copy and EXCLUDED from the hashed canonical form (DACS-Standard v0.1
  // R5-1), so the two two-sided copies hash EQUAL in the happy path. Consequences at the
  // single-bundle layer: (1) buyer- and seller-anchored copies of otherwise-identical content
  // produce the SAME bundleHash; (2) flipping anchoredByRole on a signed bundle does NOT invalidate
  // the signature (it was never in scope). Integrity of anchoredByRole is therefore NOT the
  // signature's job — it is enforced by the anchor-address ↔ anchoredByRole cross-check on the
  // two-sided path (§10.4.2/§248), exercised by the chain tests in verify-bundle-v1-chain.test.ts.
  const buyerSigned = signBy(baseUnsigned({ anchoredByRole: 'buyer' }), [realKey(0x51), realKey(0x52)]);
  const clean = verifyBundleV1(buyerSigned);
  assert.equal(clean.decision, 'accept', JSON.stringify(clean.reasons));
  assert.ok(clean.cryptographicallyVerified);

  // (1) The seller-anchored copy of the same content hashes IDENTICALLY (exclusion proof).
  const sellerSameContent = signBy(baseUnsigned({ anchoredByRole: 'seller' }), [realKey(0x51), realKey(0x52)]);
  assert.equal(verifyBundleV1(sellerSameContent).bundleHash, clean.bundleHash,
    'buyer/seller copies of identical content hash equal — anchoredByRole excluded from the hash');

  // (2) Flipping anchoredByRole WITHOUT re-signing leaves the single-bundle signature valid.
  const flipped: AttestationBundleV1 = { ...buyerSigned, anchoredByRole: 'seller' };
  const v = verifyBundleV1(flipped);
  assert.equal(v.bundleHash, clean.bundleHash, 'flip does not change the signed hash');
  assert.equal(v.decision, 'accept', 'single-bundle verify still accepts — sig unaffected by the excluded field');
  assert.ok(v.cryptographicallyVerified, 'signature still verifies (anchoredByRole not in signed scope)');
});
