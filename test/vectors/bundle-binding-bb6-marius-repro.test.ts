/**
 * BB-6 cross-implementation repro of Marius (@mj-deving)'s DACS-Standard#248 finding.
 *
 * Marius reported that the DACS-Standard *reference* resolver's `resolve_bb6()` decides
 * whether a canonical form has FULL SIGNATURE STANDING from only its first address-sorted
 * copy (`cps[0]`). If a canonical form has a lesser-signed copy at a native address that
 * sorts BEFORE a byte-equal full-signed copy, the reference masks the full copy and returns
 * `indeterminate` / null.
 *
 * This harness reproduces his EXACT construction against OUR resolver
 * (`resolveBundleBinding`, src/lib/bundle-binding-v1.ts) using the published deterministic
 * seeds from the `bb-equal-standing-divergence` vector, with real Ed25519 signatures.
 *
 * Construction:
 *   - Base: `bb-equal-standing-divergence` (form A = aborted-by-self/faulted seller at
 *     nativeAddress stor-b1a1…; form B = aborted-by-other/faulted buyer at stor-7adb…).
 *     Both are seller-only signed => lesser standing. Canonically UNEQUAL to each other.
 *   - ADD a SECOND native address for form A: a copy that is canonically BYTE-EQUAL to A
 *     (same bundleContentHash — signatures/anchoredByRole are outside the canonical scope),
 *     but carries valid BUYER + SELLER signatures => FULL standing.
 *   - Every binding must pass verify_binding; every fetched copy must pass _post_fetch_valid.
 *
 * EXPECTED per BB-6: `present`, selecting the full-standing copy of form A.
 * Marius's reference finding: `indeterminate` / null (defect).
 *
 * We ALSO run the order-independence check: place the full copy's native address so it sorts
 * BEFORE vs AFTER the lesser form-A copy — the disposition must not change.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { resolveBundleBinding, type BundleBindingV1 } from '../../src/lib/bundle-binding-v1.js';
import { jcsCanonical } from '../../src/jcs.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

const corpus = JSON.parse(readFileSync(
  new URL('../../conformance/cross-run-corpus/dacs248/bundle-binding-v0.1.json', import.meta.url),
  'utf8',
));

const encoder = new TextEncoder();
const BINDING_DOMAIN = 'dacs-bundle-binding:v1:';
const FAULT_BUNDLE_DOMAIN = 'dacs-fault-bundle:v1:';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('');
}
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function seed(name: 'buyer' | 'seller'): Uint8Array {
  return new Uint8Array(Buffer.from(corpus.seeds[name], 'hex'));
}
/** Sign domain || utf8(hex(hash)) — the exact message the resolver's verifyHashedDomain fallback checks. */
function signHashedDomain(domain: string, hash: Uint8Array, priv: Uint8Array): string {
  const hashText = encoder.encode(hex(hash));
  const domainBytes = encoder.encode(domain);
  const message = new Uint8Array(domainBytes.length + hashText.length);
  message.set(domainBytes);
  message.set(hashText, domainBytes.length);
  return b64url(ed25519.sign(message, priv));
}
/** Canonical bundle scope: strip signatures + anchoredByRole, JCS-canonicalise, sha256. */
function bundleContentHash(bundle: Record<string, unknown>): Uint8Array {
  const { signatures: _s, anchoredByRole: _a, ...signed } = bundle;
  return sha256(jcsCanonical(signed));
}
/** Sign a BundleBinding tuple: sha256(JCS(tuple without signature)) under the binding domain. */
function signBinding(tupleNoSig: Omit<BundleBindingV1, 'signature'>, priv: Uint8Array): string {
  const tupleHash = sha256(jcsCanonical(tupleNoSig));
  return signHashedDomain(BINDING_DOMAIN, tupleHash, priv);
}

const vector = corpus.vectors.find((v: { name: string }) => v.name === 'bb-equal-standing-divergence');
assert.ok(vector, 'base vector bb-equal-standing-divergence missing');

const buyerPriv = seed('buyer');
const sellerPriv = seed('seller');

// --- Sanity: seeds reproduce the published public keys -----------------------
test('BB-6 repro: published seeds reproduce published public keys', () => {
  assert.equal(b64url(ed25519.getPublicKey(buyerPriv)), corpus.publicKeys['did:demos:buyer']);
  assert.equal(b64url(ed25519.getPublicKey(sellerPriv)), corpus.publicKeys['did:demos:seller']);
});

// Form A native address + anchored bundle from the base vector (aborted-by-self / faulted seller).
const FORM_A_ADDR = 'stor-b1a17d626dbda551f8fb2d7a96632d7752d84995';
const formABundle: Record<string, unknown> = vector.anchored[FORM_A_ADDR];
assert.ok(formABundle, 'form A anchored bundle missing');
assert.equal(formABundle.outcome, 'aborted-by-self');
assert.equal(formABundle.faultedParty, 'seller');

const logicalAddress = vector.bindings[0].logicalAddress as string;
const formAContentHashHex = hex(bundleContentHash(formABundle));

/**
 * Build a FULL-signed, canonically byte-equal copy of form A at `newAddr`.
 * The canonical scope (excluding signatures/anchoredByRole) is IDENTICAL to form A, so the
 * recomputed bundleContentHash matches. We add BOTH buyer + seller signatures over the same
 * fault-bundle content hash => full standing.
 */
function buildFullFormA(newAddr: string): { binding: BundleBindingV1; anchored: Record<string, unknown> } {
  const fullBundle: Record<string, unknown> = { ...formABundle };
  const contentHash = bundleContentHash(fullBundle); // identical to form A's
  assert.equal(hex(contentHash), formAContentHashHex, 'full copy must be canonically byte-equal to form A');
  fullBundle.signatures = [
    { party: 'did:demos:buyer', algorithm: 'ed25519', value: signHashedDomain(FAULT_BUNDLE_DOMAIN, contentHash, buyerPriv) },
    { party: 'did:demos:seller', algorithm: 'ed25519', value: signHashedDomain(FAULT_BUNDLE_DOMAIN, contentHash, sellerPriv) },
  ];

  const tupleNoSig: Omit<BundleBindingV1, 'signature'> = {
    bindingVersion: '1',
    jobId: vector.request.jobId,
    role: 'seller',
    logicalAddress,
    nativeAddress: newAddr,
    bundleContentHash: hex(contentHash),
    anchorTx: `demos-testnet:tx-${newAddr.slice(5, 21)}`,
    signer: 'did:demos:seller',
  };
  const binding: BundleBindingV1 = {
    ...tupleNoSig,
    signature: { algorithm: 'ed25519', signer: 'did:demos:seller', value: signBinding(tupleNoSig, sellerPriv) },
  };
  return { binding, anchored: fullBundle };
}

function runRepro(fullAddr: string) {
  const { binding: fullBinding, anchored: fullBundle } = buildFullFormA(fullAddr);
  // Original two lesser-signed bindings (form A + form B) from the base vector, plus the new full form-A copy.
  const bindings: BundleBindingV1[] = [...vector.bindings, fullBinding];
  const anchored: Record<string, unknown> = { ...vector.anchored, [fullAddr]: fullBundle };
  return resolveBundleBinding(
    { ...vector.request, publicKeys: corpus.publicKeys, partyMap: vector.partyMap },
    bindings,
    (nativeAddress: string) => anchored[nativeAddress],
  );
}

// Choose two full-copy addresses: one sorting BEFORE the lesser form-A address (stor-b1a1…),
// one sorting AFTER it, so we exercise both native-address orderings.
const FULL_ADDR_BEFORE = 'stor-0000000000000000000000000000000000000000'; // sorts before stor-b1a1…
const FULL_ADDR_AFTER = 'stor-ffffffffffffffffffffffffffffffffffffffff'; // sorts after stor-b1a1…
assert.ok(FULL_ADDR_BEFORE.localeCompare(FORM_A_ADDR) < 0);
assert.ok(FULL_ADDR_AFTER.localeCompare(FORM_A_ADDR) > 0);

test('BB-6 repro (Marius): full-standing copy of form A is selected => present (NOT indeterminate/null)', () => {
  // The primary defect Marius found in the DACS-Standard reference: it returns indeterminate/null.
  // Our resolver computes standing across EVERY validated copy (`group.some(fullySigned)`), so the
  // form-A group has full standing and is selected => present with form-A content.
  const result = runRepro(FULL_ADDR_AFTER);
  assert.equal(result.disposition, 'present', `expected present, got ${result.disposition}: ${result.detail}`);
  assert.equal(result.resolvedRole, 'seller');
  assert.notEqual(result.resolvedNativeAddress, undefined, 'resolvedNativeAddress must not be null');
  // The resolved bundle is form A (aborted-by-self / faulted seller).
  assert.equal((result.bundle as Record<string, unknown>).outcome, 'aborted-by-self');
  assert.equal((result.bundle as Record<string, unknown>).faultedParty, 'seller');
  // The resolved native address must be the FULL-standing copy, never the lesser one.
  assert.equal(result.resolvedNativeAddress, FULL_ADDR_AFTER,
    'resolved copy must be the full-standing copy, not the canonically-equal lesser copy');
});

test('BB-6 repro (Marius): order-independence — full copy sorting BEFORE vs AFTER the lesser form-A copy yields identical disposition AND resolves to the full copy either way', () => {
  const before = runRepro(FULL_ADDR_BEFORE);
  const after = runRepro(FULL_ADDR_AFTER);
  // Disposition must be stable across native-address ordering (the ordering-dependence Marius flagged).
  assert.equal(before.disposition, after.disposition, 'disposition must not depend on native-address ordering');
  assert.equal(before.disposition, 'present');
  // In BOTH orderings the resolved copy is the full-standing copy (its own address), never the
  // lesser copy, and never null — proving standing AND winner-selection use every validated copy,
  // not just the first address-sorted one (cps[0]). This is the RED→GREEN pin for the winner fix.
  assert.equal(before.resolvedNativeAddress, FULL_ADDR_BEFORE);
  assert.equal(after.resolvedNativeAddress, FULL_ADDR_AFTER);
  assert.notEqual(before.resolvedNativeAddress, undefined);
  assert.notEqual(after.resolvedNativeAddress, undefined);
});
