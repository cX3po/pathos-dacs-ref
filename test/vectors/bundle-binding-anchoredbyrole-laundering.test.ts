/**
 * #248 authority-laundering regression suite (Codex adversarial review, 2026-07).
 *
 * VULNERABILITY CLASS: `anchoredByRole` is EXCLUDED from the signed scope of a
 * FaultAttestationBundle / legacy AttestationBundle copy (see bundle-binding-v1.ts
 * `bundleScope` — it strips `signatures` AND `anchoredByRole`; R5-1 exclusion, also
 * documented in bundle-signed-scope-v1.ts). Yet `impliedFaultSet` derives a legacy
 * copy's implied absolute-fault SET from (outcome, anchoredByRole), and
 * `faultedPartyPermitted` validates a FAB's permissible set against anchoredByRole.
 * An attacker can therefore flip `anchoredByRole` WITHOUT invalidating the signature
 * and launder a `fail` (contradiction) into a `present` (agreement).
 *
 * INVARIANT ENFORCED BY THE FIX: no mutation of the unsigned `anchoredByRole` field
 * may turn a `fail` disposition into `present`, in ANY of the 3 new #248 families
 * (perspective-pair, mixed-version, AND extended-pointer).
 * The fix re-anchors the unsigned field to a TRUSTED signal — the role-keyed anchor
 * the copy was published under. This mirrors the §10.4.2/§248 anchor-address ↔
 * anchoredByRole cross-check already enforced in verifyV1TwoSided
 * (verify-bundle-v1.ts FIX 1): the copy fetched from role X's anchor MUST declare
 * anchoredByRole === X. A copy whose anchoredByRole disagrees with its anchor
 * is forged/mislabeled → fail-closed.
 *   - pair / mixed-version families: the trusted anchor is the copies-map KEY
 *     (anchorRoleMismatch(anchorKey, copy)).
 *   - extended-pointer family: there is NO copies-map key, but the BINDING that
 *     anchors the pointer supplies the trusted role. binding.role is bound to
 *     binding.logicalAddress = derive(jobId, role); the dereferenced FAB MUST declare
 *     anchoredByRole === binding.role (anchorRoleMismatch(binding.role, dereferenced)).
 *     (Follow-up adversarial review, 2026-07: the pointer family was STILL vulnerable
 *     after the pair/mixed fix — faultedPartyPermitted trusted the unsigned
 *     anchoredByRole with no anchor to bind it. This suite pins the closure.)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { sha512, sha256 } from '@noble/hashes/sha2';
import canonicalize from 'canonicalize';
import {
  resolveMixedVersionPair,
  resolveFaultBundlePair,
  resolveFaultBundlePointer,
  deriveBundleLogicalAddress,
} from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...m));

type JsonObject = Record<string, any>;

function loadCorpus(file: string): JsonObject {
  return JSON.parse(readFileSync(
    new URL(`../../conformance/cross-run-corpus/dacs248/${file}`, import.meta.url),
    'utf8',
  ));
}

function vector(corpus: JsonObject, name: string): JsonObject {
  const v = corpus.vectors.find((c: JsonObject) => c.name === name);
  assert.ok(v, `missing corpus vector ${name}`);
  return structuredClone(v);
}

const mixed = loadCorpus('mixed-version-reconciliation-v0.3.json');
const pair = loadCorpus('fault-bundle-perspective-pair-v0.3.json');
const pointerCorpus = loadCorpus('fab-bundle-extended-pointer-v0.3.json');

const ROLES = ['buyer', 'seller', 'orchestrator'] as const;
function otherRoles(role: string): string[] {
  return ROLES.filter((r) => r !== role);
}

// ---- signing helpers (extended-pointer setup) ----------------------------------
// The pointer-family exploit requires an "impermissible-under-true-role" FAB as the
// starting state; the published fab-pointer-valid is a no-fault (completed) copy, so we
// re-derive a fault FAB and SIGN it. The disclosed corpus seeds are the ed25519 32-byte
// private seeds (corpus.seeds). Signing here is ONLY to set up the base state — the
// MUTATION step below flips anchoredByRole WITHOUT re-signing, which is the whole point
// (anchoredByRole is outside bundleScope, so the signature stays valid).
const SEEDS: Record<string, string> = pointerCorpus.seeds;
const FAULT_BUNDLE_DOMAIN = 'dacs-fault-bundle:v1:';
const FAULT_BUNDLE_POINTER_DOMAIN = 'dacs-fault-bundle-pointer:v1:';
const enc = new TextEncoder();

function hex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
}
function jcsBytes(v: unknown): Uint8Array {
  return enc.encode(canonicalize(v as any));
}
/** §10.4.1 bundleScope hash: JCS over the bundle WITHOUT signatures AND WITHOUT anchoredByRole. */
function bundleScopeHash(bundle: JsonObject): Uint8Array {
  const { signatures: _s, anchoredByRole: _a, ...signed } = bundle;
  return sha256(jcsBytes(signed));
}
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function seed(role: string): string {
  const s = SEEDS[role];
  assert.ok(typeof s === 'string', `missing disclosed seed for ${role}`);
  return s;
}
/** Ed25519 over the §B.7 domain-separated payload the verifier's fallback accepts: domain || hex(hash). */
function signDomainHash(domain: string, hash: Uint8Array, seedHex: string): string {
  const hashText = enc.encode(hex(hash));
  const dom = enc.encode(domain);
  const msg = new Uint8Array(dom.length + hashText.length);
  msg.set(dom);
  msg.set(hashText, dom.length);
  return b64url(ed25519.sign(msg, Uint8Array.from(Buffer.from(seedHex, 'hex'))));
}

/**
 * Build a valid extended-pointer request whose dereferenced FAB carries an
 * `aborted-by-other` fault with `faultedParty=faulted` anchored under `anchorRole`.
 * When faulted === anchorRole the FAB is IMPERMISSIBLE (aborted-by-other requires
 * faulted !== anchoredRole); when faulted !== anchorRole it is permissible. The
 * binding is anchored coherently at `anchorRole` (binding.role === anchorRole, with
 * logicalAddress derived from it). Signs the FAB + pointer; triple-identity holds.
 */
function buildPointerRequest(anchorRole: string, faulted: string): {
  publicKeys: JsonObject; pointer: JsonObject; dereferenced: JsonObject; binding: JsonObject;
} {
  const base = vector(pointerCorpus, 'fab-pointer-valid');
  const deref: JsonObject = structuredClone(base.dereferenced);
  deref.outcome = 'aborted-by-other';
  deref.faultedParty = faulted;
  deref.anchoredByRole = anchorRole;
  deref.phaseSummary = [{ index: 0, kind: 'deliver-storage-program', outcome: 'fail' }];
  const derefHash = bundleScopeHash(deref);
  deref.signatures = [
    { party: 'did:demos:buyer', algorithm: 'ed25519', value: signDomainHash(FAULT_BUNDLE_DOMAIN, derefHash, seed("buyer")) },
    { party: 'did:demos:seller', algorithm: 'ed25519', value: signDomainHash(FAULT_BUNDLE_DOMAIN, derefHash, seed("seller")) },
  ];

  const recomputed = hex(bundleScopeHash(deref));
  const pointer: JsonObject = structuredClone(base.pointer);
  pointer.fullBundleContentHash = recomputed;
  delete pointer.signature;
  const pointerHash = sha256(jcsBytes(pointer));
  pointer.signature = {
    algorithm: 'ed25519',
    signer: 'did:demos:seller',
    value: signDomainHash(FAULT_BUNDLE_POINTER_DOMAIN, pointerHash, seed("seller")),
  };

  const binding: JsonObject = structuredClone(base.binding);
  binding.role = anchorRole;
  binding.jobId = deref.jobId;
  binding.logicalAddress = deriveBundleLogicalAddress(binding.jobId, anchorRole as any);
  binding.bundleContentHash = recomputed;

  return { publicKeys: pointerCorpus.publicKeys, pointer, dereferenced: deref, binding };
}

/**
 * PRIMARY EXPLOIT — the published `mixed-implied-fault-contradiction` vector, mutated.
 *
 * FAB(seller) faultedParty=seller → set {seller}; legacy(buyer) aborted-by-self,
 * anchoredByRole=buyer → set {buyer}. {buyer} ∩ {seller} = ∅ → correct `fail`.
 * MUTATION: flip ONLY the legacy copy's anchoredByRole buyer→seller (signature is
 * UNTOUCHED and stays valid because anchoredByRole is unsigned). Pre-fix the resolver
 * derives {seller}, {seller} ∩ {seller} ≠ ∅ → WRONGLY `present` (authority laundering).
 * Post-fix: the legacy copy's anchoredByRole (seller) no longer matches its anchor key
 * (buyer) → fail-closed.
 */
test('EXPLOIT: flipping unsigned anchoredByRole on the legacy copy must not launder fail→present', () => {
  const v = vector(mixed, 'mixed-implied-fault-contradiction');

  // Sanity: the pristine vector resolves fail (the contradiction stands).
  const pristine = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: v.copies });
  assert.equal(pristine.disposition, 'fail', 'pristine contradiction vector must resolve fail');

  // MUTATION: flip ONLY the legacy buyer copy's anchoredByRole. Signature untouched.
  const mutated = structuredClone(v);
  assert.equal(mutated.copies.buyer.anchoredByRole, 'buyer');
  assert.ok(!('faultBundleVersion' in mutated.copies.buyer), 'buyer copy is the legacy one');
  mutated.copies.buyer.anchoredByRole = 'seller';

  const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: mutated.copies });

  // The invariant: an unsigned-field flip may NEVER turn fail into present.
  assert.notEqual(
    result.disposition, 'present',
    `AUTHORITY LAUNDERING: flipping unsigned anchoredByRole laundered fail→present (${result.detail})`,
  );
  assert.ok(
    result.disposition === 'fail' || result.disposition === 'indeterminate',
    `expected fail/indeterminate after anchoredByRole flip, got ${result.disposition}`,
  );
});

/**
 * SIBLING CLASS 1 — mixed-version family: every `fail` vector that carries a legacy
 * copy, mutate its anchoredByRole to every other role. No flip may produce `present`.
 */
test('SIBLING: no anchoredByRole flip on any legacy copy launders fail→present (mixed-version family)', () => {
  for (const v of mixed.vectors as JsonObject[]) {
    if (v.expected !== 'fail') continue;
    for (const [role, copy] of Object.entries(v.copies as JsonObject) as [string, JsonObject][]) {
      // Mutate BOTH legacy and FAB copies — anchoredByRole is unsigned on both.
      for (const flipped of otherRoles(copy.anchoredByRole ?? role)) {
        const mutated = structuredClone(v);
        mutated.copies[role].anchoredByRole = flipped;
        const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: mutated.copies });
        assert.notEqual(
          result.disposition, 'present',
          `LAUNDERING in ${v.name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
        );
      }
    }
  }
});

/**
 * SIBLING CLASS 2 — perspective-pair family: same mutation on every FAB copy of every
 * `fail` vector. No flip may produce `present`.
 */
test('SIBLING: no anchoredByRole flip on any copy launders fail→present (perspective-pair family)', () => {
  for (const v of pair.vectors as JsonObject[]) {
    if (v.expected !== 'fail') continue;
    for (const [role, copy] of Object.entries(v.copies as JsonObject) as [string, JsonObject][]) {
      for (const flipped of otherRoles(copy.anchoredByRole ?? role)) {
        const mutated = structuredClone(v);
        mutated.copies[role].anchoredByRole = flipped;
        const result = resolveFaultBundlePair({ publicKeys: pair.publicKeys, copies: mutated.copies });
        assert.notEqual(
          result.disposition, 'present',
          `LAUNDERING in ${v.name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
        );
      }
    }
  }
});

/**
 * SIBLING CLASS 3 — the perspective-flip control and the orchestrator legacy family:
 * flip anchoredByRole on the legacy-legacy genuine-divergence vector and the mixed
 * orchestrator-divergent vector individually. Belt-and-suspenders over the sweeps above.
 */
test('SIBLING: legacy-legacy divergence + orchestrator divergence resist anchoredByRole laundering', () => {
  const targets: Array<[JsonObject, string, string]> = [
    [mixed, 'legacy-legacy-genuine-divergence', 'buyer'],
    [mixed, 'legacy-legacy-genuine-divergence', 'seller'],
    [mixed, 'mixed-orchestrator-divergent', 'buyer'],
    [mixed, 'mixed-orchestrator-divergent', 'seller'],
  ];
  for (const [corpus, name, role] of targets) {
    const v = vector(corpus, name);
    for (const flipped of otherRoles(v.copies[role].anchoredByRole ?? role)) {
      const mutated = structuredClone(v);
      mutated.copies[role].anchoredByRole = flipped;
      const result = resolveMixedVersionPair({ publicKeys: corpus.publicKeys, copies: mutated.copies });
      assert.notEqual(
        result.disposition, 'present',
        `LAUNDERING in ${name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
      );
    }
  }
});

/**
 * REGRESSION — the fix must NOT break legitimate vectors: every published `pass`
 * vector (whose anchoredByRole equals its anchor-address key) must still resolve
 * present with the anchor-key binding enforced.
 */
test('REGRESSION: legitimate pass vectors still resolve present with anchor-key binding enforced', () => {
  for (const v of mixed.vectors as JsonObject[]) {
    if (v.expected !== 'pass') continue;
    const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: v.copies });
    assert.equal(result.disposition, 'present', `${v.name} regressed: ${result.detail}`);
  }
  for (const v of pair.vectors as JsonObject[]) {
    if (v.expected !== 'pass') continue;
    const result = resolveFaultBundlePair({ publicKeys: pair.publicKeys, copies: v.copies });
    assert.equal(result.disposition, 'present', `${v.name} regressed: ${result.detail}`);
  }
});

// ============================================================================
// EXTENDED-POINTER FAMILY (resolveFaultBundlePointer) — the residual hole.
//
// The pair/mixed fix bound anchoredByRole to the copies-map KEY. The pointer family
// has no such key, so faultedPartyPermitted trusted the unsigned anchoredByRole with
// nothing to anchor it. A FAB signed impermissible-under-its-TRUE-role could be
// laundered to `present` by flipping the unsigned anchoredByRole — WITHOUT re-signing.
// The fix binds anchoredByRole to the SIGNED/derived binding.role.
// ============================================================================

/**
 * PRIMARY EXPLOIT (extended-pointer) — the exact concrete laundering from the review:
 * FAB aborted-by-other, faultedParty=buyer, TRUE anchoredByRole=buyer (anchored under the
 * buyer binding). Under its true role this is IMPERMISSIBLE (aborted-by-other requires
 * faulted !== anchoredRole; buyer===buyer) → validateFaultCopy rejects → pointer resolves fail.
 * MUTATION: flip the unsigned anchoredByRole buyer→seller; the FAB signature is UNTOUCHED and
 * stays valid because bundleScope excludes anchoredByRole. Pre-fix, faultedPartyPermitted then
 * sees faulted=buyer, anchoredRole=seller, buyer !== seller → permissible → `present`.
 * Post-fix: anchoredByRole (seller) no longer matches binding.role (buyer) → fail-closed.
 */
test('EXPLOIT (pointer): flipping unsigned anchoredByRole on the dereferenced FAB must not launder fail→present', () => {
  const req = buildPointerRequest('buyer', 'buyer'); // faulted === anchorRole → impermissible under TRUE role

  // BEFORE: true anchoredByRole=buyer, aborted-by-other/faulted=buyer → impermissible → fail.
  const before = resolveFaultBundlePointer({
    publicKeys: req.publicKeys,
    pointer: structuredClone(req.pointer),
    dereferenced: structuredClone(req.dereferenced),
    binding: structuredClone(req.binding),
  });
  assert.equal(before.disposition, 'fail',
    `pristine impermissible-under-true-role FAB must resolve fail, got ${before.disposition}: ${before.detail}`);

  // MUTATION: flip ONLY the unsigned anchoredByRole. Signatures untouched (must stay valid).
  const mutatedDeref = structuredClone(req.dereferenced);
  assert.equal(mutatedDeref.anchoredByRole, 'buyer');
  mutatedDeref.anchoredByRole = 'seller';

  const after = resolveFaultBundlePointer({
    publicKeys: req.publicKeys,
    pointer: structuredClone(req.pointer),
    dereferenced: mutatedDeref,
    binding: structuredClone(req.binding),
  });

  // The invariant: an unsigned-field flip may NEVER turn fail into present.
  assert.notEqual(after.disposition, 'present',
    `AUTHORITY LAUNDERING (pointer): flipping unsigned anchoredByRole laundered fail→present (${after.detail})`);
  assert.ok(after.disposition === 'fail' || after.disposition === 'indeterminate',
    `expected fail/indeterminate after anchoredByRole flip, got ${after.disposition}`);
});

/**
 * SIBLING SWEEP (extended-pointer family) — for every impermissible base FAB (faulted ===
 * anchorRole under aborted-by-other, which is fail), flip the unsigned anchoredByRole to
 * EVERY other role. No flip may produce `present`. This is the pointer-family arm of the
 * required 3-family sweep.
 */
test('SIBLING: no anchoredByRole flip on the dereferenced FAB launders fail→present (extended-pointer family)', () => {
  for (const anchorRole of ROLES) {
    // Base: aborted-by-other with faulted === anchorRole → impermissible under true role → fail.
    const req = buildPointerRequest(anchorRole, anchorRole);
    const pristine = resolveFaultBundlePointer({
      publicKeys: req.publicKeys,
      pointer: structuredClone(req.pointer),
      dereferenced: structuredClone(req.dereferenced),
      binding: structuredClone(req.binding),
    });
    assert.equal(pristine.disposition, 'fail',
      `base (anchor=${anchorRole}, faulted=${anchorRole}) must be fail, got ${pristine.disposition}`);

    for (const flipped of otherRoles(anchorRole)) {
      const mutatedDeref = structuredClone(req.dereferenced);
      mutatedDeref.anchoredByRole = flipped;
      const result = resolveFaultBundlePointer({
        publicKeys: req.publicKeys,
        pointer: structuredClone(req.pointer),
        dereferenced: mutatedDeref,
        binding: structuredClone(req.binding),
      });
      assert.notEqual(result.disposition, 'present',
        `LAUNDERING (pointer): anchor=${anchorRole} flip anchoredByRole→${flipped} turned fail→present (${result.detail})`);
    }
  }
});

/**
 * REGRESSION (pointer) — a legitimately PERMISSIBLE fault FAB (faulted !== anchorRole),
 * anchored coherently, must resolve `present`. Then flipping its anchoredByRole away from
 * binding.role must NOT stay present (fail-closed), proving the fix binds the field rather
 * than merely passing the published vectors. Also: the published fab-pointer-valid still passes.
 */
test('REGRESSION (pointer): legitimate permissible fault FAB resolves present; anchoredByRole flip fails closed', () => {
  // Published valid vector unchanged.
  const pub = vector(pointerCorpus, 'fab-pointer-valid');
  const pubResult = resolveFaultBundlePointer({
    publicKeys: pointerCorpus.publicKeys, pointer: pub.pointer, dereferenced: pub.dereferenced, binding: pub.binding,
  });
  assert.equal(pubResult.disposition, 'present', `fab-pointer-valid regressed: ${pubResult.detail}`);

  // A permissible fault FAB (aborted-by-other, faulted=seller, anchor=buyer) → present.
  const req = buildPointerRequest('buyer', 'seller');
  const good = resolveFaultBundlePointer({
    publicKeys: req.publicKeys,
    pointer: structuredClone(req.pointer),
    dereferenced: structuredClone(req.dereferenced),
    binding: structuredClone(req.binding),
  });
  assert.equal(good.disposition, 'present',
    `legitimate permissible fault FAB regressed: ${good.disposition} ${good.detail}`);

  // Flip anchoredByRole away from binding.role (buyer) → must fail closed, not present.
  const tampered = structuredClone(req.dereferenced);
  tampered.anchoredByRole = 'seller';
  const flipped = resolveFaultBundlePointer({
    publicKeys: req.publicKeys,
    pointer: structuredClone(req.pointer),
    dereferenced: tampered,
    binding: structuredClone(req.binding),
  });
  assert.notEqual(flipped.disposition, 'present',
    `anchoredByRole flip on a permissible FAB must fail closed, got present (${flipped.detail})`);
});
