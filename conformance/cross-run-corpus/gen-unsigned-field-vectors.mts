#!/usr/bin/env tsx
/**
 * PUBLISHED conformance-vector GENERATOR for the "unsigned-field / loosely-typed member
 * laundering" DEFECT CLASS in DACS-5 §10.4 BundleBinding / FaultAttestationBundle resolution.
 *
 * THE CLASS (one sentence)
 * ------------------------
 * A receipt/bundle member that a resolution decision depends on is either OUTSIDE the signed
 * hash scope, or too LOOSELY TYPED, so a mutation that KEEPS THE SIGNATURE VALID changes the
 * verdict — laundering a `fail`/`indeterminate` into a `present` (or hiding a divergence).
 *
 * The ecosystem has been finding this ONE class one instance at a time, by hand:
 *   - `anchoredByRole` (#248): the field is stripped from bundleScope, so flipping it post-signing
 *     re-attributes fault authority without breaking the signature (fail -> present).
 *   - xm33's `bundleCount` boolean-coverage gap: a `bool` where an `int` is expected slips through
 *     an `x == 0` check because `0 == false` in JS.
 *   - RB's `windowingBasis` container-type defect: an array/object where a scalar is expected takes
 *     the wrong branch (TypeError, or — worse — silently evades a cross-copy check).
 *
 * This generator turns that artisanal hand-finding into a SYSTEMATIC, PUBLISHED, cross-runnable
 * vector set. For each resolution-relevant field that is unsigned OR loosely typed, and for each of
 * the FAB families (pair / mixed-version / extended-pointer) + the base BB path where applicable, it
 * emits a VECTOR TRIPLE:
 *   - PRISTINE : correct field, its correct expected disposition.
 *   - MUTATED  : the field altered so the SIGNATURE STILL VERIFIES (or the type is confused) — the
 *                laundering attempt — with expected disposition = the SAFE one (must NOT become
 *                present when pristine was fail/indeterminate; must fail-closed).
 *   - CONTROL  : the field flipped in a way that SHOULD LEGITIMATELY change the disposition, so the
 *                triple is not tautological — it proves the resolver distinguishes real from
 *                laundered change.
 *
 * Every signed input uses REAL Ed25519 over the JCS-canonical signed scope with the published
 * deterministic corpus seeds (buyer a1.., seller c3.., orchestrator 0e..). The generator asserts the
 * seeds reproduce the published pubkeys, so the vectors are genuine, not hand-waved.
 *
 * DETERMINISM: run with `--check` for a byte-for-byte determinism proof (regenerate in-memory,
 * compare to the on-disk file; nonzero exit on drift). `npm run gen:unsigned-vectors` = regen + check.
 *
 * Output: conformance/cross-run-corpus/dacs248/unsigned-field-laundering-v0.1.json
 * Wired into: unsigned-field-cross-run.mts (sibling runner; AGREE/DIVERGE per vector vs OUR resolver).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../../src/jcs.js';
import { deriveBundleLogicalAddress, type BundleBindingRole } from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, 'dacs248', 'unsigned-field-laundering-v0.1.json');
const SET = 'unsigned-field-laundering-v0.1';

// -------------------------------------------------------------------------------------------------
// primitives — shared shape with bb-stateful-fuzzer.mts / the anchoredByRole laundering test.
// -------------------------------------------------------------------------------------------------
type Json = Record<string, any>;
const enc = new TextEncoder();
const BINDING_DOMAIN = 'dacs-bundle-binding:v1:';
const FAULT_DOMAIN = 'dacs-fault-bundle:v1:';
const LEGACY_DOMAIN = 'dacs-bundle:v1:';
const POINTER_DOMAIN = 'dacs-fault-bundle-pointer:v1:';
const ROLES: BundleBindingRole[] = ['buyer', 'seller', 'orchestrator'];

// The published deterministic corpus seeds (dacs248). Identical to every sibling set so a vector here
// shares key material with the pinned fixtures.
const SEEDS: Record<BundleBindingRole, string> = {
  buyer: 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
  seller: 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3',
  orchestrator: '0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e',
};
// The published pubkeys these seeds MUST reproduce (asserted below — genuine-key guard).
const PUBLISHED_PUBKEYS: Record<string, string> = {
  'did:demos:buyer': 'vHy8tWNjdfodgkNNRmck2SN39TuYBpXdSdJtDOEiBaU',
  'did:demos:seller': '1AS8RFZa7buJkVDlsLOzK5RBvwy3iEwzEw2o28J90s8',
  'did:demos:orchestrator': 'C-71qeZ55qPhNP4ng3v_MsfLX11E6gm8sOVCutakwMw',
};

function hex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
}
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function priv(role: BundleBindingRole): Uint8Array {
  return Uint8Array.from(Buffer.from(SEEDS[role], 'hex'));
}
function did(role: BundleBindingRole): string {
  return `did:demos:${role}`;
}
function hashCanonical(v: unknown): Uint8Array {
  return sha256(jcsCanonical(v));
}
/** §10.4.1 scope hash: JCS over the bundle WITHOUT signatures AND WITHOUT anchoredByRole. */
function bundleScopeHash(bundle: Json): Uint8Array {
  const { signatures: _s, anchoredByRole: _a, ...signed } = bundle;
  return sha256(jcsCanonical(signed));
}
/** Ed25519 over `domain || hex(hash)` — the exact message verifyHashedDomain reconstructs. */
function signDomainHash(domain: string, hash: Uint8Array, role: BundleBindingRole): string {
  const hashText = enc.encode(hex(hash));
  const domainBytes = enc.encode(domain);
  const msg = new Uint8Array(domainBytes.length + hashText.length);
  msg.set(domainBytes);
  msg.set(hashText, domainBytes.length);
  return b64url(ed25519.sign(msg, priv(role)));
}

function publicKeys(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const role of ROLES) map[did(role)] = b64url(ed25519.getPublicKey(priv(role)));
  return map;
}

// Genuine-key guard: the disclosed seeds MUST reproduce the published pubkeys, else the vectors are
// signed with the wrong keys and every "signature valid" claim is a lie.
function assertGenuineKeys(): void {
  const derived = publicKeys();
  for (const [claim, want] of Object.entries(PUBLISHED_PUBKEYS)) {
    if (derived[claim] !== want) {
      console.error(`FATAL: seed for ${claim} does not reproduce the published pubkey.`);
      console.error(`  derived=${derived[claim]}  published=${want}`);
      process.exit(2);
    }
  }
}

// -------------------------------------------------------------------------------------------------
// builders — produce genuinely signed bundles + bindings.
// -------------------------------------------------------------------------------------------------
function parties(nonce: number): Json[] {
  return [
    { role: 'buyer', primaryClaim: did('buyer'), bundleHash: hex(sha256(enc.encode(`buyer-${nonce}`))) },
    { role: 'seller', primaryClaim: did('seller'), bundleHash: hex(sha256(enc.encode(`seller-${nonce}`))) },
  ];
}

type BundleFacts = {
  kind: 'fab' | 'legacy';
  jobId: string;
  outcome: string;
  faultedParty?: string;
  anchoredByRole: BundleBindingRole;
  nonce: number;
  /** phaseSummary index — normally a scalar 0; the container class ships an array/object here. */
  phaseIndex?: unknown;
  phaseOutcome?: string;
};

/** Build a genuinely-signed FAB / legacy AttestationBundle. Signs both roster roles. */
function buildBundle(f: BundleFacts): { bundle: Json; contentHash: string } {
  const phaseOutcome = f.phaseOutcome ?? (f.outcome === 'completed' || f.outcome === 'failed-substrate' ? 'ok' : 'fail');
  const bundle: Json = {
    jobId: f.jobId,
    outcome: f.outcome,
    anchoredByRole: f.anchoredByRole, // EXCLUDED from signed scope (R5-1)
    listingRef: { listingId: `listing-${f.jobId}`, version: 1, contentHash: hex(sha256(enc.encode(`listing-${f.jobId}`))) },
    parties: parties(f.nonce),
    phaseSummary: [{ index: f.phaseIndex ?? 0, kind: 'deliver-storage-program', outcome: phaseOutcome }],
    vetRecords: [],
    settlementEvidence: [],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1780004000000 + f.nonce,
  };
  if (f.kind === 'fab') {
    bundle.faultBundleVersion = '1';
    bundle.faultedParty = f.faultedParty;
  }
  const scopeHash = bundleScopeHash(bundle);
  const domain = f.kind === 'fab' ? FAULT_DOMAIN : LEGACY_DOMAIN;
  bundle.signatures = ROLES.filter((r) => r !== 'orchestrator').map((r) => ({
    party: did(r),
    algorithm: 'ed25519',
    value: signDomainHash(domain, scopeHash, r),
  }));
  return { bundle, contentHash: hex(scopeHash) };
}

function buildBinding(role: BundleBindingRole, jobId: string, nativeAddress: string, contentHash: string): Json {
  const tuple: Json = {
    bindingVersion: '1',
    jobId,
    role,
    logicalAddress: deriveBundleLogicalAddress(jobId, role),
    nativeAddress,
    bundleContentHash: contentHash,
    anchorTx: `demos-testnet:tx-${nativeAddress.slice(5, 21)}`,
    signer: did(role),
  };
  const value = signDomainHash(BINDING_DOMAIN, hashCanonical(tuple), role);
  return { ...tuple, signature: { algorithm: 'ed25519', signer: did(role), value } };
}

function nativeFor(tag: string): string {
  return `stor-${hex(sha256(enc.encode(`native-${tag}`))).slice(0, 40)}`;
}

// -------------------------------------------------------------------------------------------------
// vector shape. A vector carries its family adapter tag + inputs + expected disposition + provenance.
// -------------------------------------------------------------------------------------------------
type Family = 'pair' | 'mixed' | 'pointer' | 'direct';
type Disposition = 'present' | 'fail' | 'indeterminate';
type Vector = Json & {
  name: string;
  family: Family;
  field: string;             // the unsigned/loose field this vector exercises
  triple: 'pristine' | 'mutated' | 'control';
  expected: Disposition;
  reachable: boolean;        // false => aspirational/reference-only (documented, not asserted AGREE)
  provenance: Json;
};

const vectors: Vector[] = [];

// =================================================================================================
// CLASS A — `anchoredByRole` (the KNOWN #248 unsigned-field). Included so the set SELF-VALIDATES:
// our hardened resolver must AGREE on all three triple members.
// =================================================================================================
{
  // PRISTINE (mixed): a genuine implied-fault contradiction -> fail (the contradiction stands).
  //   FAB(seller) faulted=seller -> {seller}; legacy(buyer) aborted-by-self @buyer -> {buyer}.
  //   {seller} ∩ {buyer} = ∅ -> fail.
  const fabA = buildBundle({ kind: 'fab', jobId: 'ABR-1', outcome: 'aborted-by-other', faultedParty: 'seller', anchoredByRole: 'seller', nonce: 1 });
  const legA = buildBundle({ kind: 'legacy', jobId: 'ABR-1', outcome: 'aborted-by-self', anchoredByRole: 'buyer', nonce: 2 });
  vectors.push({
    name: 'anchoredByRole-pristine-contradiction',
    family: 'mixed', field: 'anchoredByRole', triple: 'pristine', expected: 'fail', reachable: true,
    copies: { seller: fabA.bundle, buyer: legA.bundle },
    provenance: {
      rule: '§10.4.3 mixed-version + §10.4.1 implied absolute-fault set',
      signedScopeRule: 'anchoredByRole is EXCLUDED from bundleScope (R5-1); it is re-anchored to the copies-map key (anchorRoleMismatch).',
      why: 'FAB {seller} and legacy implied {buyer} do not intersect — a genuine contradiction resolves fail. Both copies carry anchoredByRole == their anchor key (coherent).',
    },
  });

  // MUTATED (mixed): flip ONLY the legacy copy's UNSIGNED anchoredByRole buyer->seller. Signature is
  //   untouched and STILL VERIFIES. Pre-fix: implied {seller} intersects {seller} -> laundered present.
  //   Post-fix (our resolver): anchoredByRole(seller) != anchor key(buyer) -> fail-closed. SAFE = fail.
  const legAmut = structuredClone(legA.bundle);
  legAmut.anchoredByRole = 'seller'; // UNSIGNED flip; signature bytes unchanged
  vectors.push({
    name: 'anchoredByRole-mutated-launder-attempt',
    family: 'mixed', field: 'anchoredByRole', triple: 'mutated', expected: 'fail', reachable: true,
    copies: { seller: fabA.bundle, buyer: legAmut },
    provenance: {
      rule: '§10.4.2/§248 anchor-address ↔ anchoredByRole integrity',
      mutation: 'legacy.anchoredByRole buyer->seller AFTER signing (signature untouched — anchoredByRole is outside bundleScope, so it stays valid).',
      signedScopeRule: 'The unsigned field is re-anchored to the copies-map KEY; a copy at key=buyer that declares anchoredByRole=seller is forged/mislabeled -> reject.',
      why: 'SAFE disposition is fail: an unsigned-field flip must NEVER launder a contradiction (fail) into agreement (present).',
    },
  });

  // CONTROL (mixed): a LEGITIMATE anchoredByRole change on a coherently re-signed pair that genuinely
  //   converges. legacy(buyer) aborted-by-other @buyer implies {seller,orchestrator}; intersects FAB
  //   {seller} -> present. Here anchoredByRole == anchor key on BOTH copies (no laundering) and the
  //   fault genuinely reconciles. Proves the resolver ACCEPTS a real (coherent) configuration.
  const fabAc = buildBundle({ kind: 'fab', jobId: 'ABR-2', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller', nonce: 3 });
  const legAc = buildBundle({ kind: 'legacy', jobId: 'ABR-2', outcome: 'aborted-by-other', anchoredByRole: 'buyer', nonce: 4 });
  vectors.push({
    name: 'anchoredByRole-control-legitimate-converge',
    family: 'mixed', field: 'anchoredByRole', triple: 'control', expected: 'present', reachable: true,
    copies: { seller: fabAc.bundle, buyer: legAc.bundle },
    provenance: {
      rule: '§10.4.3 mixed-version convergence',
      why: 'A coherent pair (each anchoredByRole == its anchor key) whose implied fault sets DO intersect ({seller} ∈ {seller,orchestrator}) genuinely resolves present. This is the non-tautology control: the resolver distinguishes a real convergence from a laundered one.',
    },
  });
}

// =================================================================================================
// CLASS A' — `anchoredByRole` in the EXTENDED-POINTER family (the residual hole closed by binding.role
// re-anchoring). Self-validates the pointer arm.
// =================================================================================================
function buildPointer(anchorRole: BundleBindingRole, faulted: string, jobId: string, nonce: number, flipAnchoredByRoleTo?: BundleBindingRole): {
  pointer: Json; dereferenced: Json; binding: Json;
} {
  const { bundle: deref, contentHash } = buildBundle({
    kind: 'fab', jobId, outcome: 'aborted-by-other', faultedParty: faulted, anchoredByRole: anchorRole, nonce,
  });
  // The binding is anchored coherently at anchorRole (role bound to logicalAddress).
  const native = nativeFor(`ptr-${jobId}`);
  const binding = buildBinding(anchorRole, jobId, native, contentHash);
  const pointer: Json = {
    faultBundleVersion: '1',
    pointerKind: 'extended',
    fullBundleUrl: `https://cdn.example/${jobId}`,
    fullBundleContentHash: contentHash,
  };
  pointer.signature = {
    algorithm: 'ed25519',
    signer: did('seller'),
    value: signDomainHash(POINTER_DOMAIN, hashCanonical(pointer), 'seller'),
  };
  // ADVERSARIAL: flip the UNSIGNED anchoredByRole after signing (signature stays valid).
  if (flipAnchoredByRoleTo) deref.anchoredByRole = flipAnchoredByRoleTo;
  return { pointer, dereferenced: deref, binding };
}
{
  // PRISTINE (pointer): faulted !== anchorRole -> permissible -> present (triple-identity holds).
  const p = buildPointer('buyer', 'seller', 'ABR-PTR-1', 10);
  vectors.push({
    name: 'anchoredByRole-pointer-pristine-permissible',
    family: 'pointer', field: 'anchoredByRole', triple: 'pristine', expected: 'present', reachable: true,
    pointer: p.pointer, dereferenced: p.dereferenced, binding: p.binding,
    provenance: {
      rule: '§10.4.2 extended-pointer triple-identity + §10.4.1 permissible set',
      why: 'aborted-by-other with faulted(seller) != anchoredByRole(buyer) is permissible; binding.role==buyer re-anchors the unsigned field coherently -> present.',
    },
  });

  // MUTATED (pointer): base FAB impermissible under its TRUE role (faulted===anchor), then flip the
  //   unsigned anchoredByRole away so faultedPartyPermitted would wrongly pass. binding.role stays at
  //   the true anchor. SAFE = fail (anchoredByRole != binding.role -> fail-closed).
  const pm = buildPointer('buyer', 'buyer', 'ABR-PTR-2', 11, 'seller');
  vectors.push({
    name: 'anchoredByRole-pointer-mutated-launder-attempt',
    family: 'pointer', field: 'anchoredByRole', triple: 'mutated', expected: 'fail', reachable: true,
    pointer: pm.pointer, dereferenced: pm.dereferenced, binding: pm.binding,
    provenance: {
      rule: '§10.4.2/§248 anchor-address ↔ anchoredByRole integrity (pointer arm)',
      mutation: 'dereferenced.anchoredByRole buyer->seller AFTER signing; binding.role stays buyer. The FAB is impermissible under its TRUE role (aborted-by-other, faulted=buyer=anchor).',
      why: 'SAFE disposition is fail: the pointer family re-anchors the unsigned field to the SIGNED/derived binding.role; a flip away from it is rejected.',
    },
  });

  // CONTROL (pointer): a genuine impermissible FAB (faulted===anchor, NO flip) -> fail on its own
  //   merit (permissible-set violation). Proves the resolver rejects a truly-impermissible copy even
  //   without any laundering — the mutated case's fail is not just "any pointer with these roles fails".
  const pc = buildPointer('buyer', 'buyer', 'ABR-PTR-3', 12);
  vectors.push({
    name: 'anchoredByRole-pointer-control-genuine-impermissible',
    family: 'pointer', field: 'anchoredByRole', triple: 'control', expected: 'fail', reachable: true,
    pointer: pc.pointer, dereferenced: pc.dereferenced, binding: pc.binding,
    provenance: {
      rule: '§10.4.1 permissible set',
      why: 'aborted-by-other with faulted(buyer)==anchoredByRole(buyer) is impermissible on its own merit -> fail. No unsigned-field tamper involved; the control shows the resolver rejects genuine impermissibility (so the mutated fail is meaningful).',
    },
  });
}

// =================================================================================================
// CLASS B — BOOLEAN-FOR-INT (loose type). xm33's `bundleCount` shape: a `bool` where an `int` is
// required. The resolution-relevant int field reachable in OUR resolver is `request.budget` (the
// per-signer fetch cap, §10.4.2 N). The resolver guards it with `Number.isInteger(budget)`, so a bool
// falls back to the default N=8 (fail-SAFE): a bool must NOT be silently coerced to 0/1 and change
// the exhaustion decision. This is the DIRECT BB path.
// Setup: TWO byte-distinct copies at the same signer bucket. With budget=1 the bucket exceeds the cap
// -> indeterminate (exhausted). With budget>=2 the two distinct copies are equal-standing -> also
// indeterminate but via a DIFFERENT branch. We pin on the SAFE disposition (never present).
// =================================================================================================
function buildTwoCopyDirect(jobId: string, budget: unknown): Json {
  const role: BundleBindingRole = 'seller';
  const bindings: Json[] = [];
  const anchored: Json = {};
  for (let i = 0; i < 2; i++) {
    const { bundle, contentHash } = buildBundle({ kind: 'fab', jobId, outcome: 'completed', faultedParty: 'none', anchoredByRole: role, nonce: 100 + i });
    const native = nativeFor(`${jobId}-${i}`);
    bindings.push(buildBinding(role, jobId, native, contentHash));
    anchored[native] = bundle;
  }
  return { request: { jobId, role }, bindings, anchored, budget };
}
{
  // PRISTINE (direct): budget = 1 (correct int). Two distinct copies at one bucket exceed N=1 ->
  //   indeterminate (fetch budget exhausted). The SAFE non-present disposition.
  const b1 = buildTwoCopyDirect('BUD-1', 1);
  vectors.push({
    name: 'budget-int-pristine-exhausted',
    family: 'direct', field: 'budget', triple: 'pristine', expected: 'indeterminate', reachable: true,
    request: b1.request, bindings: b1.bindings, anchored: b1.anchored, budget: b1.budget,
    provenance: {
      rule: '§10.4.2 per-signer fetch budget N',
      typeRule: 'budget is an integer cap; Number.isInteger(budget) gates it.',
      why: 'budget=1 (int) with two byte-distinct copies at one signer bucket exhausts N=1 -> indeterminate. The resolver refuses to pick (safe).',
    },
  });

  // MUTATED (direct): budget = true (BOOL where an int is required). If the resolver coerced true->1
  //   it would keep the N=1 exhaustion; if it coerced to something else it might change the branch. Our
  //   resolver's Number.isInteger(true)===false -> falls back to DEFAULT N=8. Either way the SAFE
  //   disposition is non-present: the two distinct copies are then equal-standing -> indeterminate.
  //   THE POINT (xm33): a bool must not silently act as an int (0==false / truthy==1) and flip a
  //   decision. Expected SAFE = indeterminate (never present).
  const bmut = buildTwoCopyDirect('BUD-1', true);
  vectors.push({
    name: 'budget-bool-mutated-launder-attempt',
    family: 'direct', field: 'budget', triple: 'mutated', expected: 'indeterminate', reachable: true,
    request: bmut.request, bindings: bmut.bindings, anchored: bmut.anchored, budget: bmut.budget,
    provenance: {
      rule: '§10.4.2 per-signer fetch budget N — boolean-for-int coverage (xm33 bundleCount shape)',
      mutation: 'budget: 1 (int) -> true (bool). A naive `x == 0` / truthy check would confuse a bool for an int (0==false in JS).',
      typeRule: 'Number.isInteger(true) === false -> the resolver rejects the bool and falls back to the normative default N=8; it never treats the bool as the integer 1.',
      why: 'SAFE disposition is indeterminate: the bool must not launder the exhaustion decision into a present. Two byte-distinct equal-standing copies still resolve indeterminate under the default budget.',
    },
  });

  // CONTROL (direct): budget = 8 (a genuine, larger int) with a SINGLE copy -> present. Proves the
  //   budget field legitimately governs resolution: a real int with a resolvable single copy passes,
  //   so the mutated/pristine indeterminate is not "this shape always fails".
  const bctl = buildTwoCopyDirect('BUD-2', 8);
  // reduce to a single binding/copy so it resolves cleanly present
  const oneNative = bctl.bindings[0].nativeAddress;
  const singleAnchored: Json = { [oneNative]: bctl.anchored[oneNative] };
  vectors.push({
    name: 'budget-int-control-single-copy-present',
    family: 'direct', field: 'budget', triple: 'control', expected: 'present', reachable: true,
    request: bctl.request, bindings: [bctl.bindings[0]], anchored: singleAnchored, budget: 8,
    provenance: {
      rule: '§10.4.2 fetch budget with a single resolvable copy',
      why: 'budget=8 (int) with one authenticated, authorized, byte-exact copy resolves present. The non-tautology control: a genuine int budget governs resolution and passes when the copy is resolvable.',
    },
  });
}

// =================================================================================================
// CLASS C — CONTAINER-FOR-SCALAR (loose type). RB's `windowingBasis` shape: an array/object where a
// scalar is expected takes the wrong branch. The reachable field in OUR resolver is
// `phaseSummary[].index` (§254 shared-index limb). phaseSummaryDiverges keys a Map by p.index; if
// index is an ARRAY/OBJECT, Map key comparison is by reference, so two copies' `[0]` indices never
// match and a genuine phase divergence at that index is NEVER DETECTED -> laundered to present.
//
// index is INSIDE the signed scope, so a container index does NOT preserve a pre-existing signature;
// but a malicious SIGNER can construct copies with container indices to evade the cross-copy #254
// check. This is the loosely-typed-member arm of the class (type confusion, not scope exclusion).
//
// IMPORTANT / HONEST: at the time of writing, OUR resolver DIVERGES on the mutated case (it returns
// present where the SAFE disposition is fail) UNLESS the phaseSummaryDiverges index is normalised to a
// canonical key. The generator emits the vector with the SAFE expected disposition (fail); the sibling
// runner reports the AGREE/DIVERGE honestly. A companion resolver hardening (canonical index key)
// closes the gap; the mutation-pin test reverts it to prove teeth.
// =================================================================================================
{
  // PRISTINE (mixed): FAB(seller) faulted=seller {seller} + legacy(buyer) aborted-by-other @buyer
  //   implied {seller,orchestrator} -> intersect {seller}; BUT the shared-index-0 phaseSummary limb
  //   DIVERGES (ok vs fail). With a SCALAR index the #254 check fires -> fail (correct).
  const fabC = buildBundle({ kind: 'fab', jobId: 'IDX-1', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller', nonce: 200, phaseIndex: 0, phaseOutcome: 'ok' });
  const legC = buildBundle({ kind: 'legacy', jobId: 'IDX-1', outcome: 'aborted-by-other', anchoredByRole: 'buyer', nonce: 201, phaseIndex: 0, phaseOutcome: 'fail' });
  vectors.push({
    name: 'phaseIndex-scalar-pristine-divergence-detected',
    family: 'mixed', field: 'phaseSummary[].index', triple: 'pristine', expected: 'fail', reachable: true,
    copies: { seller: fabC.bundle, buyer: legC.bundle },
    provenance: {
      rule: '§254 shared-index phaseSummary limb',
      typeRule: 'index is a scalar; phaseSummaryDiverges keys a Map by it and the shared index 0 is compared across copies.',
      why: 'Same absolute fault {seller}, same outcome class, BUT phase outcome differs at shared index 0 (ok vs fail) -> #254 divergence -> fail. Scalar index makes the cross-copy check work.',
    },
  });

  // MUTATED (mixed): the SAME divergent-phase pair but with index = [0] (a CONTAINER where a scalar is
  //   expected). Both copies are freshly, genuinely signed WITH index:[0] (signatures valid). The Map
  //   keyed by an array uses reference identity -> the two [0] indices never match -> the #254
  //   divergence is NOT detected -> the pair wrongly converges. SAFE disposition = fail (the phase
  //   divergence is real and must still be caught). This is the container-type laundering.
  const fabCm = buildBundle({ kind: 'fab', jobId: 'IDX-2', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller', nonce: 202, phaseIndex: [0], phaseOutcome: 'ok' });
  const legCm = buildBundle({ kind: 'legacy', jobId: 'IDX-2', outcome: 'aborted-by-other', anchoredByRole: 'buyer', nonce: 203, phaseIndex: [0], phaseOutcome: 'fail' });
  vectors.push({
    name: 'phaseIndex-container-mutated-launder-attempt',
    family: 'mixed', field: 'phaseSummary[].index', triple: 'mutated', expected: 'fail', reachable: true,
    copies: { seller: fabCm.bundle, buyer: legCm.bundle },
    provenance: {
      rule: '§254 shared-index limb — container-for-scalar coverage (RB windowingBasis shape)',
      mutation: 'phaseSummary[0].index: 0 (scalar) -> [0] (array). Both copies re-signed WITH the container index, so signatures are valid — this is a loosely-typed-member type-confusion, not a scope-exclusion flip.',
      typeRule: 'A Map keyed by an ARRAY compares keys by reference; two distinct [0] arrays never collide, so the shared-index cross-copy check is silently skipped.',
      why: 'SAFE disposition is fail: a real phase divergence at index 0 must still be detected. Resolver hardening normalises the index to a canonical key so container indices cannot evade #254.',
    },
  });

  // CONTROL (mixed): a genuinely NON-divergent pair with SCALAR index (phase outcomes AGREE) -> present.
  //   Proves the #254 check does not reject an honest agreeing pair, so the pristine/mutated fail is a
  //   real divergence signal, not "any phaseSummary pair fails".
  const fabCc = buildBundle({ kind: 'fab', jobId: 'IDX-3', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller', nonce: 204, phaseIndex: 0, phaseOutcome: 'fail' });
  const legCc = buildBundle({ kind: 'legacy', jobId: 'IDX-3', outcome: 'aborted-by-other', anchoredByRole: 'buyer', nonce: 205, phaseIndex: 0, phaseOutcome: 'fail' });
  vectors.push({
    name: 'phaseIndex-scalar-control-genuine-agreement',
    family: 'mixed', field: 'phaseSummary[].index', triple: 'control', expected: 'present', reachable: true,
    copies: { seller: fabCc.bundle, buyer: legCc.bundle },
    provenance: {
      rule: '§10.4.3 mixed-version convergence with agreeing phaseSummary',
      why: 'Same fault {seller}, same class, AND the shared-index-0 phase outcomes AGREE (fail/fail) -> present. Non-tautology control: the #254 check passes an honest agreeing pair.',
    },
  });
}

// =================================================================================================
// CLASS D — ASPIRATIONAL / REFERENCE-ONLY. Fields that belong to the class in the DACS-Standard but
// are NOT independently reachable as a decision swing in OUR current resolver. Shipped as documented
// reference vectors (reachable:false) rather than fabricating a passing case. The sibling runner does
// NOT assert AGREE on these — they are coverage sign-posts for other implementations.
// =================================================================================================
{
  // `bundleCount` — xm33's exact field. Our resolver has no bundleCount field on the resolution path
  //   (it counts copies structurally via array length, which is int-typed and not caller-supplied), so
  //   there is no place a bool bundleCount could swing OUR verdict. Documented as reference-only.
  vectors.push({
    name: 'bundleCount-bool-reference-only',
    family: 'direct', field: 'bundleCount', triple: 'mutated', expected: 'indeterminate', reachable: false,
    request: { jobId: 'REF-BC', role: 'seller', bundleCount: true }, bindings: [], anchored: {}, budget: undefined,
    provenance: {
      rule: 'ASPIRATIONAL — xm33 bundleCount boolean coverage gap',
      status: 'reference-only',
      why: 'OUR resolver derives copy counts structurally (array length), not from a caller-supplied bundleCount field, so a bool bundleCount has no decision to swing here. This vector documents the class member for implementations (e.g. dacs-verify) that DO read a bundleCount int; they should reject a bool. Not asserted AGREE against our resolver.',
    },
  });

  // `windowingBasis` — RB's exact field. Not present in our §10.4 resolution surface. Documented so the
  //   container-for-scalar class is named against the DACS-Standard field even though we exercise it via
  //   phaseSummary[].index instead.
  vectors.push({
    name: 'windowingBasis-container-reference-only',
    family: 'direct', field: 'windowingBasis', triple: 'mutated', expected: 'fail', reachable: false,
    request: { jobId: 'REF-WB', role: 'seller', windowingBasis: [] }, bindings: [], anchored: {}, budget: undefined,
    provenance: {
      rule: 'ASPIRATIONAL — RB windowingBasis container-type defect',
      status: 'reference-only',
      why: 'windowingBasis is a DACS-Standard reputation-windowing field not present in our §10.4 BundleBinding resolver. We exercise the SAME container-for-scalar class via phaseSummary[].index (reachable). This vector names the canonical field for implementations that carry it; they should reject an array/object where a scalar is required. Not asserted AGREE against our resolver.',
    },
  });
}

// -------------------------------------------------------------------------------------------------
// assemble + emit
// -------------------------------------------------------------------------------------------------
function build(): Json {
  assertGenuineKeys();
  const setHash = hex(sha256(jcsCanonical(vectors)));
  return {
    set: SET,
    spec: 'DACS-5 §10.4 unsigned-field / loosely-typed member laundering defect class',
    provenance: {
      generator: 'conformance/cross-run-corpus/gen-unsigned-field-vectors.mts (deterministic; --check is a byte-for-byte determinism proof)',
      class: 'A receipt/bundle member a resolution decision depends on is either OUTSIDE the signed hash scope, or too LOOSELY TYPED, so a mutation that keeps the signature valid (or confuses the type) changes the verdict.',
      instances: [
        'anchoredByRole (#248): unsigned field, flip re-attributes fault authority -> re-anchored to the copies-map key / binding.role.',
        'budget/bundleCount (xm33): boolean-for-int, Number.isInteger gate rejects the bool -> fail-safe default.',
        'phaseSummary[].index / windowingBasis (RB): container-for-scalar, Map-key-by-reference silently skips the cross-copy check -> canonical-key normalisation.',
      ],
      tripleStructure: 'Each field ships PRISTINE (correct, correct disposition), MUTATED (signature-valid/type-confused laundering attempt, SAFE disposition, never present when pristine was fail/indeterminate), CONTROL (a legitimate change that SHOULD move the disposition — proves non-tautology).',
      canonicalisation: 'RFC 8785 JCS over the artifact minus its hash-excluded fields (FAB/legacy: signatures + anchoredByRole; binding: signature); sha256 hex content hashes; ed25519 over the CORE §B.7 domain-separated payload (dacs-fault-bundle:v1: / dacs-bundle:v1: / dacs-bundle-binding:v1: / dacs-fault-bundle-pointer:v1: || hex(hash)), base64url-unpadded.',
      seeds: 'published deterministic repeated-byte ed25519 seeds; buyer a1.., seller c3.., orchestrator 0e.. (asserted to reproduce the published pubkeys).',
      reachabilityNote: 'reachable:true vectors are asserted AGREE against OUR resolver; reachable:false vectors are aspirational/reference-only (the field is a DACS-Standard class member not independently reachable as a decision swing in our current resolver) and are documented, not asserted.',
    },
    gaps: [
      '#248 unsigned anchoredByRole fault-authority laundering',
      'xm33 bundleCount boolean-for-int coverage',
      'RB windowingBasis container-for-scalar type confusion',
    ],
    classDefinition: 'unsigned-field / loosely-typed member laundering: a decision-relevant member outside the signed scope or too loosely typed, mutable without breaking the signature, swings a resolution/reputation verdict.',
    publicKeys: publicKeys(),
    seeds: SEEDS,
    hash: setHash,
    count: vectors.length,
    vectors,
  };
}

function main(): void {
  const check = process.argv.includes('--check') || process.argv.includes('--check-reproducible');
  const generated = build();
  const serialized = JSON.stringify(generated, null, 2) + '\n';
  if (check) {
    let onDisk: string;
    try {
      onDisk = readFileSync(OUT, 'utf8');
    } catch {
      console.error(`--check: ${OUT} does not exist yet. Run the generator without --check first.`);
      process.exit(1);
    }
    if (onDisk !== serialized) {
      console.error(`--check FAILED: on-disk ${SET} differs from a fresh regeneration (non-deterministic or stale).`);
      process.exit(1);
    }
    console.log(`--check OK: ${SET} is byte-for-byte reproducible (${generated.count} vectors, hash ${generated.hash}).`);
    return;
  }
  writeFileSync(OUT, serialized);
  console.log(`Wrote ${OUT}`);
  console.log(`  ${generated.count} vectors, set hash ${generated.hash}`);
  const byField = new Map<string, number>();
  for (const v of vectors) byField.set(v.field, (byField.get(v.field) ?? 0) + 1);
  for (const [field, n] of byField) console.log(`  ${field.padEnd(24)} ${n} vectors`);
  const aspirational = vectors.filter((v) => !v.reachable).map((v) => v.name);
  console.log(`  reference-only (aspirational): ${aspirational.length ? aspirational.join(', ') : 'none'}`);
}

main();
