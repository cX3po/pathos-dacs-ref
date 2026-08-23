#!/usr/bin/env tsx
/**
 * STATEFUL / HISTORY model-based fuzzer for DACS-5 §10.4.2 BundleBinding resolution.
 *
 * WHY THIS EXISTS (and how it differs from bb-differential-fuzzer.mts)
 * -------------------------------------------------------------------
 * The existing property fuzzer (bb-differential-fuzzer.mts) is INPUT-shaped: it generates a
 * single malformed/rich input and asserts invariants on ONE resolution. But the deepest DACS
 * defects are HISTORIES — SEQUENCES of operations — not single inputs:
 *
 *   - the `anchoredByRole` laundering we fixed (#248) is a history: sign a bundle → alter the
 *     UNSIGNED anchoredByRole field → resolve. The signature still verifies (anchoredByRole is
 *     outside bundleScope), yet a fail-becomes-present unless the resolver re-anchors the unsigned
 *     field to a trusted signal;
 *   - the perspective-flip fault swap is a history: re-anchor a copy from another party's storage
 *     address and see whether the absolute faultedParty attribution moves;
 *   - mixed-version reconciliation is a history: migrate a legacy AttestationBundle ↔
 *     FaultAttestationBundle and reconcile the pair.
 *
 * @mj-deving (Marius) made this point about autoreview tooling; it's just as true of resolver
 * testing. A stateful fuzzer that generates randomized OPERATION SEQUENCES and asserts invariants
 * ACROSS THE WHOLE HISTORY catches the CLASS, not one instance.
 *
 * STATE MODEL
 * -----------
 * We model the bundle/binding lifecycle as a small per-copy state machine:
 *
 *   constructed → signed → anchored/persisted → (adversarial transitions) → resolved
 *
 * A `World` holds a roster of parties (keys derived from the case-seed so every history is fully
 * reproducible) and a list of `Copy` records. Each Copy tracks:
 *   - `signedScope`  : the JCS-canonical bytes that were actually SIGNED (frozen at sign time);
 *   - `bundle`       : the live JSON object as it sits at its anchor (may drift from signedScope
 *                       if an UNSIGNED field was altered post-signing);
 *   - `anchorRole`   : the role whose native storage address this copy is anchored at (the trusted
 *                       signal the resolver re-anchors unsigned fields to);
 *   - `nativeAddress`: the native storage address;
 *   - `sessionKey`   : the (jobId, role) this copy's binding was signed for (for replay probes);
 *   - `state`        : the lifecycle state (constructed | signed | anchored | tampered | ...).
 *
 * TRANSITION ALPHABET (legitimate + adversarial)
 * ----------------------------------------------
 *   SIGN            — sign a copy with real Ed25519 over the JCS canonical signed scope.
 *   ANCHOR          — persist/anchor a signed copy at a role's native address.
 *   ALTER_UNSIGNED  — flip anchoredByRole (or another unsigned field) AFTER signing; the signature
 *                     stays valid (anchoredByRole is excluded from bundleScope). THE laundering step.
 *   PERSPECTIVE_FLIP— re-anchor a copy under another party's role address (anchor key changes,
 *                     content unchanged) — perspective flip.
 *   REPLAY          — take a binding signed for (jobId, role=X) and resolve it against a request
 *                     for a different session/job/phase than it was bound to.
 *   RESTART         — re-resolve the SAME state (idempotence / determinism probe), possibly with
 *                     the copy list reordered (order-independence).
 *   VERSION_MIGRATE — migrate legacy AttestationBundle ↔ FaultAttestationBundle, forming a mixed
 *                     pair for resolveMixedVersionPair.
 *   DUPLICATE       — introduce a duplicate or byte-divergent copy at a fresh address.
 *
 * INVARIANTS ASSERTED ACROSS THE SEQUENCE (not per-input)
 * -------------------------------------------------------
 *   no-launder            no ALTER_UNSIGNED of an unsigned field may turn a fail/indeterminate
 *                         disposition into present (the anchoredByRole class — reproduces the known
 *                         defect if the anchorRoleMismatch guard is reverted).
 *   perspective-invariance a PERSPECTIVE_FLIP (re-anchor under another perspective) must not change
 *                         the absolute faultedParty attribution / must be rejected.
 *   replay-rejection      a copy replayed into a (jobId, role) it was not signed for is rejected
 *                         (never resolves present against the wrong session).
 *   determinism-under-restart the same state re-resolved yields the same disposition +
 *                         resolvedNativeAddress, order-independently.
 *   fail-closed           any malformed/incomplete transition yields a deterministic disposition,
 *                         never a throw/hang.
 *   monotonic-standing    a full-standing (fully-signed) copy is never overridden by a
 *                         lesser-signed one regardless of operation order.
 *   equal-standing-divergence  THREE (>2) equal-standing copies at one side with distinct content
 *                         must fail-closed to indeterminate — the resolver never arbitrarily elects one.
 *   budget-exhaustion     >N same-signer copies under request.budget=N exhaust the per-signer fetch
 *                         cap and must fail-closed to indeterminate (never skip validation → present).
 *   multi-index-phase     the #254 shared-index divergence check catches a disagreement at a NON-ZERO
 *                         phaseSummary index (not just index 0); an all-agree pair stays present.
 *
 * RUN + REPLAY
 * ------------
 *   npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts                 # 500 histories, len<=8
 *   npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts --cases 2000 --seed 42 --history-len 12
 *   npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts --case-seed 123456   # replay ONE history
 *   npm run fuzz:bb-stateful
 *
 * On any invariant violation the minimal reproducing SEQUENCE (the ordered operations) is printed
 * with a --case-seed replay command, and the process exits non-zero (CI-gateable). The signing path
 * is self-tested first so a broken oracle can't report a vacuous green.
 */
import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../../src/jcs.js';
import {
  deriveBundleLogicalAddress,
  resolveBundleBinding,
  resolveFaultBundlePair,
  resolveMixedVersionPair,
  resolveFaultBundlePointer,
  type BundleBindingRequest,
  type BundleBindingResolution,
  type BundleBindingRole,
  type BundleBindingV1,
} from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

const enc = new TextEncoder();
const BINDING_DOMAIN = 'dacs-bundle-binding:v1:';
const FAULT_DOMAIN = 'dacs-fault-bundle:v1:';
const LEGACY_DOMAIN = 'dacs-bundle:v1:';
const POINTER_DOMAIN = 'dacs-fault-bundle-pointer:v1:';
const ROLES: BundleBindingRole[] = ['buyer', 'seller', 'orchestrator'];

// The published deterministic seeds (dacs248 corpus). Using them keeps histories tied to the same
// key material the pinned vectors use, so a stateful history is a superset of the fixture corners.
const PUBLISHED_SEEDS: Record<BundleBindingRole, string> = {
  buyer: 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
  seller: 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3',
  orchestrator: '0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e',
};

// --------------------------------------------------------------------------------------------
// primitives (shared shape with bb-differential-fuzzer.mts)
// --------------------------------------------------------------------------------------------
type Json = Record<string, any>;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('');
}
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function hashCanonical(value: unknown): Uint8Array {
  return sha256(jcsCanonical(value));
}
/** Sign `domain || hex(hash)` — the exact message the resolver's verifyHashedDomain reconstructs. */
function signDomainHash(domain: string, hash: Uint8Array, priv: Uint8Array): string {
  const hashText = enc.encode(hex(hash));
  const domainBytes = enc.encode(domain);
  const msg = new Uint8Array(domainBytes.length + hashText.length);
  msg.set(domainBytes);
  msg.set(hashText, domainBytes.length);
  return b64url(ed25519.sign(msg, priv));
}
/** §10.4.1 scope hash: JCS over the bundle WITHOUT signatures AND WITHOUT anchoredByRole (bundleScope). */
function bundleScopeHash(bundle: Json): Uint8Array {
  const { signatures: _s, anchoredByRole: _a, ...signed } = bundle;
  return sha256(jcsCanonical(signed));
}

// --------------------------------------------------------------------------------------------
// seeded PRNG (mulberry32) — same generator as the input-shaped fuzzer, self-contained.
// --------------------------------------------------------------------------------------------
type Rng = {
  next(): number;
  int(nExclusive: number): number;
  pick<T>(arr: readonly T[]): T;
  chance(p: number): boolean;
  bytes(n: number): Uint8Array;
};
function makeRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (n) => Math.floor(next() * Math.max(1, n)),
    pick: (arr) => arr[Math.floor(next() * arr.length)]!,
    chance: (p) => next() < p,
    bytes: (n) => {
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) out[i] = Math.floor(next() * 256);
      return out;
    },
  };
}

// --------------------------------------------------------------------------------------------
// party roster — keys derived from the published seeds so histories share the corpus key material
// (falls back to rng-derived keys for extra parties). Fully reproducible from the case-seed.
// --------------------------------------------------------------------------------------------
type Party = { did: string; role: BundleBindingRole; priv: Uint8Array; pub: Uint8Array };

function makeRoster(): Record<BundleBindingRole, Party> {
  const roster = {} as Record<BundleBindingRole, Party>;
  for (const role of ROLES) {
    const priv = Uint8Array.from(Buffer.from(PUBLISHED_SEEDS[role], 'hex'));
    roster[role] = { did: `did:demos:${role}`, role, priv, pub: ed25519.getPublicKey(priv) };
  }
  return roster;
}
function collectKeys(roster: Record<BundleBindingRole, Party>): Record<string, string> {
  const map: Record<string, string> = {};
  for (const role of ROLES) map[roster[role].did] = b64url(roster[role].pub);
  return map;
}

function nativeAddr(rng: Rng): string {
  return `stor-${hex(rng.bytes(20))}`;
}

// --------------------------------------------------------------------------------------------
// the world state and the copy lifecycle
// --------------------------------------------------------------------------------------------
type CopyState = 'constructed' | 'signed' | 'anchored' | 'tampered' | 'flipped' | 'migrated' | 'replayed';
type CopyKind = 'fab' | 'legacy';

type Copy = {
  id: number;
  kind: CopyKind;
  bundle: Json;              // live JSON at the anchor (may drift from signedScope on ALTER_UNSIGNED)
  signedScopeHex: string;    // hex(bundleScopeHash) frozen at sign time
  anchorRole: BundleBindingRole; // role whose storage address this is anchored at (trusted signal)
  trueAnchoredByRole: BundleBindingRole; // the anchoredByRole value at sign time (before any tamper)
  nativeAddress: string;
  boundJobId: string;        // (jobId, role) the binding was SIGNED for
  boundRole: BundleBindingRole;
  binding: BundleBindingV1;  // the binding anchoring this copy
  state: CopyState;
  signed: boolean;           // is the bundle fully signed by the roster?
  fullySigned: boolean;      // were ALL roster roles' signatures present at sign time?
};

type World = {
  jobId: string;
  roster: Record<BundleBindingRole, Party>;
  publicKeys: Record<string, string>;
  copies: Copy[];
  nextId: number;
};

// An Operation is a recorded transition (for minimal-repro reporting).
type Op = { t: string; detail: string };

// --------------------------------------------------------------------------------------------
// builders — produce genuinely valid signed bundles + bindings for a copy
// --------------------------------------------------------------------------------------------
type BundleFacts = {
  kind: CopyKind;
  outcome: string;
  faultedParty: string;
  anchoredByRole: BundleBindingRole;
  nonce: number;
  fullySigned: boolean;   // sign with every roster role vs a single signer
  role: BundleBindingRole; // the requested side / anchor role
  phases?: Array<{ index: unknown; kind: string; outcome: string }>; // override the single index-0 phaseSummary
};

function buildSignedBundle(world: World, facts: BundleFacts): { bundle: Json; contentHash: string; fullySigned: boolean } {
  const { roster, jobId } = world;
  const parties = ROLES.map((r) => ({
    role: r,
    primaryClaim: roster[r].did,
    bundleHash: hex(sha256(enc.encode(`${jobId}-${r}-${facts.nonce}`))),
  }));
  // #254 phaseSummary limb must AGREE across shared indices for a non-divergent pair. Drive the
  // phase outcome off the OUTCOME (not faultedParty): a no-fault outcome (completed) is 'ok', any
  // fault/abort outcome is 'fail'. This keeps a FAB and its legacy mirror (same outcome class) on
  // the same shared-index phase outcome, so a coherently-constructed mixed pair does not trip the
  // #254 divergence check for a reason unrelated to the property under test.
  const phaseOutcome = facts.outcome === 'completed' || facts.outcome === 'failed-substrate' ? 'ok' : 'fail';
  const bundle: Json = {
    jobId,
    outcome: facts.outcome,
    faultedParty: facts.faultedParty,
    anchoredByRole: facts.anchoredByRole, // EXCLUDED from signed scope
    parties,
    // Default: a single index-0 phase. Multi-index histories override facts.phases to drive the #254
    // shared-index divergence check at indices beyond 0 (phaseSummary IS in signed scope, so the
    // whole array is bound — this exercises value-correct divergence detection, not laundering).
    phaseSummary: facts.phases ?? [{ index: 0, kind: 'deliver-storage-program', outcome: phaseOutcome }],
    finalisedAt: 1780000000000 + facts.nonce,
    nonce: facts.nonce,
  };
  if (facts.kind === 'fab') bundle.faultBundleVersion = '1';
  else delete bundle.faultedParty; // legacy AttestationBundle has no explicit faultedParty

  const scopeHash = bundleScopeHash(bundle);
  const domain = facts.kind === 'fab' ? FAULT_DOMAIN : LEGACY_DOMAIN;
  // Aborts only need the self-signer for BB validity; otherwise fully-signed vs single-signed.
  const signerRoles: BundleBindingRole[] = facts.fullySigned ? ROLES : [facts.role];
  bundle.signatures = signerRoles.map((r) => ({
    party: roster[r].did,
    algorithm: 'ed25519',
    value: signDomainHash(domain, scopeHash, roster[r].priv),
  }));
  return { bundle, contentHash: hex(scopeHash), fullySigned: facts.fullySigned };
}

function buildBinding(world: World, role: BundleBindingRole, nativeAddress: string, contentHash: string): BundleBindingV1 {
  const signer = world.roster[role];
  const tuple: Json = {
    bindingVersion: '1',
    jobId: world.jobId,
    role,
    logicalAddress: deriveBundleLogicalAddress(world.jobId, role),
    nativeAddress,
    bundleContentHash: contentHash,
    anchorTx: `demos-testnet:tx-${nativeAddress.slice(5, 21)}`,
    signer: signer.did,
  };
  const value = signDomainHash(BINDING_DOMAIN, hashCanonical(tuple), signer.priv);
  return { ...tuple, signature: { algorithm: 'ed25519', signer: signer.did, value } } as BundleBindingV1;
}

/**
 * SIGN + ANCHOR a fresh copy for `role` at a native address. Because a copy is only useful once
 * signed+anchored, these two lifecycle steps are fused into the constructor; ALTER_UNSIGNED,
 * PERSPECTIVE_FLIP, REPLAY, VERSION_MIGRATE then act on the anchored copy.
 */
function constructCopy(world: World, rng: Rng, facts: BundleFacts): Copy {
  const { bundle, contentHash, fullySigned } = buildSignedBundle(world, facts);
  const native = nativeAddr(rng);
  const binding = buildBinding(world, facts.role, native, contentHash);
  const copy: Copy = {
    id: world.nextId++,
    kind: facts.kind,
    bundle,
    signedScopeHex: contentHash,
    anchorRole: facts.role,           // anchored at the requested role's address by default
    trueAnchoredByRole: facts.anchoredByRole,
    nativeAddress: native,
    boundJobId: world.jobId,
    boundRole: facts.role,
    binding,
    state: 'anchored',
    signed: true,
    fullySigned,
  };
  return copy;
}

// --------------------------------------------------------------------------------------------
// scenario families — each generates a HISTORY (sequence of ops) targeting one invariant class.
// Each returns the World, the request(s) to resolve, an ops log, and an expectation.
// --------------------------------------------------------------------------------------------
type ResolveTarget =
  | { api: 'bb'; request: BundleBindingRequest; role: BundleBindingRole }
  | { api: 'pair'; copies: Record<string, unknown> }
  | { api: 'mixed'; copies: Record<string, unknown> }
  | { api: 'pointer'; pointer: Json; dereferenced: Json; binding: Json };

type History = {
  kind: string;
  world: World;
  ops: Op[];
  target: ResolveTarget;
  // invariant expectation for this history
  invariant: string;
  // for no-launder / replay families: the disposition BEFORE the adversarial step (must not become present)
  preAdversarialFail?: boolean;
  // for present families
  expectPresent?: boolean;
  expectedNative?: string;
  // for equal-standing-divergence / budget-exhaustion: the resolver must fail-closed to indeterminate
  // (stronger than "not present" — a wrong 'fail'/'present' here is also a violation).
  expectIndeterminate?: boolean;
  // pin the resolution to a specific fail-closed PATH by requiring a substring in res.detail (e.g.
  // 'budget'): without it a budget-exhaustion history could pass indeterminate for an unrelated reason.
  expectDetailIncludes?: string;
};

function freshWorld(rng: Rng): World {
  const roster = makeRoster();
  const world: World = {
    jobId: `JOB-${hex(rng.bytes(4))}`,
    roster,
    publicKeys: collectKeys(roster),
    copies: [],
    nextId: 0,
  };
  return world;
}

function fetchOf(world: World) {
  const map = new Map<string, unknown>();
  for (const c of world.copies) map.set(c.nativeAddress, c.bundle);
  return (nativeAddress: string): unknown => map.get(nativeAddress);
}

function resolve(world: World, target: ResolveTarget): BundleBindingResolution {
  switch (target.api) {
    case 'bb':
      return resolveBundleBinding(
        { ...target.request, publicKeys: world.publicKeys },
        world.copies.map((c) => c.binding),
        fetchOf(world),
      );
    case 'pair':
      return resolveFaultBundlePair({ publicKeys: world.publicKeys, copies: target.copies });
    case 'mixed':
      return resolveMixedVersionPair({ publicKeys: world.publicKeys, copies: target.copies });
    case 'pointer':
      return resolveFaultBundlePointer({
        publicKeys: world.publicKeys,
        pointer: target.pointer,
        dereferenced: target.dereferenced,
        binding: target.binding,
      });
  }
}

// ---- FAB pair / mixed helpers --------------------------------------------------------------
/** aborted-by-other with faulted === anchor is IMPERMISSIBLE (a fail base for laundering). */
const OTHER_OUTCOMES = ['aborted-by-other', 'failed-counterparty'] as const;

function otherRole(role: BundleBindingRole, rng: Rng): BundleBindingRole {
  return rng.pick(ROLES.filter((r) => r !== role));
}

// ============================================================================================
// HISTORY GENERATORS
// ============================================================================================

/**
 * no-launder (mixed-version) — build a genuine contradiction pair (fail), then ALTER_UNSIGNED
 * anchoredByRole on one copy to try to launder fail→present. The signature is NOT re-computed.
 */
function histLaunderMixed(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(1_000_000);
  // FAB(seller): aborted-by-other faulted=seller -> singleton {seller}; anchored at seller.
  const fab = constructCopy(world, rng, {
    kind: 'fab', outcome: 'aborted-by-other', faultedParty: 'seller', anchoredByRole: 'seller',
    nonce, fullySigned: true, role: 'seller',
  });
  ops.push({ t: 'SIGN+ANCHOR', detail: 'FAB seller aborted-by-other faulted=seller @seller' });
  // legacy(buyer): aborted-by-self anchoredByRole=buyer -> implied {buyer}; anchored at buyer.
  const legacy = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-self', faultedParty: 'none', anchoredByRole: 'buyer',
    nonce: nonce + 1, fullySigned: true, role: 'buyer',
  });
  ops.push({ t: 'SIGN+ANCHOR', detail: 'legacy buyer aborted-by-self @buyer -> implied {buyer}' });
  world.copies.push(fab, legacy);

  // Pristine contradiction: {seller} ∩ {buyer} = ∅ -> fail.
  const copies: Record<string, unknown> = { seller: fab.bundle, buyer: legacy.bundle };

  // ADVERSARIAL: flip the UNSIGNED anchoredByRole on the legacy copy buyer->seller (no re-sign).
  legacy.bundle.anchoredByRole = 'seller';
  legacy.state = 'tampered';
  ops.push({ t: 'ALTER_UNSIGNED', detail: 'legacy.anchoredByRole buyer->seller (signature untouched; laundering attempt)' });

  return {
    kind: 'launder-mixed', world, ops,
    target: { api: 'mixed', copies },
    invariant: 'no-launder', preAdversarialFail: true,
  };
}

/**
 * no-launder (perspective-pair) — a FAB whose faultedParty is out of the permissible set under its
 * TRUE anchor (fail), then ALTER_UNSIGNED anchoredByRole to try to make it permissible.
 */
function histLaunderPair(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(1_000_000);
  const anchor: BundleBindingRole = rng.pick(['buyer', 'seller']);
  // aborted-by-other with faulted === anchor -> impermissible under true role -> fail.
  const fab = constructCopy(world, rng, {
    kind: 'fab', outcome: rng.pick(OTHER_OUTCOMES), faultedParty: anchor, anchoredByRole: anchor,
    nonce, fullySigned: true, role: anchor,
  });
  ops.push({ t: 'SIGN+ANCHOR', detail: `FAB ${anchor} aborted-by-other faulted=${anchor} @${anchor} (impermissible under true role)` });
  world.copies.push(fab);
  const copies: Record<string, unknown> = { [anchor]: fab.bundle };

  // ADVERSARIAL: flip anchoredByRole to a role != faulted so faultedPartyPermitted would pass.
  const flipped = otherRole(anchor, rng);
  fab.bundle.anchoredByRole = flipped;
  fab.state = 'tampered';
  ops.push({ t: 'ALTER_UNSIGNED', detail: `FAB.anchoredByRole ${anchor}->${flipped} (laundering permissibility)` });

  return {
    kind: 'launder-pair', world, ops,
    target: { api: 'pair', copies },
    invariant: 'no-launder', preAdversarialFail: true,
  };
}

/**
 * no-launder (extended-pointer) — a FAB impermissible under its true role dereferenced through a
 * coherent binding (fail), then ALTER_UNSIGNED anchoredByRole away from binding.role (laundering).
 */
function histLaunderPointer(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(1_000_000);
  const anchor: BundleBindingRole = rng.pick(['buyer', 'seller']);
  const fab = constructCopy(world, rng, {
    kind: 'fab', outcome: 'aborted-by-other', faultedParty: anchor, anchoredByRole: anchor,
    nonce, fullySigned: true, role: anchor,
  });
  ops.push({ t: 'SIGN+ANCHOR', detail: `FAB ${anchor} aborted-by-other faulted=${anchor} @${anchor} (impermissible under true role)` });
  world.copies.push(fab);

  // Build the extended pointer over the dereferenced FAB (triple-identity holds pre-tamper).
  const recomputed = fab.signedScopeHex;
  const pointer: Json = {
    faultBundleVersion: '1',
    pointerKind: 'extended',
    fullBundleContentHash: recomputed,
    jobId: world.jobId,
    nonce,
  };
  const pointerHash = hashCanonical(pointer);
  pointer.signature = {
    algorithm: 'ed25519',
    signer: world.roster[anchor].did,
    value: signDomainHash(POINTER_DOMAIN, pointerHash, world.roster[anchor].priv),
  };
  // The binding anchoring the pointer: role=anchor, logicalAddress derived, hash == recomputed.
  const binding = { ...fab.binding, bundleContentHash: recomputed };
  ops.push({ t: 'BUILD_POINTER', detail: `extended pointer over FAB, binding.role=${anchor}, triple-identity holds` });

  // ADVERSARIAL: flip the dereferenced FAB's anchoredByRole away from binding.role (=anchor).
  const flipped = otherRole(anchor, rng);
  const mutatedDeref = { ...fab.bundle, anchoredByRole: flipped };
  ops.push({ t: 'ALTER_UNSIGNED', detail: `dereferenced.anchoredByRole ${anchor}->${flipped} (laundering; binding.role stays ${anchor})` });

  return {
    kind: 'launder-pointer', world, ops,
    target: { api: 'pointer', pointer, dereferenced: mutatedDeref, binding },
    invariant: 'no-launder', preAdversarialFail: true,
  };
}

/**
 * perspective-invariance — two legacy copies that are the SAME event seen from two perspectives.
 * A genuine perspective pair (aborted-by-self@X mirrored by aborted-by-other faulting X@Y) must
 * reconcile to the SAME absolute fault. A PERSPECTIVE_FLIP that re-anchors one copy under the WRONG
 * party's address must not change the absolute attribution to `present` — it must be rejected.
 */
function histPerspectiveFlip(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(1_000_000);
  // legacy(buyer): aborted-by-self @buyer -> implied {buyer}.
  const a = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-self', faultedParty: 'none', anchoredByRole: 'buyer',
    nonce, fullySigned: true, role: 'buyer',
  });
  // legacy(seller): aborted-by-other @seller -> implied {buyer,orchestrator}\... actually others.
  const b = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-other', faultedParty: 'none', anchoredByRole: 'seller',
    nonce: nonce + 1, fullySigned: true, role: 'seller',
  });
  world.copies.push(a, b);
  ops.push({ t: 'SIGN+ANCHOR', detail: 'legacy buyer aborted-by-self @buyer' });
  ops.push({ t: 'SIGN+ANCHOR', detail: 'legacy seller aborted-by-other @seller' });

  // ADVERSARIAL PERSPECTIVE_FLIP: present copy `a` at the seller's anchor key (re-anchor under
  // another perspective) WITHOUT altering the content. The copies-map key now disagrees with the
  // copy's anchoredByRole (buyer) -> must be rejected, not laundered into agreement.
  const copies: Record<string, unknown> = { seller: a.bundle, buyer: b.bundle };
  ops.push({ t: 'PERSPECTIVE_FLIP', detail: 'anchor copy a(anchoredByRole=buyer) under seller key, copy b under buyer key (perspective swap)' });

  return {
    kind: 'perspective-flip', world, ops,
    target: { api: 'mixed', copies },
    invariant: 'perspective-invariance', preAdversarialFail: true,
  };
}

/**
 * replay-rejection — sign a binding for (jobId, role=X), then REPLAY it against a request for a
 * DIFFERENT session (jobId') / role. The binding's logicalAddress no longer matches the requested
 * side, so the copy must never resolve present for the wrong session.
 */
function histReplay(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(1_000_000);
  const role: BundleBindingRole = rng.pick(['buyer', 'seller']);
  const copy = constructCopy(world, rng, {
    kind: 'fab', outcome: 'completed', faultedParty: 'none', anchoredByRole: role,
    nonce, fullySigned: true, role,
  });
  world.copies.push(copy);
  ops.push({ t: 'SIGN+ANCHOR', detail: `FAB ${role} completed @${role}, binding bound to (jobId=${world.jobId}, role=${role})` });

  // REPLAY: resolve against a DIFFERENT session/role than the binding was signed for.
  const replayKind = rng.int(3);
  let request: BundleBindingRequest;
  let requestRole: BundleBindingRole;
  if (replayKind === 0) {
    // wrong jobId (replay across sessions)
    request = { jobId: `JOB-${hex(rng.bytes(4))}`, role };
    requestRole = role;
    ops.push({ t: 'REPLAY', detail: `resolve request jobId=${request.jobId} (!= bound ${world.jobId}) role=${role}` });
  } else if (replayKind === 1) {
    // wrong role (replay across roles/phase)
    requestRole = otherRole(role, rng);
    request = { jobId: world.jobId, role: requestRole };
    ops.push({ t: 'REPLAY', detail: `resolve request role=${requestRole} (!= bound ${role})` });
  } else {
    // both wrong
    requestRole = otherRole(role, rng);
    request = { jobId: `JOB-${hex(rng.bytes(4))}`, role: requestRole };
    ops.push({ t: 'REPLAY', detail: `resolve request jobId+role both != bound` });
  }
  return {
    kind: 'replay', world, ops,
    target: { api: 'bb', request, role: requestRole },
    invariant: 'replay-rejection', preAdversarialFail: true, // must be non-present (not the bound side)
  };
}

/**
 * monotonic-standing — one fully-signed completed copy and one single-signed divergent copy at the
 * same side. Operation ORDER (which is anchored first, binding order) is randomized. The fully-
 * signed copy must always win / never be overridden by the lesser-signed one.
 */
function histMonotonicStanding(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const role: BundleBindingRole = 'seller';
  const nonce = rng.int(500_000);
  const full = constructCopy(world, rng, {
    kind: 'fab', outcome: 'completed', faultedParty: 'none', anchoredByRole: role,
    nonce, fullySigned: true, role,
  });
  const lesser = constructCopy(world, rng, {
    kind: 'fab', outcome: 'aborted-by-self', faultedParty: role, anchoredByRole: role,
    nonce: nonce + 1 + rng.int(1000), fullySigned: false, role,
  });
  // randomize anchor/binding ORDER
  if (rng.chance(0.5)) world.copies.push(full, lesser);
  else world.copies.push(lesser, full);
  ops.push({ t: 'SIGN+ANCHOR(order-randomized)', detail: `full-signed completed @${role} + single-signed abort @${role}` });

  return {
    kind: 'monotonic-standing', world, ops,
    target: { api: 'bb', request: { jobId: world.jobId, role }, role },
    invariant: 'monotonic-standing',
    expectPresent: true, expectedNative: full.nativeAddress, // the fully-signed copy must win
  };
}

/**
 * version-migrate — a legacy AttestationBundle and a FAB describing the SAME non-divergent event.
 * Migrating legacy↔FAB and reconciling the mixed pair must be present (unified) and stay present
 * under restart/reorder.
 */
function histVersionMigrate(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(500_000);
  // FAB(seller) aborted-by-self faulted=seller -> {seller}; anchored @seller.
  const fab = constructCopy(world, rng, {
    kind: 'fab', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller',
    nonce, fullySigned: true, role: 'seller',
  });
  // legacy(seller) aborted-by-self @seller -> implied {seller}; SAME absolute fault.
  const legacy = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-self', faultedParty: 'none', anchoredByRole: 'seller',
    nonce: nonce + 1, fullySigned: true, role: 'seller',
  });
  world.copies.push(fab, legacy);
  ops.push({ t: 'SIGN+ANCHOR', detail: 'FAB seller aborted-by-self faulted=seller @seller' });
  ops.push({ t: 'VERSION_MIGRATE', detail: 'legacy seller aborted-by-self @seller (implied {seller}) — mixed pair' });

  const copies: Record<string, unknown> = { seller: fab.bundle };
  // legacy copy keyed under its own anchor (seller) too — but the map is role->copy, so put the
  // legacy at a different party role that ALSO implies seller is impossible; instead use buyer key
  // only if anchoredByRole matches. Keep it coherent: legacy anchored @seller — but seller key is
  // taken by the FAB. Anchor the legacy under buyer with anchoredByRole=buyer implying {buyer} would
  // contradict. To keep a clean NON-divergent mixed pair we instead migrate the SAME anchor: put the
  // legacy copy alone in a mixed request is invalid (needs 2). So form the pair FAB@seller +
  // legacy@buyer where legacy is a genuine mirror.
  // Simpler coherent construction: legacy(buyer) aborted-by-other @buyer -> implied {seller,orch};
  // seller ∈ that set -> intersects FAB {seller} -> non-divergent present.
  const legacyMirror = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-other', faultedParty: 'none', anchoredByRole: 'buyer',
    nonce: nonce + 2, fullySigned: true, role: 'buyer',
  });
  world.copies.push(legacyMirror);
  copies.buyer = legacyMirror.bundle;
  ops.push({ t: 'VERSION_MIGRATE', detail: 'legacy buyer aborted-by-other @buyer implied {seller,orchestrator} intersects FAB {seller}' });

  return {
    kind: 'version-migrate', world, ops,
    target: { api: 'mixed', copies },
    invariant: 'determinism-under-restart',
    expectPresent: true,
  };
}

/**
 * malformed-transition (fail-closed) — a valid history whose last op corrupts an unsigned/structural
 * field into garbage. The resolver must return a deterministic disposition, never throw/hang.
 */
function histMalformedTransition(rng: Rng): History {
  const base = rng.pick([histLaunderMixed, histLaunderPair, histMonotonicStanding, histVersionMigrate])(rng);
  const ops = base.ops.slice();
  // Corrupt a field on whatever target this history resolves.
  const garbage = rng.pick([null, undefined, 42, NaN, '', [], {}, { nested: {} }, 'not-a-role', 1.5]);
  const field = rng.pick(['anchoredByRole', 'outcome', 'faultedParty', 'parties', 'signatures', 'jobId', 'nonce']);
  if (base.target.api === 'pair' || base.target.api === 'mixed') {
    const keys = Object.keys(base.target.copies);
    const k = rng.pick(keys);
    const copy = base.target.copies[k];
    if (copy && typeof copy === 'object') (copy as Json)[field] = garbage;
    ops.push({ t: 'CORRUPT', detail: `copies.${k}.${field} := ${JSON.stringify(garbage)}` });
  } else if (base.target.api === 'pointer') {
    (base.target.dereferenced as Json)[field] = garbage;
    ops.push({ t: 'CORRUPT', detail: `dereferenced.${field} := ${JSON.stringify(garbage)}` });
  } else {
    // bb: corrupt a binding
    const b = base.world.copies[0];
    if (b) (b.binding as Json)[field] = garbage;
    ops.push({ t: 'CORRUPT', detail: `binding.${field} := ${JSON.stringify(garbage)}` });
  }
  // NOTE: we deliberately do NOT set preAdversarialFail here. Corrupting an arbitrary field can
  // legitimately leave the disposition unchanged (the resolver may not read that field on this
  // path, or the corruption may be caught into a fail/indeterminate). The property this family
  // actually guards is fail-closed: the resolver must return a DETERMINISTIC disposition and never
  // throw/hang on a malformed transition. That is enforced by the no-throw + determinism +
  // order-independence checks in checkHistory, which apply to every history regardless of flags.
  return {
    kind: 'malformed-transition', world: base.world, ops,
    target: base.target,
    invariant: 'fail-closed',
  };
}

/**
 * equal-standing N-way divergence (>2 copies) — THREE fully-signed copies at the SAME side with
 * DISTINCT content (distinct nonce → distinct canonical scope). No copy dominates (all full-signed),
 * so the resolver sees three equal-standing groups and MUST fail-closed to indeterminate — it may
 * never arbitrarily elect one as present. Extends monotonic-standing (2 copies, one dominant) into
 * the no-dominant N-way case. Order across all three copies is randomized; determinism-under-restart
 * (checkHistory) then asserts the verdict is order-independent across the 3! permutations sampled.
 */
function histThreeWayDivergence(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const role: BundleBindingRole = rng.pick(ROLES);
  const baseNonce = rng.int(400_000);
  // identical (valid) outcome, DISTINCT nonce — three genuinely different attested contents for the
  // same job+side = equivocation. All valid → all reach validCopies → three canonical groups.
  const copies = [0, 1, 2].map((i) => constructCopy(world, rng, {
    kind: 'fab', outcome: 'completed', faultedParty: 'none', anchoredByRole: role,
    nonce: baseNonce + 1 + i, fullySigned: true, role,
  }));
  const order = [0, 1, 2];
  for (let i = order.length - 1; i > 0; i--) { const j = rng.int(i + 1); [order[i], order[j]] = [order[j]!, order[i]!]; }
  for (const idx of order) world.copies.push(copies[idx]!);
  ops.push({ t: 'SIGN+ANCHOR x3', detail: `three full-signed distinct copies @${role} (insertion order ${order.join(',')})` });
  return {
    kind: 'three-way-divergence', world, ops,
    target: { api: 'bb', request: { jobId: world.jobId, role }, role },
    invariant: 'equal-standing-divergence',
    expectIndeterminate: true,
  };
}

/**
 * per-signer budget exhaustion (as a history) — construct N+k copies all signed by the SAME signer at
 * the SAME side, then resolve with request.budget = N. The per-signer fetch bucket overflows, so the
 * resolver MUST fail-closed to indeterminate (BB-7) — it may never skip validation and present, nor
 * throw. Budget exhaustion modeled as an accumulating sequence of SIGN+ANCHOR steps, not a single input.
 *
 * CRITICAL (Codex 2026-07-22): every copy carries IDENTICAL canonical content (same nonce/signed
 * fields), only the native address/binding differs. So the ONLY reason this resolves indeterminate is
 * the per-signer budget cap firing BEFORE canonical grouping. If the copies had distinct content, a
 * removed budget check would still yield indeterminate via equal-standing DIVERGENCE — the test would
 * pass for the wrong reason and could not detect budget enforcement being broken. With identical
 * content, a removed budget check instead collapses all copies into ONE group → present → the test
 * (expectIndeterminate) correctly goes RED. expectDetailIncludes:'budget' pins it to the BB-7 path.
 */
function histBudgetExhaustion(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const role: BundleBindingRole = rng.pick(ROLES);
  const budget = 1 + rng.int(3);               // N in [1,3]
  const copyCount = budget + 1 + rng.int(3);   // strictly exceed the per-signer bucket
  const nonce = rng.int(300_000);              // SAME nonce for all → identical canonical content
  for (let i = 0; i < copyCount; i++) {
    world.copies.push(constructCopy(world, rng, {
      kind: 'fab', outcome: 'completed', faultedParty: 'none', anchoredByRole: role,
      nonce, fullySigned: true, role,
    }));
    ops.push({ t: 'SIGN+ANCHOR', detail: `copy ${i + 1}/${copyCount} @${role} (signer=${role}, identical content)` });
  }
  ops.push({ t: 'RESOLVE(budget)', detail: `request.budget=N=${budget} < ${copyCount} same-signer copies → per-signer fetch budget exhausted` });
  return {
    kind: 'budget-exhaustion', world, ops,
    target: { api: 'bb', request: { jobId: world.jobId, role, budget }, role },
    invariant: 'budget-exhaustion',
    expectIndeterminate: true,
    expectDetailIncludes: 'budget',
  };
}

/**
 * multi-index phaseSummary (#254 beyond index 0) — a coherent, otherwise-PRESENT mixed pair whose two
 * copies share 2..4 phaseSummary indices. In the DIVERGE variant they disagree on the outcome of a
 * NON-ZERO index; the #254 shared-index check must catch it (never present). In the AGREE variant all
 * shared indices match and the pair stays present. Exercises the hardened phaseSummaryDiverges (this
 * session's container-index fix) across the whole array, not just index 0.
 */
function histMultiIndexPhase(rng: Rng): History {
  const world = freshWorld(rng);
  const ops: Op[] = [];
  const nonce = rng.int(400_000);
  const diverge = rng.chance(0.5);
  const idxCount = 2 + rng.int(3); // 2..4 shared indices
  const phasesA = Array.from({ length: idxCount }, (_, i) => ({ index: i, kind: 'deliver-storage-program', outcome: 'ok' }));
  const phasesB = phasesA.map((p) => ({ ...p }));
  let divergeAt = -1;
  if (diverge) { divergeAt = 1 + rng.int(idxCount - 1); phasesB[divergeAt] = { ...phasesB[divergeAt]!, outcome: 'fail' }; }
  // coherent present base (version-migrate shape): FAB seller aborted-by-self faulted=seller ∩ legacy
  // buyer aborted-by-other → fault-sets intersect {seller}; ONLY phaseSummary varies between variants.
  const fab = constructCopy(world, rng, {
    kind: 'fab', outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller',
    nonce, fullySigned: true, role: 'seller', phases: phasesA,
  });
  const legacy = constructCopy(world, rng, {
    kind: 'legacy', outcome: 'aborted-by-other', faultedParty: 'none', anchoredByRole: 'buyer',
    nonce: nonce + 1, fullySigned: true, role: 'buyer', phases: phasesB,
  });
  world.copies.push(fab, legacy);
  ops.push({ t: 'SIGN+ANCHOR', detail: `FAB seller + legacy buyer, ${idxCount} shared phase indices` });
  ops.push(diverge
    ? { t: 'PHASE_DIVERGE', detail: `phaseSummary[${divergeAt}].outcome disagrees across the pair (non-zero index)` }
    : { t: 'PHASE_AGREE', detail: `all ${idxCount} shared phase indices agree` });
  const copies: Record<string, unknown> = { seller: fab.bundle, buyer: legacy.bundle };
  return {
    kind: diverge ? 'multi-index-phase-diverge' : 'multi-index-phase-agree', world, ops,
    target: { api: 'mixed', copies },
    invariant: diverge ? 'no-launder' : 'determinism-under-restart',
    ...(diverge ? { preAdversarialFail: true } : { expectPresent: true }),
  };
}

const GENERATORS: Array<{ gen: (rng: Rng) => History; weight: number }> = [
  { gen: histLaunderMixed, weight: 16 },
  { gen: histLaunderPair, weight: 16 },
  { gen: histLaunderPointer, weight: 16 },
  { gen: histPerspectiveFlip, weight: 12 },
  { gen: histReplay, weight: 12 },
  { gen: histMonotonicStanding, weight: 10 },
  { gen: histVersionMigrate, weight: 10 },
  { gen: histMalformedTransition, weight: 12 },
  { gen: histThreeWayDivergence, weight: 10 },
  { gen: histBudgetExhaustion, weight: 8 },
  { gen: histMultiIndexPhase, weight: 10 },
];
function pickGenerator(rng: Rng): (rng: Rng) => History {
  const total = GENERATORS.reduce((s, g) => s + g.weight, 0);
  let r = rng.int(total);
  for (const g of GENERATORS) {
    if (r < g.weight) return g.gen;
    r -= g.weight;
  }
  return GENERATORS[0]!.gen;
}

// --------------------------------------------------------------------------------------------
// invariant checking across the history
// --------------------------------------------------------------------------------------------
type RunOutcome =
  | { threw: true; error: string }
  | { threw: false; resolution: BundleBindingResolution };

function runResolve(world: World, target: ResolveTarget): RunOutcome {
  try {
    return { threw: false, resolution: resolve(world, target) };
  } catch (error) {
    return { threw: true, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
  }
}

/** Produce an order-reshuffled clone of a resolve target (for determinism-under-restart). */
function reorderTarget(world: World, target: ResolveTarget, rng: Rng): { world: World; target: ResolveTarget } {
  if (target.api === 'bb') {
    const shuffled = { ...world, copies: world.copies.slice() };
    for (let i = shuffled.copies.length - 1; i > 0; i--) {
      const j = rng.int(i + 1);
      [shuffled.copies[i], shuffled.copies[j]] = [shuffled.copies[j]!, shuffled.copies[i]!];
    }
    return { world: shuffled, target };
  }
  if (target.api === 'pair' || target.api === 'mixed') {
    // reverse key insertion order (object key order is observable to Object.entries)
    const entries = Object.entries(target.copies).reverse();
    const copies = Object.fromEntries(entries);
    return { world, target: { ...target, copies } };
  }
  return { world, target };
}

type Violation = { invariant: string; detail: string };

function checkHistory(h: History): Violation[] {
  const violations: Violation[] = [];
  const first = runResolve(h.world, h.target);

  // fail-closed: never throws on any history.
  if (first.threw) {
    violations.push({ invariant: 'fail-closed', detail: `resolver threw: ${first.error}` });
    return violations;
  }
  const res = first.resolution;

  if (res.disposition !== 'present' && res.disposition !== 'fail' && res.disposition !== 'indeterminate') {
    violations.push({ invariant: 'valid-disposition', detail: `disposition=${JSON.stringify(res.disposition)}` });
  }

  // determinism-under-restart: re-resolve identical state -> identical result.
  const second = runResolve(h.world, h.target);
  if (second.threw) {
    violations.push({ invariant: 'determinism-under-restart', detail: `re-resolve threw: ${second.error}` });
  } else if (JSON.stringify(second.resolution) !== JSON.stringify(res)) {
    violations.push({
      invariant: 'determinism-under-restart',
      detail: `run1=${JSON.stringify(res)} run2=${JSON.stringify(second.resolution)}`,
    });
  }

  // determinism-under-restart (order-independence): reorder copies / key order -> same verdict.
  const rng = makeRng(0x51ed ^ h.world.copies.length ^ h.kind.length);
  const reordered = reorderTarget(h.world, h.target, rng);
  const reo = runResolve(reordered.world, reordered.target);
  if (reo.threw) {
    violations.push({ invariant: 'determinism-under-restart', detail: `reordered run threw: ${reo.error}` });
  } else {
    if (reo.resolution.disposition !== res.disposition) {
      violations.push({
        invariant: 'determinism-under-restart',
        detail: `disposition flipped ${res.disposition} -> ${reo.resolution.disposition} on reorder`,
      });
    }
    if (res.disposition === 'present' && reo.resolution.disposition === 'present' &&
        reo.resolution.resolvedNativeAddress !== res.resolvedNativeAddress) {
      violations.push({
        invariant: 'determinism-under-restart',
        detail: `winner changed ${res.resolvedNativeAddress} -> ${reo.resolution.resolvedNativeAddress} on reorder`,
      });
    }
  }

  // no-launder / perspective-invariance / replay-rejection / fail-closed families:
  // the adversarial step must NEVER yield present.
  if (h.preAdversarialFail && res.disposition === 'present') {
    violations.push({
      invariant: h.invariant,
      detail: `LAUNDERED to present after adversarial op: ${JSON.stringify(res)}`,
    });
  }

  // fail-closed divergence families (equal-standing N-way divergence, per-signer budget exhaustion):
  // the resolver must resolve INDETERMINATE — never present (would launder) and never a spurious fail.
  if (h.expectIndeterminate && res.disposition !== 'indeterminate') {
    violations.push({ invariant: h.invariant, detail: `expected indeterminate (fail-closed), got ${res.disposition}: ${res.detail}` });
  }
  if (h.expectDetailIncludes && !(res.detail ?? '').toLowerCase().includes(h.expectDetailIncludes.toLowerCase())) {
    violations.push({ invariant: h.invariant, detail: `expected detail to name "${h.expectDetailIncludes}" path, got: ${res.detail}` });
  }

  // constructive present families
  if (h.expectPresent) {
    if (res.disposition !== 'present') {
      violations.push({ invariant: `${h.kind}:expect-present`, detail: `got ${res.disposition}: ${res.detail}` });
    } else if (h.expectedNative !== undefined && res.resolvedNativeAddress !== h.expectedNative) {
      violations.push({
        invariant: 'monotonic-standing',
        detail: `expected winner ${h.expectedNative} got ${res.resolvedNativeAddress} (lesser-signed copy overrode full-signed)`,
      });
    }
  }

  return violations;
}

// --------------------------------------------------------------------------------------------
// serialisation for minimal-repro reporting
// --------------------------------------------------------------------------------------------
function historyToRepro(h: History): Json {
  return {
    kind: h.kind,
    invariant: h.invariant,
    jobId: h.world.jobId,
    ops: h.ops,
    target: h.target,
    expectPresent: h.expectPresent,
    expectedNative: h.expectedNative,
    preAdversarialFail: h.preAdversarialFail,
  };
}

// --------------------------------------------------------------------------------------------
// self-test: prove the signing path produces resolver-'present' AND resolver-'fail' verdicts, so a
// broken oracle can't report a vacuous green (every "valid" history collapsing to non-present, or
// every "fail" base already being present for the wrong reason).
// --------------------------------------------------------------------------------------------
function selfTest(): void {
  // (a) a hand-built valid monotonic-standing history MUST resolve present.
  const okRng = makeRng(1);
  const ok = histMonotonicStanding(okRng);
  const okOut = runResolve(ok.world, ok.target);
  if (okOut.threw || okOut.resolution.disposition !== 'present') {
    console.error('FATAL self-test (a): a valid full-signed history did not resolve present.');
    console.error(okOut.threw ? okOut.error : JSON.stringify(okOut.resolution));
    console.error('Signing/oracle wiring is broken — fuzz results would be vacuous. Aborting.');
    process.exit(2);
  }
  // (b) the PRISTINE contradiction base of a laundering history (before the ALTER_UNSIGNED) MUST be
  //     fail — otherwise "no-launder" would be vacuously satisfied by a base that was never fail.
  //     Reconstruct the pristine mixed contradiction with the same key material.
  const world = freshWorld(makeRng(2));
  const fab = constructCopy(world, makeRng(3), {
    kind: 'fab', outcome: 'aborted-by-other', faultedParty: 'seller', anchoredByRole: 'seller',
    nonce: 100, fullySigned: true, role: 'seller',
  });
  const legacy = constructCopy(world, makeRng(4), {
    kind: 'legacy', outcome: 'aborted-by-self', faultedParty: 'none', anchoredByRole: 'buyer',
    nonce: 101, fullySigned: true, role: 'buyer',
  });
  const pristine = resolveMixedVersionPair({
    publicKeys: world.publicKeys, copies: { seller: fab.bundle, buyer: legacy.bundle },
  });
  if (pristine.disposition !== 'fail') {
    console.error('FATAL self-test (b): the pristine contradiction base did NOT resolve fail.');
    console.error(JSON.stringify(pristine));
    console.error('A no-launder base that is not fail would make the invariant vacuous. Aborting.');
    process.exit(2);
  }
  // (c) a 3-way equal-standing divergence MUST resolve indeterminate — else the divergence family is
  //     vacuous (a base that was already present/fail for an unrelated reason).
  const three = histThreeWayDivergence(makeRng(5));
  const threeOut = runResolve(three.world, three.target);
  if (threeOut.threw || threeOut.resolution.disposition !== 'indeterminate') {
    console.error('FATAL self-test (c): a 3-way equal-standing divergence did NOT resolve indeterminate.');
    console.error(threeOut.threw ? threeOut.error : JSON.stringify(threeOut.resolution));
    process.exit(2);
  }
  // (d) budget exhaustion MUST resolve indeterminate VIA the BB-7 budget path — else the family never
  //     exercises the cap. The copies carry identical canonical content, so:
  const budg = histBudgetExhaustion(makeRng(6));
  const budgOut = runResolve(budg.world, budg.target);
  if (budgOut.threw || budgOut.resolution.disposition !== 'indeterminate' || !/budget/i.test(budgOut.resolution.detail ?? '')) {
    console.error('FATAL self-test (d): per-signer budget exhaustion did NOT resolve indeterminate via the BB-7 budget path.');
    console.error(budgOut.threw ? budgOut.error : JSON.stringify(budgOut.resolution));
    process.exit(2);
  }
  //     …and NON-VACUITY (Codex 2026-07-22): the SAME copies resolved under a budget large enough NOT
  //     to exhaust must resolve PRESENT (identical content = one canonical group). If they don't, the
  //     indeterminate above is not attributable to budget exhaustion and the family is vacuous — a
  //     removed budget check would then pass on equal-standing divergence instead of failing RED.
  const relaxedTarget: ResolveTarget = budg.target.api === 'bb'
    ? { api: 'bb', request: { ...budg.target.request, budget: 4096 }, role: budg.target.role }
    : budg.target;
  const relaxed = runResolve(budg.world, relaxedTarget);
  if (relaxed.threw || relaxed.resolution.disposition !== 'present') {
    console.error('FATAL self-test (d-nonvacuity): budget-exhaustion copies under a large budget did NOT resolve present.');
    console.error('The indeterminate is therefore NOT attributable to the budget cap (identical-content construction broke). Aborting.');
    console.error(relaxed.threw ? relaxed.error : JSON.stringify(relaxed.resolution));
    process.exit(2);
  }
  // (e) BOTH multi-index phase variants must be reachable and correct: a NON-ZERO-index divergence
  //     resolves non-present, and the all-agree control resolves present. Search seeds for one of each
  //     so a build where phaseSummaryDiverges silently no-ops (present on divergence) is caught here.
  let sawDivergeFail = false, sawAgreePresent = false;
  for (let s = 1; s <= 64 && !(sawDivergeFail && sawAgreePresent); s++) {
    const h = histMultiIndexPhase(makeRng(s));
    const out = runResolve(h.world, h.target);
    if (out.threw) continue;
    if (h.kind === 'multi-index-phase-diverge' && out.resolution.disposition !== 'present') sawDivergeFail = true;
    if (h.kind === 'multi-index-phase-agree' && out.resolution.disposition === 'present') sawAgreePresent = true;
  }
  if (!sawDivergeFail || !sawAgreePresent) {
    console.error(`FATAL self-test (e): multi-index phase family vacuous (divergeCaught=${sawDivergeFail}, agreePresent=${sawAgreePresent}).`);
    console.error('phaseSummaryDiverges may be no-opping beyond index 0, or the coherent base is not present. Aborting.');
    process.exit(2);
  }
}

// --------------------------------------------------------------------------------------------
// CLI + main loop
// --------------------------------------------------------------------------------------------
function parseArgs(argv: string[]): { cases: number; seed: number; historyLen: number; caseSeed?: number; verbose: boolean } {
  let cases = 500;
  let seed = 20260701; // fixed default for reproducibility
  let historyLen = 8;  // advisory cap on ops per history (families build 2..K ops)
  let caseSeed: number | undefined;
  let verbose = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cases') cases = parseInt(argv[++i]!, 10);
    else if (a === '--seed') seed = parseInt(argv[++i]!, 10) >>> 0;
    else if (a === '--history-len') historyLen = parseInt(argv[++i]!, 10);
    else if (a === '--case-seed') caseSeed = parseInt(argv[++i]!, 10) >>> 0;
    else if (a === '--verbose' || a === '-v') verbose = true;
  }
  return { cases, seed, historyLen, caseSeed, verbose };
}

function runOneCase(caseSeed: number): { history: History; violations: Violation[] } {
  const rng = makeRng(caseSeed);
  const history = pickGenerator(rng)(rng);
  const violations = checkHistory(history);
  return { history, violations };
}

function main(): void {
  const { cases, seed, historyLen, caseSeed, verbose } = parseArgs(process.argv.slice(2));
  selfTest();

  if (caseSeed !== undefined) {
    const { history, violations } = runOneCase(caseSeed);
    console.log(`Replaying case-seed ${caseSeed} (kind=${history.kind}, invariant=${history.invariant})`);
    console.log('operation sequence (history):');
    history.ops.forEach((op, i) => console.log(`  ${i + 1}. [${op.t}] ${op.detail}`));
    const live = runResolve(history.world, history.target);
    console.log('\nresolution:', live.threw ? `THREW ${live.error}` : JSON.stringify(live.resolution));
    console.log('\nfull repro:');
    console.log(JSON.stringify(historyToRepro(history), null, 2));
    if (violations.length === 0) console.log('\nNo invariant violations for this history.');
    else {
      console.log(`\n${violations.length} violation(s):`);
      for (const v of violations) console.log(`  [${v.invariant}] ${v.detail}`);
      process.exitCode = 1;
    }
    return;
  }

  console.log('DACS-5 §10.4.2 BundleBinding — STATEFUL / HISTORY model-based fuzzer');
  console.log(`seed=${seed}  cases=${cases}  history-len<=${historyLen}\n`);

  const kindCounts = new Map<string, number>();
  const invariantCounts = new Map<string, number>();
  type FailRecord = { caseSeed: number; kind: string; violations: Violation[]; repro: Json };
  const firstFailurePerInvariant = new Map<string, FailRecord>();
  let totalViolations = 0;
  let failingCases = 0;

  const master = makeRng(seed);
  for (let i = 0; i < cases; i++) {
    const cs = Math.floor(master.next() * 4294967296) >>> 0;
    const { history, violations } = runOneCase(cs);
    kindCounts.set(history.kind, (kindCounts.get(history.kind) ?? 0) + 1);
    if (violations.length > 0) {
      failingCases++;
      totalViolations += violations.length;
      for (const v of violations) {
        invariantCounts.set(v.invariant, (invariantCounts.get(v.invariant) ?? 0) + 1);
        if (!firstFailurePerInvariant.has(v.invariant)) {
          firstFailurePerInvariant.set(v.invariant, {
            caseSeed: cs, kind: history.kind, violations, repro: historyToRepro(history),
          });
        }
      }
      if (verbose) {
        console.log(`FAIL case-seed=${cs} kind=${history.kind}`);
        for (const v of violations) console.log(`    [${v.invariant}] ${v.detail}`);
      }
    }
  }

  console.log('history coverage:');
  for (const [kind, count] of [...kindCounts.entries()].sort()) {
    console.log(`  ${kind.padEnd(26)} ${count}`);
  }
  console.log('');

  if (totalViolations === 0) {
    console.log(`RESULT: ${cases}/${cases} histories pass. No invariant violations across any sequence.`);
    console.log('Invariants exercised: no-launder, perspective-invariance, replay-rejection,');
    console.log('determinism-under-restart, fail-closed, monotonic-standing, equal-standing-divergence,');
    console.log('budget-exhaustion (per-signer fetch cap), multi-index phaseSummary (#254 beyond index 0).');
    return;
  }

  console.log(`RESULT: ${failingCases}/${cases} histories had violations (${totalViolations} total).`);
  console.log('violations by invariant:');
  for (const [inv, count] of [...invariantCounts.entries()].sort()) {
    console.log(`  ${inv.padEnd(30)} ${count}`);
  }
  console.log('\nminimal reproducing SEQUENCES (first occurrence per invariant):');
  for (const [inv, rec] of firstFailurePerInvariant.entries()) {
    console.log(`\n=== invariant: ${inv} ===`);
    console.log(`replay: npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts --case-seed ${rec.caseSeed}`);
    console.log(`kind: ${rec.kind}`);
    console.log('reproducing operation sequence:');
    (rec.repro.ops as Op[]).forEach((op, i) => console.log(`  ${i + 1}. [${op.t}] ${op.detail}`));
    for (const v of rec.violations.filter((x) => x.invariant === inv)) console.log(`detail: ${v.detail}`);
  }
  process.exitCode = 1;
}

main();
