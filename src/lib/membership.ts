/**
 * cci-membership — CCI-keyed roster membership proof ENGINE (v0, minimal-disclosure).
 *
 * Spec / contract source: wayfare/conformance/cci-membership-verifier-contract.md
 *   §9  the canonical verifier algorithm (the authorization predicate — two impls MUST agree)
 *   §4  decision semantics (accept | reject | indeterminate | error — §7.5.1, do NOT collapse)
 *   §5  linkability ceiling
 *   §2  authoritative root + epoch authority
 *   §3  roster governance (publish/revoke; admin binding over the FULL tuple)
 *
 * ============================ HONESTY / SCOPE (contract §5) ===================================
 * ⚠️ This engine proves "my CCI-keyed leaf is a MEMBER of roster R at epoch E" — a predicate
 * outcome ONLY. It is MINIMAL DISCLOSURE, **NOT anonymity**:
 *   - The proof REVEALS the prover's CCI to the verifier it is shown to (contract §5). Presentations
 *     to the SAME verifier are LINKABLE via the presentation key. v0 MUST NOT be marketed as
 *     anonymous. Mitigation (not removal): an audience-scoped presentation key, rotated per epoch so
 *     links break ACROSS epochs — the CCI value key never signs ongoing messages.
 *   - True unlinkability (hide WHICH member) is the DEFERRED zk tier (Semaphore-style) — a separate
 *     threat model + new crypto, out of scope here.
 *   - "Member" ≠ "currently funded" (contract §1). A live balance read is a SEPARATE caller check.
 *
 * Decision lattice (contract §4 / §7.5.1 — precedence ACCUMULATED, never coerced):
 *   malformed → error ; else any reject → reject ; else any indeterminate → indeterminate ; else accept.
 *   Outcomes are ACCUMULATED across checks and precedence is applied ONCE at the end — the verifier
 *   does NOT short-circuit on the first non-pass. A reject ALWAYS beats an indeterminate, even when
 *   both apply: a proof that is simultaneously stale-epoch (indeterminate) AND carries a forged
 *   member binding (reject) → reject, because the member binding is anchor-INDEPENDENT (verifiable
 *   from the proof's own preimage+cci) and fires regardless of anchor readability.
 *   A valid Merkle path ALONE is NOT acceptance — the fast-revoke gate is part of the predicate (§4).
 *
 * ============================ NO-GO LIST ====================================================
 * Salted-hash CCI-keyed Merkle leaves (reusing the audited disclose.ts commitment scheme) +
 * ed25519 admin/member bindings ONLY. No ZK / L2PS / FHE / bridges / escrow. Dependency-light: the
 * leaf is `computeCommitment(salt, memberClaim)` so it stays consistent with the audited commitment
 * primitive — we do NOT hand-roll a parallel hash. The roster tree is `computeCommitmentRoot([...])`.
 *
 * ============================ CROSS-ROSTER / CROSS-ADMIN / REPLAY SAFETY (contract §9) ========
 * `rosterAdminCCI` + `rosterId` + `epoch` are bound INSIDE the leaf preimage AND inside EVERY signed
 * scope (admin binding tuple, member binding, epoch head). The artifacts also live at `(adminCCI,
 * rosterId, epoch)`-derived anchor addresses. So a proof from roster A / epoch N cannot validate
 * against roster B / epoch M — and, crucially, a member of Admin-X's roster "shared-id" cannot have
 * an UNMODIFIED proof + REUSED member-binding signature accepted against a different Admin-Y who
 * publishes a roster with the SAME `rosterId` string: the leaf recompute, the path fold, the admin
 * tuple match, AND the member binding all carry rosterAdminCCI+rosterId+epoch, and the verifier
 * confirms the proof's bound rosterAdminCCI EQUALS `expected.rosterAdminCCI` (case-insensitive on
 * hex) before any anchor read. rosterId collisions across admins are therefore HARMLESS (F1).
 */

import { computeCommitment, verifyMerklePath, MIN_SALT_BYTES, type MerklePathStep } from './disclose.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { DACS_X_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical } from '../jcs.js';
import { hexToBytes } from './verify-bundle.js';
import type { ClaimReference } from '../types/identity.js';

const ROOT_SEP = DACS_X_EXTENSION_SEPARATORS.ROSTER_ROOT;   // 'dacs-x-roster-root:v1:'
const BIND_SEP = DACS_X_EXTENSION_SEPARATORS.ROSTER_BIND;   // 'dacs-x-roster-bind:v1:'
const EPOCH_SEP = DACS_X_EXTENSION_SEPARATORS.ROSTER_EPOCH; // 'dacs-x-roster-epoch:v1:'

const TREE_HASH_ALG = 'rfc6962-sha256' as const;

/**
 * Lowercase a hex identifier (cci / presentationKeyPub / rosterAdminCCI) before it enters a JCS
 * leaf/binding or a comparison. The same key in upper- vs lower-case hex MUST yield ONE leaf, else
 * linkability + equivocation-detection break (F3). Mirrors consent.ts / disclose.ts which lowercase
 * all hex identifiers. rosterId is an opaque label, not hex, so it is NOT lowercased.
 */
function lc(s: string): string {
  return s.toLowerCase();
}

/* -------------------------------------------------------------------------- */
/*  Types                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The opening of ONE roster member leaf. `cci` is the prover's CCI identifier (revealed to the
 * verifier — §5). `presentationKeyPub` is the audience-scoped key that signs ongoing messages AFTER
 * acceptance (never the CCI value key). `rosterId` + `epoch` are bound inside the leaf for replay
 * safety.
 */
export interface MemberLeafPreimage {
  /**
   * The roster admin's CCI. Bound INTO the leaf (and the member binding) so a member of Admin-X's
   * roster "shared-id" cannot have their proof replayed against a different Admin-Y who publishes a
   * roster with the SAME rosterId string (cross-admin replay — contract §9). rosterId collisions
   * across admins are therefore harmless.
   */
  rosterAdminCCI: string;
  rosterId: string;
  cci: string;
  presentationKeyPub: string;
  epoch: number;
}

/**
 * The admin-published, admin-signed roster root artifact, anchored at derive(rosterAdminCCI,
 * rosterId, epoch). `adminBinding` is an ed25519 signature by `rosterAdminCCI` under ROSTER_ROOT
 * over JCS of the FULL tuple (contract §3 — a root-only sig is replayable into another context).
 */
export interface RosterRootArtifact {
  protocol: 'cci-membership';
  v: 1;
  network: string;
  rosterAdminCCI: string;
  rosterId: string;
  epoch: number;
  treeHashAlg: 'rfc6962-sha256';
  treeDepth: number;
  root: string;
  publishedAt: number;
  /** ed25519 sig (hex) by rosterAdminCCI under ROSTER_ROOT over JCS of the signable tuple. */
  adminBinding: string;
}

/**
 * The canonical `currentEpoch` pointer, admin-signed, anchored at derive(rosterAdminCCI, rosterId,
 * "epoch-head") (contract §2). A proof whose epoch ∉ {current} ∪ acceptedEpochs is indeterminate.
 */
export interface EpochHead {
  protocol: 'cci-membership-epoch';
  v: 1;
  rosterAdminCCI: string;
  rosterId: string;
  currentEpoch: number;
  /** Explicitly-published grace range of still-accepted epochs (contract §2). */
  acceptedEpochs?: number[];
  /** ed25519 sig (hex) by rosterAdminCCI under ROSTER_EPOCH over JCS of the signable body. */
  sig: string;
}

/** The off-chain proof a prover presents (contract §7). */
export interface MembershipProof {
  leafPreimage: MemberLeafPreimage;
  /** Salt (hex) opening the member leaf commitment. CSPRNG, >= MIN_SALT_BYTES. */
  salt: string;
  /** Audit path from the member leaf commitment to the anchored root. */
  merklePath: MerklePathStep[];
  /** ed25519 sig (hex) by `cci` under ROSTER_BIND over {rosterId, epoch, presentationKeyPub}. */
  bindingSig: string;
  /** The epoch this proof is for. MUST equal leafPreimage.epoch. */
  epoch: number;
}

/** One ordered verifier check, recorded for auditability. */
export interface MembershipCheck {
  id: string;
  /** true = passed, false = failed (contributes a reject/error), null = indeterminate. */
  ok: boolean | null;
  detail: string;
}

/** The verdict — decision precedence per §4, with the ordered check trail. */
export interface MembershipVerdict {
  decision: 'accept' | 'reject' | 'indeterminate' | 'error';
  checks: MembershipCheck[];
}

/* -------------------------------------------------------------------------- */
/*  Adapter interfaces (a Demos adapter wraps these thinly)                      */
/* -------------------------------------------------------------------------- */

/**
 * Reads the authoritative epoch-head pointer + root artifact from wherever they are anchored. The
 * engine NEVER discovers addresses itself — the adapter derives them from (adminCCI, rosterId,
 * epoch). Returning `null` means UNREADABLE → the verifier yields `indeterminate` (never a silent
 * pass — contract §4).
 */
export interface AnchorReader {
  readEpochHead(adminCCI: string, rosterId: string): Promise<EpochHead | null>;
  readRoot(adminCCI: string, rosterId: string, epoch: number): Promise<RosterRootArtifact | null>;
}

/**
 * Resolves fast-revoke (contract §3b / §9.7) for a member leaf commitment + audience. `readable:
 * false` means the revoke ledger could not be read → `indeterminate`. `revoked: true` (readable) →
 * `reject`. `revoked: false` (readable) → the gate passes.
 */
export interface RevokeResolver {
  isRevoked(memberCommitmentHex: string, audience: string): Promise<{ revoked: boolean; readable: boolean }>;
}

/* -------------------------------------------------------------------------- */
/*  Member leaf (reuses the audited disclose.ts commitment scheme)              */
/* -------------------------------------------------------------------------- */

/**
 * The MEMBER CLAIM whose commitment is the roster leaf. Object-form ClaimReference so the leaf is
 * `computeCommitment(salt, memberClaim)` — keeping the leaf consistent with the audited commitment
 * scheme (no parallel hash). `cci` is the identifier; rosterId + presentationKeyPub + epoch ride in
 * params so they are bound into the leaf for replay safety.
 */
function memberClaim(p: MemberLeafPreimage): ClaimReference {
  return {
    scheme: 'cci',
    identifier: lc(p.cci),
    params: {
      // rosterAdminCCI is bound into the leaf so the same member in two admins' same-rosterId
      // rosters yields DIFFERENT leaves → cross-admin replay is impossible (contract §9).
      rosterAdminCCI: lc(p.rosterAdminCCI),
      // rosterId is an opaque label, NOT a hex identifier, so it is bound verbatim (matches the
      // admin tuple + epoch head, which also carry rosterId verbatim).
      rosterId: p.rosterId,
      presentationKeyPub: lc(p.presentationKeyPub),
      // params is Record<string,string>; epoch is encoded as decimal ASCII (stable, no float drift).
      epoch: String(p.epoch),
    },
  };
}

/**
 * Compute the member leaf COMMITMENT (hex) = computeCommitment(salt, memberClaim(preimage)). This is
 * the leaf that goes into the roster Merkle tree (computeCommitmentRoot([...member commitments])).
 */
export function memberLeaf(salt: string, preimage: MemberLeafPreimage): string {
  return computeCommitment(salt, memberClaim(preimage));
}

/* -------------------------------------------------------------------------- */
/*  Admin / prover helpers                                                       */
/* -------------------------------------------------------------------------- */

/** The canonical SIGNABLE tuple for the admin binding (contract §3 — the FULL tuple, no signature). */
function rootSignableTuple(a: Omit<RosterRootArtifact, 'adminBinding'>): Omit<RosterRootArtifact, 'adminBinding'> {
  return {
    protocol: a.protocol,
    v: a.v,
    network: a.network,
    rosterAdminCCI: a.rosterAdminCCI,
    rosterId: a.rosterId,
    epoch: a.epoch,
    treeHashAlg: a.treeHashAlg,
    treeDepth: a.treeDepth,
    root: a.root,
    publishedAt: a.publishedAt,
  };
}

/** The canonical SIGNABLE body for the epoch head (no signature). */
function epochSignableBody(e: Omit<EpochHead, 'sig'>): Omit<EpochHead, 'sig'> {
  const out: Omit<EpochHead, 'sig'> = {
    protocol: e.protocol,
    v: e.v,
    rosterAdminCCI: e.rosterAdminCCI,
    rosterId: e.rosterId,
    currentEpoch: e.currentEpoch,
  };
  // Only include acceptedEpochs when present, so an undefined never JCS-encodes inconsistently.
  if (e.acceptedEpochs !== undefined) out.acceptedEpochs = [...e.acceptedEpochs].sort((x, y) => x - y);
  return out;
}

/**
 * The canonical SIGNABLE body for the member binding (contract §9.6). Binds rosterAdminCCI so the
 * CCI's binding signature is NOT reusable against a different admin who reuses the rosterId string
 * (cross-admin replay — F1). Hex identifiers are lowercased (F3).
 */
function memberBindingBody(b: {
  rosterAdminCCI: string;
  rosterId: string;
  epoch: number;
  presentationKeyPub: string;
}): {
  rosterAdminCCI: string;
  rosterId: string;
  epoch: number;
  presentationKeyPub: string;
} {
  return {
    rosterAdminCCI: lc(b.rosterAdminCCI),
    rosterId: b.rosterId,
    epoch: b.epoch,
    presentationKeyPub: lc(b.presentationKeyPub),
  };
}

/**
 * Admin-side: build + sign a roster root artifact (contract §3). The admin signs the FULL tuple
 * under ROSTER_ROOT, so the binding is NOT replayable into another context. `root` is the
 * caller-supplied Merkle root over the member leaf commitments (computeCommitmentRoot([...])).
 *
 * @param adminPriv  the rosterAdminCCI's ed25519 private key
 */
export function buildRosterRoot(
  adminPriv: Uint8Array,
  fields: {
    network: string;
    rosterAdminCCI: string;
    rosterId: string;
    epoch: number;
    treeDepth: number;
    root: string;
    publishedAt: number;
  }
): RosterRootArtifact {
  const tuple = rootSignableTuple({
    protocol: 'cci-membership',
    v: 1,
    network: fields.network,
    rosterAdminCCI: fields.rosterAdminCCI,
    rosterId: fields.rosterId,
    epoch: fields.epoch,
    treeHashAlg: TREE_HASH_ALG,
    treeDepth: fields.treeDepth,
    root: fields.root,
    publishedAt: fields.publishedAt,
  });
  const adminBinding = bytesToHexLocal(edSign(ROOT_SEP, jcsCanonical(tuple), adminPriv));
  return { ...tuple, adminBinding };
}

/**
 * Admin-side: build + sign an epoch-head pointer (contract §2). Signs the body under ROSTER_EPOCH.
 */
export function signEpochHead(
  adminPriv: Uint8Array,
  fields: {
    rosterAdminCCI: string;
    rosterId: string;
    currentEpoch: number;
    acceptedEpochs?: number[];
  }
): EpochHead {
  const body = epochSignableBody({
    protocol: 'cci-membership-epoch',
    v: 1,
    rosterAdminCCI: fields.rosterAdminCCI,
    rosterId: fields.rosterId,
    currentEpoch: fields.currentEpoch,
    acceptedEpochs: fields.acceptedEpochs,
  });
  const sig = bytesToHexLocal(edSign(EPOCH_SEP, jcsCanonical(body), adminPriv));
  return { ...body, sig };
}

/**
 * Member/prover-side: sign the member binding (contract §9.6) — the CCI signs {rosterAdminCCI,
 * rosterId, epoch, presentationKeyPub} under ROSTER_BIND, tying the presentation key to the CCI for
 * THIS admin+roster+epoch. Binding rosterAdminCCI makes the signature non-replayable against another
 * admin who reuses the rosterId string (F1).
 *
 * @param cciPriv  the member CCI's ed25519 private key
 */
export function signMemberBinding(
  cciPriv: Uint8Array,
  fields: { rosterAdminCCI: string; rosterId: string; epoch: number; presentationKeyPub: string }
): string {
  return bytesToHexLocal(edSign(BIND_SEP, jcsCanonical(memberBindingBody(fields)), cciPriv));
}

/** Prover-side: assemble a MembershipProof from its parts (pure structural helper). */
export function buildMembershipProof(fields: {
  leafPreimage: MemberLeafPreimage;
  salt: string;
  merklePath: MerklePathStep[];
  bindingSig: string;
}): MembershipProof {
  return {
    leafPreimage: fields.leafPreimage,
    salt: fields.salt,
    merklePath: fields.merklePath,
    bindingSig: fields.bindingSig,
    epoch: fields.leafPreimage.epoch,
  };
}

/* -------------------------------------------------------------------------- */
/*  Local hex helper (avoid importing the bytesToHex name twice through types)   */
/* -------------------------------------------------------------------------- */

function bytesToHexLocal(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/* -------------------------------------------------------------------------- */
/*  Runtime shape validation for anchor artifacts + path elements               */
/* -------------------------------------------------------------------------- */

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;
const isStr = (x: unknown): x is string => typeof x === 'string';
const isInt = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x);

/**
 * Strict runtime shape+type validation of an EpochHead (Codex caveat). The adapter is untrusted —
 * malformed adapter data must yield the contract's clean indeterminate (epoch authority
 * unconfirmable), NOT a thrown exception or a misclassification inside canonicalize/edVerify.
 */
function isValidEpochHeadShape(e: unknown): e is EpochHead {
  if (!isObj(e)) return false;
  if (e.protocol !== 'cci-membership-epoch' || e.v !== 1) return false;
  if (!isStr(e.rosterAdminCCI) || !isStr(e.rosterId)) return false;
  if (!isInt(e.currentEpoch)) return false;
  if (e.acceptedEpochs !== undefined) {
    if (!Array.isArray(e.acceptedEpochs) || !e.acceptedEpochs.every(isInt)) return false;
  }
  if (!isStr(e.sig)) return false;
  return true;
}

/**
 * Strict runtime shape+type validation of a RosterRootArtifact (Codex caveat). Returns false on any
 * malformed/missing/wrong-typed field so canonicalize/edVerify never run on garbage.
 */
function isValidRootShape(r: unknown): r is RosterRootArtifact {
  if (!isObj(r)) return false;
  if (r.protocol !== 'cci-membership' || r.v !== 1) return false;
  if (!isStr(r.network) || !isStr(r.rosterAdminCCI) || !isStr(r.rosterId)) return false;
  if (!isInt(r.epoch)) return false;
  if (r.treeHashAlg !== TREE_HASH_ALG) return false;
  if (!isInt(r.treeDepth)) return false;
  if (!isStr(r.root)) return false;
  if (!isInt(r.publishedAt)) return false;
  if (!isStr(r.adminBinding)) return false;
  return true;
}

/**
 * Validate a Merkle audit-path's element shapes (F5). A path element missing `sibling`/`side` (or
 * with the wrong types) is MALFORMED INPUT → error (contract §4), not a verification reject. The
 * cryptographic fold itself (verifyMerklePath) is what produces a reject for a well-formed but
 * non-folding path.
 */
function isValidMerklePathShape(path: unknown[]): boolean {
  for (const step of path) {
    if (!isObj(step)) return false;
    if (!isStr(step.sibling)) return false;
    if (step.side !== 'left' && step.side !== 'right') return false;
  }
  return true;
}

/* -------------------------------------------------------------------------- */
/*  The canonical verifier (contract §9 — implemented EXACTLY, in order)         */
/* -------------------------------------------------------------------------- */

/**
 * Verify a membership proof against an expected roster (contract §9). Runs the algorithm and returns
 * a verdict with the full check trail.
 *
 * Decision precedence (§4 / §7.5.1 — ACCUMULATED, never short-circuited): malformed input → error;
 * else any reject → reject; else any indeterminate → indeterminate; else accept. A reject ALWAYS
 * beats an indeterminate, even when both apply to the same proof (F2). Anchor-INDEPENDENT reject
 * checks — the member binding (verifiable from the proof's own preimage+cci, no anchor needed),
 * the schema/path-shape gate, and the expected-field/leaf-scope comparisons — are evaluated and
 * contribute their reject EVEN WHEN an anchor read is unreadable. Anchor-DEPENDENT checks whose
 * anchor is unreadable contribute `indeterminate` (never a silent pass).
 *
 * Checks (run when their inputs are available; outcomes accumulated, precedence applied at the end):
 *   schema/parse + path-shape  → malformed → error (verifier-side, retryable; short-circuits)
 *   leaf-scope                 → preimage rosterId/epoch/rosterAdminCCI must match expected → else reject (anchor-independent)
 *   member-binding             → bindingSig verifies under preimage.cci → else reject (anchor-independent)
 *   admin-key-resolve          → expected.rosterAdminCCI resolves to a key → else indeterminate
 *   epoch authority            → epoch-head readable + admin-signed + epoch accepted → else indeterminate
 *   authoritative root         → root readable + strict shape → else indeterminate
 *   admin-binding              → adminBinding verifies over FULL tuple + tuple matches expected → else reject (anchor-dependent inputs)
 *   leaf-path                  → recompute leaf, verifyMerklePath to root → else reject (anchor-dependent inputs)
 *   fast-revoke gate           → unreadable → indeterminate; revoked → reject
 */
export async function verifyMembership(
  proof: MembershipProof,
  expected: { rosterId: string; rosterAdminCCI: string; audience: string },
  deps: { anchor: AnchorReader; revoke: RevokeResolver }
): Promise<MembershipVerdict> {
  const checks: MembershipCheck[] = [];
  // Accumulators — final precedence (§4) is applied once, after every runnable check has fired.
  let sawReject = false;
  let sawIndeterminate = false;
  const pass = (id: string, detail: string) => checks.push({ id, ok: true, detail });
  const rej = (id: string, detail: string) => {
    checks.push({ id, ok: false, detail });
    sawReject = true;
  };
  const indet = (id: string, detail: string) => {
    checks.push({ id, ok: null, detail });
    sawIndeterminate = true;
  };
  // error short-circuits: a malformed proof can't be reasoned about further (contract §4).
  const err = (id: string, detail: string): MembershipVerdict => {
    checks.push({ id, ok: false, detail });
    return { decision: 'error', checks };
  };
  const finalize = (): MembershipVerdict => {
    const decision = sawReject ? 'reject' : sawIndeterminate ? 'indeterminate' : 'accept';
    return { decision, checks };
  };

  /* -- schema/parse — malformed → error (verifier-side, retryable; short-circuits) ----------- */
  // Structural shape.
  if (
    proof === null ||
    typeof proof !== 'object' ||
    typeof proof.leafPreimage !== 'object' ||
    proof.leafPreimage === null ||
    typeof proof.salt !== 'string' ||
    !Array.isArray(proof.merklePath) ||
    typeof proof.bindingSig !== 'string' ||
    typeof proof.epoch !== 'number'
  ) {
    return err('schema', 'malformed proof: missing/wrong-typed required fields');
  }
  const lp = proof.leafPreimage;
  if (
    typeof lp.rosterAdminCCI !== 'string' ||
    typeof lp.rosterId !== 'string' ||
    typeof lp.cci !== 'string' ||
    typeof lp.presentationKeyPub !== 'string' ||
    typeof lp.epoch !== 'number'
  ) {
    return err('schema', 'malformed proof: leafPreimage fields missing/wrong-typed');
  }
  if (!Number.isInteger(proof.epoch) || !Number.isInteger(lp.epoch)) {
    return err('schema', 'malformed proof: epoch must be an integer');
  }
  if (proof.epoch !== lp.epoch) {
    return err('schema', `malformed proof: proof.epoch=${proof.epoch} != leafPreimage.epoch=${lp.epoch}`);
  }
  // F5: a malformed merkle-path ELEMENT (missing/typo `sibling`/`side`) is malformed input → error,
  // NOT a verification reject. The crypto fold (verifyMerklePath) only reaches well-formed elements.
  if (!isValidMerklePathShape(proof.merklePath)) {
    return err('schema', 'malformed proof: a merkle-path element is missing/typed-wrong sibling/side');
  }
  // Hex widths: salt must decode and meet the 128-bit floor; bindingSig must be 64-byte ed25519.
  let saltLen: number;
  try {
    saltLen = hexToBytes(proof.salt).length;
  } catch {
    return err('schema', 'malformed proof: salt is not valid hex');
  }
  if (saltLen < MIN_SALT_BYTES) {
    return err('schema', `malformed proof: salt too short (${saltLen} bytes < ${MIN_SALT_BYTES})`);
  }
  let bindingSigBytes: Uint8Array;
  try {
    bindingSigBytes = hexToBytes(proof.bindingSig);
  } catch {
    return err('schema', 'malformed proof: bindingSig is not valid hex');
  }
  if (bindingSigBytes.length !== 64) {
    return err('schema', 'malformed proof: bindingSig is not a 64-byte ed25519 signature');
  }
  // cci must be valid-hex ed25519 pubkey (it verifies the member binding below).
  let cciPub: Uint8Array;
  try {
    cciPub = hexToBytes(lp.cci);
  } catch {
    return err('schema', 'malformed proof: cci is not valid hex');
  }
  if (cciPub.length !== 32) {
    return err('schema', 'malformed proof: cci is not a 32-byte ed25519 public key');
  }
  pass('schema', 'proof is structurally well-formed; salt/bindingSig/cci widths + path shape valid');

  /* -- admin-key-resolve — expected.rosterAdminCCI must resolve to a 32-byte key, else epoch
   *    authority (and a meaningful cross-admin comparison) cannot be confirmed at all (contract §4 →
   *    indeterminate). Resolved FIRST so a garbage expected admin yields a clean indeterminate
   *    rather than a spurious cross-admin leaf-scope reject against an unresolvable identifier. */
  let adminPub: Uint8Array | null = null;
  try {
    const k = hexToBytes(expected.rosterAdminCCI);
    if (k.length !== 32) {
      indet('admin-key-resolve', 'rosterAdminCCI does not resolve to a 32-byte ed25519 key');
    } else {
      adminPub = k;
      pass('admin-key-resolve', 'rosterAdminCCI resolves to a 32-byte ed25519 key');
    }
  } catch {
    indet('admin-key-resolve', 'rosterAdminCCI is not resolvable to a key (not valid hex)');
  }

  /* == ANCHOR-INDEPENDENT reject checks — fire even if anchor reads later fail (F2) ========== */

  /* -- leaf-scope — preimage rosterAdminCCI/rosterId/epoch must match expected (case-insensitive
   *    on hex; F1 binds the admin, F3 normalizes case). Anchor-independent → contributes reject. The
   *    admin-equality portion is only a meaningful reject when expected.rosterAdminCCI RESOLVES to a
   *    key — an unresolvable expected admin is the admin-key-resolve indeterminate above, not a
   *    cross-admin attack. rosterId/epoch are always compared. */
  {
    const adminMismatch = adminPub !== null && lc(lp.rosterAdminCCI) !== lc(expected.rosterAdminCCI);
    if (adminMismatch || lp.rosterId !== expected.rosterId || lp.epoch !== proof.epoch) {
      rej(
        'leaf-scope',
        `leaf preimage scope mismatch: admin/rosterId/epoch=${lp.rosterAdminCCI.slice(0, 8)}…/${lp.rosterId}/${lp.epoch} ` +
          `expected ${expected.rosterAdminCCI.slice(0, 8)}…/${expected.rosterId}/${proof.epoch}`
      );
    } else {
      pass('leaf-scope', `leaf scope matches expected admin/${expected.rosterId}/${proof.epoch}`);
    }
  }

  /* -- member binding — verify bindingSig under preimage.cci. PURELY anchor-independent: the
   *    preimage + cci are in the proof itself, so a forged binding yields `reject` EVEN WHEN the
   *    anchor is unreadable (F2). Binds rosterAdminCCI so it is non-replayable cross-admin (F1). */
  {
    const body = memberBindingBody({
      rosterAdminCCI: lp.rosterAdminCCI,
      rosterId: lp.rosterId,
      epoch: lp.epoch,
      presentationKeyPub: lp.presentationKeyPub,
    });
    if (!edVerify(BIND_SEP, bindingSigBytes, jcsCanonical(body), cciPub)) {
      rej('member-binding', 'bindingSig does not verify under cci over {rosterAdminCCI, rosterId, epoch, presentationKeyPub} (non-holder / forged)');
    } else {
      pass('member-binding', 'member bindingSig verifies under cci (presentationKeyPub is bound to the CCI for this admin+roster+epoch)');
    }
  }

  /* == ANCHOR-DEPENDENT checks — unreadable/unconfirmable authority contributes indeterminate == */
  // Everything below needs the admin key; if it didn't resolve, those authority checks are
  // indeterminate (already recorded). Anchor-independent rejects above are preserved by finalize().
  if (adminPub !== null) {
    const adminKey = adminPub;

    /* -- epoch authority — read epoch-head; strictly validate shape; admin-sign; epoch accepted. */
    let epochHead: EpochHead | null = null;
    let epochAuthorityOk = false;
    try {
      const raw = await deps.anchor.readEpochHead(lc(expected.rosterAdminCCI), expected.rosterId);
      if (raw === null) {
        indet('epoch-head-read', 'epoch-head pointer unreadable (anchor returned null)');
      } else if (!isValidEpochHeadShape(raw)) {
        // Codex caveat: malformed adapter data → clean indeterminate (authority unconfirmable),
        // never a throw inside canonicalize/edVerify.
        indet('epoch-head-shape', 'epoch-head is malformed (shape/type invalid) — epoch authority unconfirmable');
      } else {
        epochHead = raw;
      }
    } catch (e) {
      indet('epoch-head-read', `epoch-head read threw: ${(e as Error).message}`);
    }

    if (epochHead !== null) {
      let ehVerified = false;
      try {
        const ehSig = hexToBytes(epochHead.sig);
        const ehBody = epochSignableBody(epochHead);
        ehVerified =
          lc(epochHead.rosterAdminCCI) === lc(expected.rosterAdminCCI) &&
          epochHead.rosterId === expected.rosterId &&
          edVerify(EPOCH_SEP, ehSig, jcsCanonical(ehBody), adminKey);
      } catch {
        ehVerified = false;
      }
      if (!ehVerified) {
        indet('epoch-head-sig', 'epoch-head not admin-signed for this roster (epoch authority unconfirmable)');
      } else {
        const accepted = new Set<number>([epochHead.currentEpoch, ...(epochHead.acceptedEpochs ?? [])]);
        if (!accepted.has(proof.epoch)) {
          indet(
            'epoch-accepted',
            `proof.epoch=${proof.epoch} not in {current=${epochHead.currentEpoch}}∪accepted=${JSON.stringify(epochHead.acceptedEpochs ?? [])} (stale/unconfirmable)`
          );
        } else {
          epochAuthorityOk = true;
          pass('epoch-accepted', `epoch ${proof.epoch} is current or within the accepted grace range`);
        }
      }
    }

    /* -- authoritative root — read + strictly validate shape; verify admin binding + leaf path. */
    let rootArtifact: RosterRootArtifact | null = null;
    try {
      const raw = await deps.anchor.readRoot(lc(expected.rosterAdminCCI), expected.rosterId, proof.epoch);
      if (raw === null) {
        indet('root-read', `authoritative root unreadable at (admin, ${expected.rosterId}, epoch ${proof.epoch})`);
      } else if (!isValidRootShape(raw)) {
        // Codex caveat: a malformed root artifact → indeterminate (cannot confirm authority). A
        // structurally-VALID but cryptographically-invalid signed root is handled below as reject.
        indet('root-shape', 'root artifact is malformed (shape/type invalid) — authority unconfirmable');
      } else {
        rootArtifact = raw;
        pass('root-read', `authoritative root read for epoch ${proof.epoch}`);
      }
    } catch (e) {
      indet('root-read', `root read threw: ${(e as Error).message}`);
    }

    if (rootArtifact !== null) {
      const root = rootArtifact;
      /* -- admin binding — verify over FULL tuple by rosterAdminCCI AND tuple fields match. */
      let adminBindingOk = false;
      try {
        const adminSig = hexToBytes(root.adminBinding);
        const tuple = rootSignableTuple(root);
        if (!edVerify(ROOT_SEP, adminSig, jcsCanonical(tuple), adminKey)) {
          rej('admin-binding', 'adminBinding does not verify over the full tuple by rosterAdminCCI');
        } else if (
          lc(root.rosterAdminCCI) !== lc(expected.rosterAdminCCI) ||
          root.rosterId !== expected.rosterId ||
          root.epoch !== proof.epoch
        ) {
          rej(
            'admin-binding',
            `admin tuple mismatch: admin/rosterId/epoch=${root.rosterAdminCCI.slice(0, 8)}…/${root.rosterId}/${root.epoch} ` +
              `expected ${expected.rosterAdminCCI.slice(0, 8)}…/${expected.rosterId}/${proof.epoch}`
          );
        } else {
          adminBindingOk = true;
          pass('admin-binding', 'adminBinding verifies over the full tuple; root tuple matches expected roster+epoch');
        }
      } catch {
        rej('admin-binding', 'adminBinding is not valid hex');
      }

      /* -- leaf + path — recompute leaf, verify path folds to the authoritative root. */
      if (adminBindingOk) {
        let leafCommitment: string | null = null;
        try {
          leafCommitment = memberLeaf(proof.salt, lp);
        } catch (e) {
          rej('leaf-path', `member leaf recompute failed: ${(e as Error).message}`);
        }
        if (leafCommitment !== null) {
          if (!verifyMerklePath(leafCommitment, proof.merklePath, root.root)) {
            rej('leaf-path', 'member leaf does not fold to the authoritative root via the audit path (non-member / tampered path)');
          } else {
            pass('leaf-path', `member leaf folds to the authoritative root for ${expected.rosterId}/${proof.epoch}`);

            /* -- fast-revoke gate — only meaningful once we have a confirmed in-tree leaf. */
            try {
              const revokeState = await deps.revoke.isRevoked(leafCommitment, expected.audience);
              if (!revokeState.readable) {
                indet('revoke-gate', 'revoke ledger unreadable (cannot decide — never a silent pass)');
              } else if (revokeState.revoked) {
                rej('revoke-gate', 'an applicable fast-revoke denies this member for this audience');
              } else {
                pass('revoke-gate', 'no applicable fast-revoke denies this member');
              }
            } catch (e) {
              indet('revoke-gate', `revoke ledger read threw: ${(e as Error).message}`);
            }
          }
        }
      }
    }

    // If epoch authority failed but nothing else rejected, the indeterminate is already recorded.
    void epochAuthorityOk;
  }

  /* -- final precedence (§4): error already returned; any reject → reject; else any indeterminate
   *    → indeterminate; else accept. A reject from an anchor-independent check (e.g. forged member
   *    binding) wins over an indeterminate from an unreadable anchor (F2). */
  return finalize();
}
