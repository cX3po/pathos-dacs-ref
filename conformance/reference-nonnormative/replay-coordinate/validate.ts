/**
 * NON-NORMATIVE reference artifact — SR-4 "replay coordinate" anti-replay capability hook.
 *
 * This is NOT a DACS conformance vector set. It is the concrete reference impl of the proposal we
 * made on DACS-Standard #195 (issuecomment-4847774751): the L2PS nonce-reuse / channel-replay defence
 * is expressible as a black-box conformance hook WITHOUT DACS normatively defining the crypto envelope
 * fields `(channel, epoch, key-id, nonce)` — IF DACS defines a single abstract observable instead:
 *
 *   A conformant substrate emits, per admitted message, an opaque **replay coordinate** — an equality
 *   token that folds whatever anti-replay inputs the substrate uses. The single normative contract is:
 *     "Within one session, two admitted messages MUST NOT share a replay coordinate;
 *      a message whose coordinate was already admitted MUST be rejected."
 *
 * The checker tests the CONTRACT on the opaque token — never the crypto. Same move as §7.5.1's abstract
 * decision and the abstract SR-2 anchor in sealed-envelope: test the property, not the mechanism. If the
 * substrate emits no coordinate, the capability is unobservable → `indeterminate` (NOT a violation).
 *
 * Decision (§7.5.1, never collapsed): pass (fresh coordinate → admit) · fail (coordinate already admitted
 * in this session → MUST-REJECT) · indeterminate (substrate emitted no coordinate — hook unobservable) ·
 * error (malformed: coordinate present but not a well-formed opaque token, or malformed session ctx).
 *
 * Coordinates are compared by EXACT equality; emitting canonical (injective) tokens is the substrate's
 * responsibility, exactly as the envelope crypto is. The token is modelled as a non-empty string.
 *
 * Pure, offline, deterministic, dep-free.  Stays in pathos-dacs-ref; no DACS-Standard PR until #195's
 * "does DACS define the abstract coordinate?" question is settled.
 */

export interface ReplayMessage {
  /** opaque, substrate-emitted equality token; absent/null ⇒ substrate exposes no coordinate. */
  replayCoordinate?: string | null;
  /** carried for realism / labelling; NOT used in the decision (the point is the token is opaque). */
  ref?: string;
}
export interface SessionCtx {
  sessionId: string;
  /** the replay coordinates already ADMITTED in THIS session (session-scoped, not global). */
  admittedCoordinates: string[];
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface ReplayVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

/** a well-formed opaque token is a non-empty string (the substrate's injectivity is its own concern). */
function isCoordinateToken(v: unknown): v is string { return typeof v === 'string' && v.length > 0; }

/**
 * Validate AND materialise the admitted-set in a SINGLE pass: read `length` once and each element exactly
 * once into a local, validate that same local, copy that same local. This makes validation and snapshot the
 * same read, so a hostile proxy cannot return a token during validation and a different one during copy
 * (Codex binding review rounds 1–3, 2026-06-30). Rejects non-arrays, holes (sparse), and non-token elements.
 * Returns a plain dense copy, or null if malformed.
 */
function materializeTokens(a: unknown): string[] | null {
  if (!Array.isArray(a)) return null;
  const len = a.length >>> 0;                                       // read length once
  const copy: string[] = [];
  for (let i = 0; i < len; i++) {
    if (!Object.prototype.hasOwnProperty.call(a, i)) return null;   // reject holes (sparse)
    const v = (a as unknown[])[i];                                  // read element ONCE
    if (!isCoordinateToken(v)) return null;
    copy.push(v);                                                   // copy the SAME local
  }
  return copy;
}
/** intrinsic membership — never trusts a (possibly overridden) instance `.includes`. */
function tokenAdmitted(a: string[], token: string): boolean {
  const len = a.length;
  for (let i = 0; i < len; i++) if ((a as unknown[])[i] === token) return true;
  return false;
}

export function checkReplayCoordinate(msg: ReplayMessage, ctx: SessionCtx): ReplayVerdict {
  const checks: Check[] = [];
  const out = (d: ReplayVerdict['decision']): ReplayVerdict => ({ decision: d, checks });

  // [0] structural — read every field ONCE inside a guarded block and snapshot into plain locals, so a
  // hostile getter/proxy trap (on msg.replayCoordinate or ctx.admittedCoordinates) cannot throw or swap the
  // value out from under a later read. Any throw → malformed artifact → error, never an uncaught crash.
  let snap: { coord: unknown; admitted: string[] } | null = null;
  try {
    if (msg && typeof msg === 'object' && ctx && typeof ctx === 'object' &&
        typeof ctx.sessionId === 'string' && ctx.sessionId.length > 0) {
      const copy = materializeTokens(ctx.admittedCoordinates);   // validate + copy in one pass (read-once)
      if (copy) snap = { coord: msg.replayCoordinate, admitted: copy };  // read coordinate once

    }
  } catch { snap = null; }
  if (!snap) {
    checks.push({ id: 'structural', ok: false, detail: 'malformed message / session ctx (admittedCoordinates must be a dense array of non-empty string tokens)' });
    return out('error');
  }
  checks.push({ id: 'structural', ok: true, detail: 'well-formed session ctx' });

  // [1] coordinate observability — a present-but-malformed token is `error`; an absent token is `indeterminate`
  const c = snap.coord;
  if (c === undefined || c === null) {
    checks.push({ id: 'coordinate-present', ok: null, detail: 'substrate emitted no replay coordinate — capability unobservable (NOT a violation)' });
    return out('indeterminate');
  }
  if (!isCoordinateToken(c)) {
    checks.push({ id: 'coordinate-wellformed', ok: false, detail: 'replayCoordinate present but not a well-formed opaque token (non-empty string)' });
    return out('error');
  }
  checks.push({ id: 'coordinate-wellformed', ok: true, detail: 'opaque coordinate token present' });

  // [2] the contract — within this session, a coordinate already admitted MUST be rejected (exact equality).
  // Operates only on the plain local snapshot — no further proxy/getter reads.
  if (tokenAdmitted(snap.admitted, c)) {
    checks.push({ id: 'replay-coordinate-unique', ok: false, detail: 'replay coordinate already admitted in this session — duplicate, MUST reject (SR-4 anti-replay)' });
    return out('fail');
  }
  checks.push({ id: 'replay-coordinate-unique', ok: true, detail: 'replay coordinate fresh for this session — admit' });
  return out('pass');
}
