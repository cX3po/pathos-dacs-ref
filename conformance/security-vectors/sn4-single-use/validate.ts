/**
 * CORE §B.8 SN-4 SINGLE-USE — the consume-on-attempt / reject-reuse branch.
 *
 * RB (steward, 2026-06-22, DACS-Standard#143): SN-4 is a genuine MUST — "consume on attempt, reject any
 * later presentation of the same nonce for that `jobId`", which implies the verifier tracks per-`jobId`
 * consumed state. Our sibling vp-replay validator (PR #18) is stateless ("one expected nonce, no
 * used-nonce ledger") and covers SN-4's *reject-not-issued* branch only. This dedicated vector covers
 * the OTHER branch — *consume / reject-reuse* — so the cross-impl matrix shows SN-4 as covered, not
 * silently partial. §14.6 conformance plan already names the same-session-replay branch.
 *
 * The verifier maintains a per-jobId consumed-nonce ledger. We model the ledger as an explicit input
 * (the set consumed BEFORE this presentation) so each vector is deterministic. Single-use is scoped to
 * `(jobId, nonce)` — a nonce consumed for one jobId does not block a different jobId (each session is
 * issued its own nonce per SN-1/SN-3).
 *
 * Decision (§7.5.1 do-not-collapse): accept (fresh — first valid use; verifier then marks it consumed)
 * · reject (the (jobId,nonce) is already consumed — a replayed single-use nonce) · indeterminate (the
 * consumed-ledger is unreadable — cannot confirm single-use; fail-safe, NEVER assume fresh) · error
 * (malformed: missing/empty jobId or nonce).
 *
 * SCOPE (non-normative, Codex review): this vector covers the deterministic consume/reuse DECISION
 * semantics only. Passing it does NOT prove a production-safe SN-4 implementation — that additionally
 * requires the consume-if-absent for (jobId,nonce) to be DURABLE (survives restart) and ATOMIC (no
 * check-then-mark race admitting concurrent double-use). Those are impl/harness properties, not
 * decision-vector properties.
 */

export interface SN4Input {
  jobId?: unknown;
  nonce?: unknown;
  /** (jobId, nonce) pairs the verifier has already consumed for this session-space. */
  consumedBefore?: [string, string][];
  /** false ⇒ the consumed-ledger could not be read → indeterminate (never assume fresh). */
  ledgerReadable?: boolean;
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface SN4Verdict { decision: 'accept' | 'reject' | 'indeterminate' | 'error'; checks: Check[] }

export function verifySN4SingleUse(input: SN4Input): SN4Verdict {
  const err = (d: string): SN4Verdict => ({ decision: 'error', checks: [{ id: 'schema', ok: false, detail: `${d} (verifier-side, retryable — never reject)` }] });
  if (typeof input.jobId !== 'string' || input.jobId.length === 0) return err('jobId missing/empty');
  if (typeof input.nonce !== 'string' || input.nonce.length === 0) return err('nonce missing/empty');

  // fail-safe: an unreadable consumed-ledger cannot confirm single-use → indeterminate, never assume fresh.
  if (input.ledgerReadable === false) {
    return { decision: 'indeterminate', checks: [{ id: 'ledger', ok: null, detail: 'consumed-nonce ledger unreadable — cannot confirm single-use; fail-safe (never assume the nonce is fresh)' }] };
  }
  const consumed = Array.isArray(input.consumedBefore) ? input.consumedBefore : [];
  const already = consumed.some((p) => Array.isArray(p) && p[0] === input.jobId && p[1] === input.nonce);
  if (already) {
    return { decision: 'reject', checks: [{ id: 'single-use', ok: false, detail: `nonce already consumed for jobId "${input.jobId}" — single-use violation (SN-4 replay: same nonce re-presented for the same session)` }] };
  }
  return { decision: 'accept', checks: [{ id: 'single-use', ok: true, detail: `first valid use of this nonce for jobId "${input.jobId}" — accept; verifier MUST now mark (jobId,nonce) consumed` }] };
}
