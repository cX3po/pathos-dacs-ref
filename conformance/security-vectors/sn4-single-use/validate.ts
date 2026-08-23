/**
 * CORE §B.8 SN-4 SINGLE-USE — the consume-on-attempt / reject-reuse branch.
 *
 * RB (steward, 2026-06-22, DACS-Standard#143): SN-4 is a genuine MUST — "consume on attempt, reject any
 * later presentation of the same nonce for that `jobId`", which implies the verifier tracks per-`jobId`
 * consumed state. Our sibling vp-replay validator (PR #18) is stateless ("one expected nonce, no
 * used-nonce ledger"). This dedicated vector covers consume/reject-reuse and bounded lifetime, while
 * retaining the SN-3 issuance binding needed to ensure a nonce from another job never validates here.
 *
 * The verifier maintains a per-jobId consumed-nonce ledger. We model the issued challenge, observation
 * time, and ledger as explicit inputs so each vector is deterministic. Consumption is scoped to
 * `(jobId, nonce)`, but a presentation can use that scope only after proving this verifier issued the
 * nonce for the presented jobId. Merely finding the same bytes under another job never authorizes use.
 *
 * Decision (§7.5.1 do-not-collapse): accept (issued for this job, unexpired, first valid use;
 * verifier marks it consumed on the attempt) · reject (wrong-job issuance, expired challenge, replay,
 * or a later presentation check failing after a valid nonce match)
 * · indeterminate (the challenge/consumption record is unreadable; NEVER assume fresh) · error
 * (malformed input or challenge metadata).
 *
 * SCOPE (non-normative, Codex review): this vector covers the deterministic consume/reuse DECISION
 * semantics only. Passing it does NOT prove a production-safe SN-4 implementation — that additionally
 * requires the consume-if-absent for (jobId,nonce) to be DURABLE and ATOMIC, and the issued/consumed
 * record to remain available until the bound session reaches a terminal state. This set does not
 * claim to prove durable retention; that remains an implementation/harness conformance obligation.
 */

export interface SN4Input {
  jobId?: unknown;
  nonce?: unknown;
  /** Exact challenge provenance retained by the verifier. */
  issuedForJobId?: unknown;
  issuedNonce?: unknown;
  issuedAtMs?: unknown;
  observedAtMs?: unknown;
  challengeLifetimeMs?: unknown;
  /** Models the rest of the presentation after its issued nonce matched. */
  presentationOtherwiseValid?: unknown;
  /** (jobId, nonce) pairs the verifier has already consumed for this session-space. */
  consumedBefore?: unknown;
  /** false ⇒ issued/consumed state could not be read → indeterminate (never assume fresh). */
  recordReadable?: boolean;
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface SN4Verdict {
  decision: 'accept' | 'reject' | 'indeterminate' | 'error';
  checks: Check[];
  /** Null means state was malformed/unreadable and no transition can be claimed. */
  consumedAfter: [string, string][] | null;
  /** True only when this attempt newly consumes the issued challenge. */
  consumedOnAttempt: boolean;
}

export function verifySN4SingleUse(input: SN4Input): SN4Verdict {
  const err = (d: string): SN4Verdict => ({
    decision: 'error',
    checks: [{ id: 'schema', ok: false, detail: `${d} (verifier-side, retryable — never reject)` }],
    consumedAfter: null,
    consumedOnAttempt: false,
  });
  if (typeof input.jobId !== 'string' || input.jobId.length === 0) return err('jobId missing/empty');
  if (typeof input.nonce !== 'string' || input.nonce.length === 0) return err('nonce missing/empty');

  // Fail-safe: an unreadable challenge record cannot prove issuance, lifetime, or single-use.
  if (typeof input.recordReadable !== 'boolean') return err('recordReadable missing/non-boolean');
  if (input.recordReadable === false) {
    return {
      decision: 'indeterminate',
      checks: [{ id: 'challenge-record', ok: null, detail: 'issued/consumed challenge record unreadable — cannot confirm provenance, lifetime, or single-use' }],
      consumedAfter: null,
      consumedOnAttempt: false,
    };
  }

  if (typeof input.issuedForJobId !== 'string' || input.issuedForJobId.length === 0) return err('issuedForJobId missing/empty');
  if (typeof input.issuedNonce !== 'string' || input.issuedNonce.length === 0) return err('issuedNonce missing/empty');
  if (typeof input.issuedAtMs !== 'number' || !Number.isSafeInteger(input.issuedAtMs) || input.issuedAtMs < 0) return err('issuedAtMs missing/invalid');
  if (typeof input.observedAtMs !== 'number' || !Number.isSafeInteger(input.observedAtMs) || input.observedAtMs < 0) return err('observedAtMs missing/invalid');
  if (typeof input.challengeLifetimeMs !== 'number' || !Number.isSafeInteger(input.challengeLifetimeMs) || input.challengeLifetimeMs <= 0) return err('challengeLifetimeMs missing/non-positive');
  if (typeof input.presentationOtherwiseValid !== 'boolean') return err('presentationOtherwiseValid missing/non-boolean');
  if (input.observedAtMs < input.issuedAtMs) return err('observedAtMs precedes issuedAtMs');

  if (!Array.isArray(input.consumedBefore)) return err('consumedBefore missing/non-array');
  const consumed: [string, string][] = [];
  for (const pair of input.consumedBefore) {
    if (!Array.isArray(pair) || pair.length !== 2 ||
        typeof pair[0] !== 'string' || pair[0].length === 0 ||
        typeof pair[1] !== 'string' || pair[1].length === 0) {
      return err('consumedBefore contains malformed entry');
    }
    consumed.push([pair[0], pair[1]]);
  }

  if (input.issuedForJobId !== input.jobId || input.issuedNonce !== input.nonce) {
    return {
      decision: 'reject',
      checks: [{ id: 'issued-challenge', ok: false, detail: 'presented (jobId,nonce) does not equal the verifier-issued challenge for this session' }],
      consumedAfter: consumed,
      consumedOnAttempt: false,
    };
  }

  const already = consumed.some((p) => p[0] === input.jobId && p[1] === input.nonce);
  if (already) {
    return {
      decision: 'reject',
      checks: [{ id: 'single-use', ok: false, detail: `nonce already consumed for jobId "${input.jobId}" — single-use violation (SN-4 replay: same nonce re-presented for the same session)` }],
      consumedAfter: consumed,
      consumedOnAttempt: false,
    };
  }

  // The exact issued nonce is consumed on ATTEMPT before lifetime/downstream outcome.
  const consumedAfter: [string, string][] = [...consumed, [input.jobId, input.nonce]];
  if (input.observedAtMs - input.issuedAtMs > input.challengeLifetimeMs) {
    return {
      decision: 'reject',
      checks: [{ id: 'challenge-lifetime', ok: false, detail: 'verifier-set bounded challenge lifetime elapsed while the session remained pending' }],
      consumedAfter,
      consumedOnAttempt: true,
    };
  }
  if (!input.presentationOtherwiseValid) {
    return {
      decision: 'reject',
      checks: [{ id: 'later-presentation-check', ok: false, detail: 'presentation failed after issued nonce match; challenge remains consumed on attempt' }],
      consumedAfter,
      consumedOnAttempt: true,
    };
  }
  return {
    decision: 'accept',
    checks: [{ id: 'single-use', ok: true, detail: `first valid use of this nonce for jobId "${input.jobId}" — accepted and consumed on attempt` }],
    consumedAfter,
    consumedOnAttempt: true,
  };
}
