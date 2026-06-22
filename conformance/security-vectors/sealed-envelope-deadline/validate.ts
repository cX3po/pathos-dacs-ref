/**
 * DACS-3 SEALED-ENVELOPE deadline enforcement — threat-matrix GAP #27 (post-deadline submission,
 * chain-timestamp anchoring). Filed as DACS-Standard#158; 0.2 roadmap candidate (RB invited, 2026-06-22).
 *
 * THREAT (#27): §8.4.3 negotiate-sealed-envelope runs in two timed phases — COMMIT (hash-committed bids,
 * before `commitDeadline`) then REVEAL (after the deadline, within `revealWindow`). A bidder can try to
 * submit/reveal LATE while claiming they were on time. Defense: time the phase by an ANCHORED (chain)
 * timestamp, never a self-claimed one — a commit after `commitDeadline`, a reveal before it (breaks the
 * seal), or a reveal after `commitDeadline + revealWindow` is rejected.
 *
 * Self-contained, dep-free, behaviour-keyed (survives the v0.2 §-renumber). The KEY point is that timing
 * rests on `anchoredTs` ONLY; an absent anchored timestamp is fail-safe `indeterminate` — the validator
 * NEVER falls back to a self-claimed time (that fallback is exactly the hole #27 describes).
 *
 * Decision (§7.5.1 do-not-collapse): accept (anchored time valid for the phase) · reject (post-deadline
 * commit / pre-deadline reveal / post-window reveal) · indeterminate (no anchored timestamp — timing
 * unverifiable; never assume on-time) · error (malformed params: commitDeadline not finite, revealWindow
 * < 60, unknown phase).
 *
 * SCOPE (state narrowly — Codex review): validates PHASE TIMING against a caller-supplied anchored
 * timestamp only. It does NOT verify the commitment hash, that the reveal opens the commitment, bidder
 * identity / replay / uniqueness, that `anchoredTs` was genuinely chain-anchored, nor chain finality /
 * anchor confirmation-depth / proposer drift. It closes the #27 timing-fallback hole ONLY if callers
 * never substitute a self-claimed time and treat ONLY `accept` as valid (`indeterminate` is NOT accepted).
 * Boundary is intentionally asymmetric: ts == commitDeadline is COMMIT phase (accept commit / reject
 * reveal) — internally consistent; inclusive vs exclusive is flagged as a convergence question, not asserted.
 * Out of scope (separate validators): commitDeadline-in-past at setup, revealWindow upper bound,
 * anchoredTs-before-commit-open. Unix-ms inputs are safe-integer; arbitrary huge inputs are not guarded.
 */

export interface SealedTimingInput {
  phase: 'commit' | 'reveal';
  /** The CHAIN-ANCHORED submission timestamp (unix ms). Absent ⇒ indeterminate (never self-claimed). */
  anchoredTs?: number | null;
  /** §8.4.3 commitDeadline (unix ms). */
  commitDeadline: number;
  /** §8.4.3 revealWindow (SECONDS after commitDeadline; MUST be >= 60). */
  revealWindow: number;
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface SealedVerdict { decision: 'accept' | 'reject' | 'indeterminate' | 'error'; checks: Check[] }

const isFiniteNum = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n);

export function verifySealedEnvelopeTiming(input: SealedTimingInput): SealedVerdict {
  const checks: Check[] = [];
  const add = (id: string, ok: boolean | null, detail: string) => { checks.push({ id, ok, detail }); };
  const err = (d: string): SealedVerdict => ({ decision: 'error', checks: [{ id: 'params', ok: false, detail: `${d} (verifier-side, retryable)` }] });

  // ── param gate → error ──
  if (input.phase !== 'commit' && input.phase !== 'reveal') return err(`unknown phase "${String(input.phase)}" (expected commit|reveal)`);
  if (!isFiniteNum(input.commitDeadline)) return err('commitDeadline is not a finite unix-ms number');
  if (!isFiniteNum(input.revealWindow) || input.revealWindow < 60) return err(`revealWindow must be a number >= 60s (got ${String(input.revealWindow)})`);

  // ── the chain-timestamp point: NO anchored timestamp ⇒ indeterminate, never assume on-time ──
  if (!isFiniteNum(input.anchoredTs)) {
    add('anchored-ts', null, 'no anchored (chain) submission timestamp — timing unverifiable; fail-safe (never trust a self-claimed time)');
    return { decision: 'indeterminate', checks };
  }
  const ts = input.anchoredTs as number;
  const windowEnd = input.commitDeadline + input.revealWindow * 1000;

  if (input.phase === 'commit') {
    // commit MUST land at/before the deadline. (boundary ts == commitDeadline treated INCLUSIVE — see note.)
    const ok = ts <= input.commitDeadline;
    add('commit-before-deadline', ok, ok
      ? `commit anchored at ${ts} <= commitDeadline ${input.commitDeadline}`
      : `commit anchored at ${ts} > commitDeadline ${input.commitDeadline} — LATE bid (post-deadline submission)`);
    return { decision: ok ? 'accept' : 'reject', checks };
  }

  // reveal: MUST be strictly after the deadline (reveal before close breaks the seal) AND within the window.
  if (ts <= input.commitDeadline) {
    add('reveal-after-deadline', false, `reveal anchored at ${ts} <= commitDeadline ${input.commitDeadline} — revealed before the commit phase closed (breaks the sealed property)`);
    return { decision: 'reject', checks };
  }
  const inWindow = ts <= windowEnd;
  add('reveal-in-window', inWindow, inWindow
    ? `reveal anchored at ${ts} within (${input.commitDeadline}, ${windowEnd}]`
    : `reveal anchored at ${ts} > revealWindow end ${windowEnd} — post-deadline reveal`);
  return { decision: inWindow ? 'accept' : 'reject', checks };
}
