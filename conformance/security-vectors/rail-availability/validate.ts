/**
 * DACS-4 RAIL-AVAILABILITY pinning — threat-matrix GAP #13 (rail availability-field poisoning,
 * read-before-pin). Filed as DACS-Standard#158; 0.2 roadmap candidate (RB invited picks, 2026-06-22).
 *
 * THREAT (#13): a settlement consumer READS a rail's availability (§9.5) and relies on it, but the
 * field can be POISONED between read and use — most dangerously UPGRADED to look like real settlement
 * (`mocked`/`failed` → `live`) so synthetic/broken evidence is read as value that moved. Defense:
 * PIN the availability at read time; any later artifact MUST carry the SAME value; a post-pin change
 * is rejected, and an absent value is fail-safe (never assumed `live`).
 *
 * Mirrors the §7.4.5 recipe-availability preflight (src/lib/recipe-availability.ts) but for rails, and
 * adds the read-before-PIN comparison that recipe preflight doesn't cover. Self-contained + dep-free so
 * it's portable for cross-impl diffing (RailAvailability values inlined from src/types/settle.ts §9.5).
 *
 * Decision (§7.5.1 do-not-collapse): accept (presented == pinned, recognized) · reject (post-pin
 * change — poisoning; upgrade flagged as the dangerous direction) · indeterminate (presented absent —
 * cannot confirm the pin held; never assume `live`) · error (unrecognized availability value).
 *
 * SCOPE (state tightly — Codex review): this validates PIN-CONSISTENCY of the rail `availability` FIELD
 * only. It does NOT prove the rail actually settled on-chain, nor verify finality, receipt validity,
 * registry signature/version/supersedes, handler correctness, or that mock/devnet evidence carries real
 * value. The favorability RANK below is DIAGNOSTIC ONLY (labels the poison direction) — it has NO effect
 * on the verdict; the verdict is pure exact-match. A downstream relying party MUST treat `indeterminate`
 * as non-success and MUST NOT default an absent availability to `live`.
 */

/** §9.5 RailAvailability values, inlined for portability. Ranked by "favorability" (how much a relying
 *  party would trust it as REAL settled value) — used only to label the poisoning DIRECTION. */
export const RAIL_AVAILABILITY = ['live', 'operator_gated', 'bilateral', 'closed_data', 'mocked', 'disabled', 'failed'] as const;
export type RailAvail = (typeof RAIL_AVAILABILITY)[number];
const KNOWN = new Set<string>(RAIL_AVAILABILITY);
/** Higher = more favorable (more likely read as "real value moved"). `live` is the top of the lattice. */
const RANK: Record<RailAvail, number> = { live: 6, operator_gated: 5, bilateral: 4, closed_data: 3, mocked: 2, disabled: 1, failed: 0 };

export interface Check { id: string; ok: boolean | null; detail: string }
export interface RailVerdict { decision: 'accept' | 'reject' | 'indeterminate' | 'error'; checks: Check[] }

/**
 * @param presented  the rail-availability carried by the artifact under check (e.g. settlement evidence).
 * @param pinned     the rail-availability the consumer READ + pinned at the start (the trusted baseline).
 */
export function verifyRailAvailabilityPin(presented: unknown, pinned: unknown): RailVerdict {
  const checks: Check[] = [];
  const add = (id: string, ok: boolean | null, detail: string) => { checks.push({ id, ok, detail }); };

  // pinned baseline MUST itself be a recognized value (verifier misconfig otherwise → error, never silent).
  if (typeof pinned !== 'string' || !KNOWN.has(pinned)) {
    return { decision: 'error', checks: [{ id: 'pin', ok: false, detail: `pinned rail-availability "${String(pinned)}" is absent/unrecognized — verifier has no trusted baseline (§9.5; retryable)` }] };
  }
  // absent presented → cannot confirm the pin held; fail-safe to indeterminate, NEVER assume live (§9.5).
  if (presented === undefined || presented === null) {
    add('present', null, 'presented rail-availability absent — cannot confirm the pinned read still holds; fail-safe (never assume `live`)');
    return { decision: 'indeterminate', checks };
  }
  // unrecognized presented → error (a value the verifier does not understand is not a reject verdict).
  if (typeof presented !== 'string' || !KNOWN.has(presented)) {
    return { decision: 'error', checks: [{ id: 'present', ok: false, detail: `presented rail-availability "${String(presented)}" not in §9.5 enum (${RAIL_AVAILABILITY.join('|')}) — verifier-side, never reject` }] };
  }
  // the pin check: presented MUST equal pinned. A change is poisoning; an UPGRADE (more favorable than
  // pinned) is the dangerous direction — synthetic/broken evidence dressed up as real settlement.
  if (presented === pinned) {
    add('pin-match', true, `rail-availability "${presented}" matches the pinned read`);
    return { decision: 'accept', checks };
  }
  const dir = RANK[presented as RailAvail] > RANK[pinned as RailAvail] ? 'UPGRADE (poisoned to look like more-real settlement)' : 'downgrade (still a post-pin change — inconsistent)';
  add('pin-match', false, `rail-availability "${presented}" ≠ pinned "${pinned}" — post-pin change: ${dir}`);
  return { decision: 'reject', checks };
}
