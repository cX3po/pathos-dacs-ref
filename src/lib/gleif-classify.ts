import type { VerifyDecision } from '../types/index.js';

/**
 * §7.5.1 GLEIF registration-status → decision mapping (PURE — the deterministic contract the
 * DNO drift-test diffs against; see DACS-Standard convergence issue #146, Mode-A positions).
 *
 * Source-grounded against LEI-CDF 3.1 (DNO convergence, #146) — the deterministic contract the
 * DNO drift-test diffs against:
 *   ISSUED                       → pass
 *   LAPSED, RETIRED              → indeterminate  (lifecycle-end; GLEIF treats as still-valid-but-
 *                                                  not-current — NOT a conclusive contradiction §7.5.1)
 *   ANNULLED, DUPLICATE, CANCELLED → fail         (GLEIF assignment-error states — erroneous /
 *                                                  invalid / non-surviving registration)
 *   anything else (incl MERGED)  → indeterminate  (authority answered; status non-binary; never coerce)
 *
 * `error` (verification could-not-complete) and `not found → fail` are decided upstream in the
 * fetch/parse path, not here — this maps a parsed registration status only.
 */
/**
 * Fetch-level §7.5.1 classification, applied BEFORE reading the registration status:
 *
 *   HTTP 404                         → fail   (true not-found — GLEIF has no record for this
 *                                              LEI; a conclusive negative)
 *   any other non-2xx / error body   → error  (verification could-not-complete: a 429/500/auth/
 *                                              proxy failure means the verifier never obtained an
 *                                              authority decision — it MUST NOT become a `fail`
 *                                              verdict, which would corrupt the #146 drift-diff)
 *   otherwise                         → null   (no fetch-level verdict; proceed to classify the
 *                                              parsed registration status)
 */
export function classifyFetchStatus(
  responseStatus: number,
  hasErrors: boolean,
  errorDetail?: string,
): { decision: VerifyDecision; reason: string } | null {
  if (responseStatus === 404) {
    return { decision: 'fail', reason: `LEI not found at GLEIF (HTTP 404): ${errorDetail ?? 'no record'}` };
  }
  // anything that is not a 2xx success (3xx redirect, 4xx, 5xx) or that carries an errors[]
  // body means the verifier never obtained a clean authority decision → error, never a verdict.
  if (responseStatus < 200 || responseStatus >= 300 || hasErrors) {
    return { decision: 'error', reason: `GLEIF API error (HTTP ${responseStatus}): ${errorDetail ?? 'unspecified error response'}` };
  }
  return null;
}

export function classifyRegistrationStatus(
  regStatus: string | undefined,
  entityName?: string,
): { decision: VerifyDecision; reason: string } {
  if (regStatus === 'ISSUED') {
    return { decision: 'pass', reason: `LEI active (ISSUED), entity="${entityName ?? 'unknown'}"` };
  }
  // Source-grounded against LEI-CDF 3.1 (DNO, #146 convergence) — not model opinion.
  if (regStatus === 'LAPSED' || regStatus === 'RETIRED') {
    // Lifecycle-end states GLEIF treats as still-valid-but-not-current — NOT a conclusive
    // contradiction (§7.5.1). RETIRED moved fail→indeterminate to converge with DNO's LEI-CDF 3.1
    // grounding (it reads like LAPSED: "was valid, no longer current", not "invalid ab initio").
    return { decision: 'indeterminate', reason: `LEI registration status=${regStatus} — lifecycle-end, not a conclusive contradiction (§7.5.1; LEI-CDF 3.1)` };
  }
  if (regStatus === 'ANNULLED' || regStatus === 'DUPLICATE' || regStatus === 'CANCELLED') {
    // GLEIF assignment-error states (erroneous / invalid / non-surviving registration) → conclusive fail.
    return { decision: 'fail', reason: `LEI registration status=${regStatus} — GLEIF assignment-error state (LEI-CDF 3.1)` };
  }
  return { decision: 'indeterminate', reason: `LEI registration status=${regStatus ?? '(absent)'} — neither ISSUED nor a known failure value` };
}
