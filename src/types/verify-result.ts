/**
 * DACS-2 Vet — VerifyResult + CompositeVerificationRecord
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §7.5, §7.7
 *
 * **LOAD-BEARING NORMATIVE RULE (§7.5.1):**
 *   decision ∈ {pass, fail, indeterminate}
 *   Consumers MUST NOT treat indeterminate as pass.
 *   Implementations MUST NOT silently coerce ambiguous outcomes to pass.
 *
 * This rule is the single most important conformance check in DACS-2.
 * It is enforced at the TS type level (no boolean coercion) and at the
 * verifier CLI level (separate exit codes for pass / fail / indeterminate).
 */

import type { ClaimRef } from './identity.js';

/** Per §7.5.1 — exactly three permitted decisions, no implicit boolean coercion. */
export type VerifyDecision = 'pass' | 'fail' | 'indeterminate';

/** Reference to an anchored attestation (§7.5.2). */
export interface AttestationRef {
  /** Locator that resolves to the anchored bytes (e.g. "stor-...", or an explorer URL) */
  anchor: {
    substrate: 'demos' | 'evm' | 'ipfs'; // extensible
    locator: string;
  };
  /** SHA-256 of the anchored bytes; consumer MUST recompute and compare (§7.5.2) */
  contentHash: string; // hex
  /** Type of attestation (matches recipeId or method) */
  type: string;
  /** When the attestation was produced (ISO 8601) */
  producedAt: string;
}

/** A single verification's outcome. */
export interface VerifyResult {
  v: 'dacs-2-verify-result:0.1';
  /** The job/session this result belongs to */
  jobId: string;
  /** The claim that was verified */
  claim: ClaimRef;
  /** The recipe used (id@version) */
  recipe: string;
  /** The decision — pass | fail | indeterminate, MUST NOT collapse */
  decision: VerifyDecision;
  /** Reason for the decision (free-text, structured-where-possible) */
  reason: string;
  /** When the verification ran (ISO 8601) */
  runAt: string;
  /** Freshness window declared by the recipe — caller MAY treat as cache validity */
  freshnessSec?: number;
  /** The attestation produced (if the recipe anchors one) */
  attestation?: AttestationRef;
  /** Any supplementary signals (e.g. soft-signal scorers) */
  supplementarySignals?: Record<string, unknown>;
}

/** Aggregated verification across all claims for a session (§7.7). */
export interface CompositeVerificationRecord {
  v: 'dacs-2-composite-verify:0.1';
  jobId: string;
  /** All individual VerifyResults aggregated here */
  results: VerifyResult[];
  /** Aggregate decision per §7.7.1:
   *   - 'pass'         iff every result.decision === 'pass'
   *   - 'fail'         iff any result.decision === 'fail'
   *   - 'indeterminate' iff no 'fail' and at least one 'indeterminate'
   *
   * NB: aggregation keeps fail and indeterminate distinct — they do NOT collapse.
   */
  aggregateDecision: VerifyDecision;
  /** Aggregate produced at (ISO 8601) */
  aggregatedAt: string;
}

/**
 * Type-level safety: this helper makes it a compile error to write code that
 * coerces a VerifyDecision to a boolean. Use it wherever you would have
 * written `if (result.decision)` — instead write `if (isPass(result.decision))`.
 *
 * This is the §7.5.1 invariant, hoisted into the type system.
 */
export function isPass(d: VerifyDecision): d is 'pass' {
  return d === 'pass';
}
export function isFail(d: VerifyDecision): d is 'fail' {
  return d === 'fail';
}
export function isIndeterminate(d: VerifyDecision): d is 'indeterminate' {
  return d === 'indeterminate';
}
