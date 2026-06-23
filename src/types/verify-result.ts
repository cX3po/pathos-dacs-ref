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

import type { ClaimRef, VerifyResultRef } from './identity.js';

/**
 * Per §7.5.1 — the four permitted decisions, no implicit boolean coercion.
 *   - pass          : ran cleanly, authority confirmed the claim.
 *   - fail          : ran cleanly, authority conclusively contradicts the claim.
 *   - indeterminate : ran cleanly, response parseable but neither confirms nor contradicts.
 *   - error         : verification could not complete (transport failure, timeout,
 *                     parser cannot consume the response, parser exception, unexpected
 *                     authority API change). The verifier never received a decision.
 * error vs indeterminate is the verifier's failure to obtain an answer vs the authority's
 * answer being non-binary — consumers MUST NOT collapse them (§7.5.1 aggregation semantics).
 */
export type VerifyDecision = 'pass' | 'fail' | 'indeterminate' | 'error';

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
  /** The decision — pass | fail | indeterminate | error, MUST NOT collapse (§7.5.1) */
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

/** §7.7 ComponentSignature — {algorithm, signer (ClaimReference string), value}. */
export interface ComponentSignature {
  algorithm: 'ed25519' | 'ecdsa-secp256k1' | 'sr1-aggregate';
  /** §B.1 ClaimReference, carried as the canonical "Scheme:Identifier" string. */
  signer: string;
  /** Signature over "dacs-composite:v1:" || record_hash (record minus `signature`), §B.7. */
  value: string;
}

/** §7.7 SupplementarySignal — soft reputation/quality signal accompanying a Vet record. */
export interface SupplementarySignal {
  source: 'dacs-5' | 'cci-nomis' | 'cci-ethos' | 'cci-humanpassport' | 'external' | string;
  signalType: string; // e.g. "completion-rate", "dispute-rate", "rating-avg"
  value: number | string;
  observedAt: number;
  attestation?: AttestationRef; // required for "external" sources
}

/** §7.7 WarningCode — enumerated advisory codes aligned to the §7.6.1 retry taxonomy. */
export type WarningCode =
  | 'AUTHORITY_UNAVAILABLE'
  | 'AUTHORITY_RATE_LIMITED'
  | 'DNS_RESOLUTION_FAILED'
  | 'TLS_HANDSHAKE_FAILED'
  | 'RESPONSE_MALFORMED'
  | 'RETRY_EXHAUSTED';

/** §7.7 VerificationWarning — advisory only; MUST NOT affect overallDecision (WN-1). */
export interface VerificationWarning {
  claimRef: string; // §B.1 ClaimReference string
  code: WarningCode;
  retryable: boolean;
  suggestedRetryAfterMs?: number;
}

/**
 * §7.7 CompositeVerificationRecord — aggregated Vet result for a session, signed by the verifier.
 *
 * §7.7.1 aggregation: `overallDecision` is 'pass' iff every required claim has a passing
 * VerifyResult (oneOf within-group precedence error > indeterminate > fail; cross-accumulator
 * fail > error > indeterminate); fail / indeterminate / error NEVER collapse to pass (§7.5.1).
 */
export interface CompositeVerificationRecord {
  recordVersion: '1';
  /** DACS-5 session id */
  jobId: string;
  /** counterparty's primary identity claim (§B.1 ClaimReference string) */
  evaluatedParty: string;
  /** sha256 of the IdentityBundle this Vet ran against */
  bundleHash: string;
  /** sha256 of the listing's BundleRequirement */
  requirementHash: string;
  /** re-verifications of pre-attested claims */
  freshness: VerifyResultRef[];
  supplementary: SupplementarySignal[];
  dealSpecific: VerifyResultRef[];
  overallDecision: VerifyDecision;
  /** advisory only; MUST NOT affect overallDecision (WN-1) */
  warnings?: VerificationWarning[];
  generatedAt: number;
  /** signed by the verifier (§7.7); OMITTED from the hashed canonical form */
  signature: ComponentSignature;
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
export function isError(d: VerifyDecision): d is 'error' {
  return d === 'error';
}
