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
/**
 * Reference to an anchored attestation: the DACS-2 §7.5.2 wire form, exactly
 * `{ anchor: { kind, locator }, contentHash, signer? }` (spec/DACS-2-VET.md `type AttestationRef`).
 * The pinned dacs-sdk checks these keys exactly; a reference carrying other members (a substrate
 * name, a type, a producedAt) is not an AttestationRef to it and the bundle citing it is not a
 * bundle. Producers that need the attestation kind or time keep them on the cited artifact.
 */
export interface AttestationRef {
    /** Where the bytes are anchored: a Demos storage program (`stor-…`), IPFS, or an HTTPS locator. */
    anchor: {
        kind: 'storage-program' | 'ipfs' | 'https';
        locator: string;
    };
    /** SHA-256 of the anchored bytes; consumer MUST recompute and compare (§7.5.2) */
    contentHash: string;
    /** Expected author when the artifact body does not define its own signer policy. */
    signer?: ClaimRef | string;
}
/**
 * The DAHR bridge's attestation: a spec-form reference plus the bridge's honest-scope marker
 * (`type`, `dahr-stub:` prefixed when the bytes were not fetched through consensus) and the
 * fetch time. It travels inside a VerifyResult; a bundle cites it through a plain AttestationRef.
 */
export interface DahrAttestation extends AttestationRef {
    type: string;
    producedAt: string;
}
/** The v0.2 legacy reference shape (`dacs-5-bundle:0.1` bundles already anchored): read-only compatibility. */
export interface LegacyAttestationRef {
    anchor: {
        substrate?: 'demos' | 'evm' | 'ipfs';
        kind?: 'storage-program' | 'ipfs' | 'https';
        locator: string;
    };
    contentHash: string;
    type?: string;
    producedAt?: string;
    signer?: ClaimRef | string;
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
    attestation?: DahrAttestation;
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
     *   - 'pass' iff every result.decision === 'pass'
     *   - otherwise the aggregate is a non-pass outcome; §7.7.1 ranks the three non-pass
     *     values by context (oneOf within-group: error > indeterminate > fail;
     *     cross-accumulator: fail > error > indeterminate) and NEVER collapses any of
     *     fail / indeterminate / error to pass (§7.5.1 aggregation invariant).
     *
     * NB: fail, indeterminate, and error stay distinct — they do not collapse.
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
export declare function isPass(d: VerifyDecision): d is 'pass';
export declare function isFail(d: VerifyDecision): d is 'fail';
export declare function isIndeterminate(d: VerifyDecision): d is 'indeterminate';
export declare function isError(d: VerifyDecision): d is 'error';
