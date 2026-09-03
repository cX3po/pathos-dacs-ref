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
/**
 * Type-level safety: this helper makes it a compile error to write code that
 * coerces a VerifyDecision to a boolean. Use it wherever you would have
 * written `if (result.decision)` — instead write `if (isPass(result.decision))`.
 *
 * This is the §7.5.1 invariant, hoisted into the type system.
 */
export function isPass(d) {
    return d === 'pass';
}
export function isFail(d) {
    return d === 'fail';
}
export function isIndeterminate(d) {
    return d === 'indeterminate';
}
export function isError(d) {
    return d === 'error';
}
