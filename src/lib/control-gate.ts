/**
 * control-gate.ts — DACS-1 §6.3.2 step (6) control gate (existence ≠ control).
 *
 * PATH-OS Labs independent implementation, derived from the normative spec — NOT fitted to
 * mj-deving's expected verdicts (that would make a cross-run meaningless). The rules:
 *
 *  - A DACS-2 VerifyResult establishes EXISTENCE/VALIDITY, never CONTROL (DACS-2 §320). A
 *    bare-registry `bindingClass: "existence"` result (e.g. `lei` at GLEIF) is valid-but-uncontrolled:
 *    it MAY satisfy a *required* claim, but MUST NOT be the `presentedBy` / reputation (controlled) claim.
 *  - CONTROL of a claim (DACS-1 §6.3.2 step 6) is proven by ONE of: the bundle presentation signature
 *    for a `key:` claim; the anchored address-key linkage for a `cci-xm:` claim; or a credential
 *    holder-binding proof (§7.3.2). "Control follows the proof, not the storage."
 *  - BR-5 (§6.3.3): when the primary scheme is verification-required, the `presentedBy` claim MUST
 *    ITSELF be verified-and-fresh — a bundle may not launder an unverified primary onto a separately
 *    verified sibling claim.
 *  - Freshness (§6.3.2): an expired primary claim is not-currently-verified → reject.
 *  - Do-not-collapse (§7.5.1): an UNRESOLVABLE control binding is `indeterminate`, never `fail`.
 *
 * Only the `controlled` uses (presentedBy / reputation key) are gated by step 6; steps 1–5 (required-
 * claim satisfaction) accept a valid existence claim. `controlledUse=false` therefore runs the
 * required-claim gate only.
 */

export type Decision = 'pass' | 'fail' | 'indeterminate' | 'error';

export interface Claim {
  ref: string;
  verifiedBy?: string;
  issuedAt?: number;
  expiresAt?: number;
}

export interface Presentation {
  kind?: string;
  signer?: string;
  valid?: boolean;
}

export interface ResolverEntry {
  decision: Decision;
  method?: string;
  bindingClass?: string;   // 'existence' | 'control'
  data?: unknown;
  errorClass?: string;
}

export interface RequirementEntry {
  scheme: string;
  verificationRequired?: boolean;
}

export interface ControlGateInput {
  bundle: {
    presentedBy: string;
    claims: Claim[];
    presentation?: Presentation;
  };
  requirement?: {
    required?: RequirementEntry[];
    primaryClaimSelector?: string;
  };
  reputationKey?: string;
  resolver?: Record<string, ResolverEntry>;
  controlledUse: boolean;
}

export interface ControlGateResult {
  decision: Decision;
  threw: boolean;
  reason: string;
}

const schemeOf = (ref: string): string => (ref.split(':', 1)[0] || '').toLowerCase();
const eqScheme = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * DACS-2 validity signal for a `verifiedBy` binding (used for BR-5 "verified-and-fresh"):
 *   'none' = no binding claimed; 'indeterminate' = claimed but unresolvable (do-not-collapse, §7.5.1);
 *   else the resolver's four-value decision.
 */
function verifySignal(verifiedBy: string | undefined, resolver: Record<string, ResolverEntry>): Decision | 'none' {
  if (!verifiedBy) return 'none';
  const r = resolver[verifiedBy];
  if (!r) return 'indeterminate';        // Codex fix: a CLAIMED but unresolvable binding is indeterminate, never fail
  return r.decision;
}

/**
 * CONTROL signal for a `verifiedBy` binding — control must be POSITIVELY identified (bindingClass
 * 'control'), because DACS-2 validity never establishes control (§320, Codex fix):
 *   'control' = a resolved control binding; 'indeterminate' = claimed but unresolvable;
 *   'error' = the resolver itself errored (do-not-collapse, §7.5.1 — NOT a definite no-control);
 *   'none' = no binding, or a pass that only proves existence/validity (not control).
 * NB: a resolver `fail` IS a definite no-control (correctly folds to 'none' → gate fails), but a
 * resolver `error` is the verifier failing to obtain an answer and MUST NOT collapse to fail.
 */
function controlSignal(verifiedBy: string | undefined, resolver: Record<string, ResolverEntry>): 'control' | 'indeterminate' | 'error' | 'none' {
  if (!verifiedBy) return 'none';
  const r = resolver[verifiedBy];
  if (!r) return 'indeterminate';        // claimed anchored binding, unresolvable → do-not-collapse
  if (r.decision === 'indeterminate') return 'indeterminate';
  if (r.decision === 'error') return 'error';   // do-not-collapse (§7.5.1): resolver error propagates as error
  if (r.decision === 'pass' && r.bindingClass === 'control') return 'control';
  return 'none';                          // pass-but-existence, or a definite fail → no control established
}

/** Required-claim gate (steps 1–5): an existence `pass` satisfies a required claim. */
function requiredClaimGate(input: ControlGateInput): Decision {
  const resolver = input.resolver ?? {};
  for (const r of input.requirement?.required ?? []) {
    if (!r.verificationRequired) continue;
    const claim = input.bundle.claims.find((c) => eqScheme(schemeOf(c.ref), r.scheme));
    const vs = verifySignal(claim?.verifiedBy, resolver);
    if (vs === 'none') return 'fail';
    if (vs === 'indeterminate') return 'indeterminate';
    if (vs === 'error') return 'error';   // do-not-collapse (§7.5.1): a resolver error is not a definite fail
    if (vs !== 'pass') return 'fail';     // a definite 'fail' from the resolver → fail
  }
  return 'pass';
}

/**
 * Classify a control-gate vector. `now` is the evaluation clock (ms) for the freshness gate.
 * Never throws — a malformed input yields `{decision:'error', threw:true}` (the caller distinguishes
 * a graceful `fail` from a thrown `error`, per the vet-control `{decision, throws}` expectation).
 */
export function classifyControlGate(input: ControlGateInput, now: number): ControlGateResult {
  try {
    const resolver = input.resolver ?? {};
    // The controlled claim being gated: `presentedBy`, unless a concrete `reputationKey` names another
    // claim (Codex fix: reputationKey must gate the claim it identifies, not always presentedBy).
    const rk = input.reputationKey;
    const controlledRef = rk && rk !== 'presentedBy' && rk.includes(':') ? rk : input.bundle.presentedBy;
    const cScheme = schemeOf(controlledRef);
    const cClaim = input.bundle.claims.find((c) => c.ref === controlledRef);

    // Not a controlled use → only the required-claim gate applies (existence pass is fine).
    if (!input.controlledUse) {
      return { decision: requiredClaimGate(input), threw: false, reason: 'uncontrolled: required-claim gate only' };
    }

    if (!cClaim) {
      return { decision: 'fail', threw: false, reason: 'controlled claim absent from bundle' };
    }

    // Existence-only bindings structurally cannot confer control (§320) — the METHOD decides,
    // not producer-supplied data (a forged holder-binding on a registry method confers nothing).
    const cRes = cClaim.verifiedBy ? resolver[cClaim.verifiedBy] : undefined;
    if (cRes && cRes.bindingClass === 'existence') {
      return { decision: 'fail', threw: false, reason: 'existence-only binding cannot be a controlled/primary claim (§320)' };
    }

    // Freshness gate (§6.3.2): an expired primary claim is not currently verified.
    if (typeof cClaim.expiresAt === 'number' && cClaim.expiresAt <= now) {
      return { decision: 'fail', threw: false, reason: 'controlled claim expired/stale' };
    }

    // BR-5 applies to the PRIMARY scheme — expressed by primaryClaimSelector, falling back to the
    // controlled claim's own scheme (Codex fix: honour the selector, not only `required`).
    const primaryScheme = input.requirement?.primaryClaimSelector ?? cScheme;
    const reqForPrimary = input.requirement?.required?.find((r) => eqScheme(r.scheme, primaryScheme));

    if (cScheme === 'key') {
      // BR-5: a verification-required primary must ITSELF be verified-and-fresh (no laundering onto a sibling).
      if (reqForPrimary?.verificationRequired) {
        const vs = verifySignal(cClaim.verifiedBy, resolver);
        if (vs === 'none') return { decision: 'fail', threw: false, reason: 'BR-5: presentedBy claim itself unverified (selector-laundering)' };
        if (vs === 'indeterminate') return { decision: 'indeterminate', threw: false, reason: 'presentedBy control binding unresolvable (do-not-collapse)' };
        if (vs === 'error') return { decision: 'error', threw: false, reason: 'presentedBy verification resolver errored (do-not-collapse, §7.5.1)' };
        if (vs !== 'pass') return { decision: 'fail', threw: false, reason: 'presentedBy verification did not pass' };
      }
      // Control proof: the bundle presentation signature (the key signs the bundle).
      const pres = input.bundle.presentation;
      if (pres) {
        const ok = pres.valid === true && pres.signer === controlledRef;
        return { decision: ok ? 'pass' : 'fail', threw: false,
                 reason: ok ? 'key claim control-proven via presentation signature'
                            : 'key presentation signature invalid or signer mismatch — control not proven' };
      }
      // No presentation → control may rest only on a POSITIVELY control-bound resolver (Codex fix).
      const cs = controlSignal(cClaim.verifiedBy, resolver);
      if (cs === 'control') return { decision: 'pass', threw: false, reason: 'key claim control-proven via holder-binding' };
      if (cs === 'indeterminate') return { decision: 'indeterminate', threw: false, reason: 'control binding unresolvable (do-not-collapse)' };
      if (cs === 'error') return { decision: 'error', threw: false, reason: 'key control-binding resolver errored (do-not-collapse, §7.5.1)' };
      return { decision: 'fail', threw: false, reason: 'no control proof for key claim (no presentation, no control binding)' };
    }

    if (cScheme === 'cci-xm') {
      const cs = controlSignal(cClaim.verifiedBy, resolver);
      if (cs === 'control') return { decision: 'pass', threw: false, reason: 'cci-xm anchored address-key linkage' };
      if (cs === 'indeterminate') return { decision: 'indeterminate', threw: false, reason: 'cci-xm linkage unresolvable (do-not-collapse)' };
      if (cs === 'error') return { decision: 'error', threw: false, reason: 'cci-xm linkage resolver errored (do-not-collapse, §7.5.1)' };
      return { decision: 'fail', threw: false, reason: 'cci-xm claim not control-bound' };
    }

    // Any other scheme (e.g. lei) as a controlled claim with no control proof → not control.
    return { decision: 'fail', threw: false, reason: `scheme "${cScheme}" has no control proof under controlled use` };
  } catch (e) {
    return { decision: 'error', threw: true, reason: 'exception: ' + String((e as { message?: string })?.message ?? e) };
  }
}
