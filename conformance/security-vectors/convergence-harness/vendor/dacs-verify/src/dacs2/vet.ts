import {
  claimFreshnessAndMaxAgePasses,
  claimFreshnessPasses,
  schemeOf,
  type BundleClaim,
  type BundleRequirement,
  type ClaimRequirement,
  type ClaimReference,
  type IdentityBundle,
  type MatchResult,
} from "../dacs1.ts";
import { cf4Encode } from "../logical-address.ts";
import { canonicalize } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { buildSignedBytes, DOMAIN_SEPARATOR_REGISTRY, verifyEd25519 } from "../signing.ts";

// DACS-2 (Vet) — the verifier-side conformance surface of §7.4/§7.5/§7.6 and the
// §6.3.3 match algorithm. This module covers the read-only checks the spec's §14.2
// test plan groups: the method common contract (CM-1..5), retry semantics
// (VP-R1..4), and the matching algorithm (MA-1..3) — the last extending dacs1's
// presence-only MA-3 to the full `verifiedBy` → resolved-decision check the spec
// mandates. No key handling; recipe authoring / caching / aggregation stay above.

// §7.5.1 — the closed set of VerifyResult decisions (CM-4).
export type VetDecision = "pass" | "fail" | "indeterminate" | "error";
export const VET_DECISIONS: readonly VetDecision[] = ["pass", "fail", "indeterminate", "error"];

/** CM-4: classify a raw decision string against the closed §7.5.1 set; throws on anything else. */
export function classifyVetOutcome(raw: string): VetDecision {
  if ((VET_DECISIONS as readonly string[]).includes(raw)) return raw as VetDecision;
  throw new Error(`§7.5.1 CM-4: outcome must be one of ${VET_DECISIONS.join("/")}, got ${JSON.stringify(raw)}`);
}

// §7.5 — VerifyResult (the subset the contract checks need). `method` is the
// method's own kind (CM-5); `retryClass` drives VP-R1/VP-R3.
export interface VerifyResult {
  decision: VetDecision;
  method: string;
  recipeVersion?: number;
  retryClass?: "transient" | "permanent";
  retryOnIndeterminate?: boolean;
  errorClass?: "permanent" | "transient" | "counterparty";
  data?: Record<string, unknown>;
}

export type ContractResult = { ok: true } | { ok: false; reason: string };

/**
 * CM-1 / CM-3 / CM-5: a conformant VerifyResult MUST have a decision in the
 * closed set and a non-empty `method` set to its own kind. A result missing
 * either is rejected (surfaced as a contract error), never silently passed.
 * When `expectedMethod` is given, CM-5 requires `method === expectedMethod`.
 */
export function validateMethodContract(vr: Partial<VerifyResult>, expectedMethod?: string): ContractResult {
  if (typeof vr.method !== "string" || vr.method.length === 0) {
    return { ok: false, reason: "CM-1/CM-5: VerifyResult.method missing" };
  }
  if (typeof vr.decision !== "string" || !(VET_DECISIONS as readonly string[]).includes(vr.decision)) {
    return { ok: false, reason: "CM-3/CM-4: VerifyResult.decision missing or outside §7.5.1 set" };
  }
  if (expectedMethod !== undefined && vr.method !== expectedMethod) {
    return { ok: false, reason: `CM-5: VerifyResult.method ${vr.method} != produced kind ${expectedMethod}` };
  }
  return { ok: true };
}

/**
 * CM-2: the public anchor address for a DACS-2 attestation —
 * `dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}` (§7.3.1). The scheme is
 * lowercased per CF-2 canonical claim form; the identifier is CF-4 encoded.
 */
export function vetAttestationAddress(jobId: string, scheme: string, identifier: string, recipeVersion: number): string {
  return `dacs2:${jobId}:${scheme.toLowerCase()}:${cf4Encode(identifier)}:v${recipeVersion}`;
}

export function vetCompositeAddress(jobId: string, evaluatedParty: ClaimReference): string {
  return `dacs2:composite:${jobId}:${cf4Encode(evaluatedParty)}`;
}

// §7.6.1 — retry budget default (VP-R1).
export const DEFAULT_RETRY_BUDGET = 3;

export interface RetryContext {
  decision: VetDecision;
  retryClass?: "transient" | "permanent";
  retryOnIndeterminate?: boolean;
  attempts: number; // attestation attempts already made (≥1 after the first)
  retryBudget?: number;
}

/**
 * VP-R1..R4: decide whether the verifier MAY retry.
 *  - VP-R1: decision=error + retryClass=transient → retry while attempts < budget.
 *  - VP-R3: decision=error + retryClass=permanent → never retry within the session.
 *  - VP-R4: decision=indeterminate → retry ONLY if retryOnIndeterminate===true (default false).
 *  - pass/fail are terminal authority answers — never retried.
 * VP-R2 (each retry MUST produce a NEW attestation) is a producer obligation; this
 * predicate only governs the may-retry decision.
 */
export function mayRetry(ctx: RetryContext): boolean {
  const budget = ctx.retryBudget ?? DEFAULT_RETRY_BUDGET;
  if (ctx.attempts >= budget) return false; // VP-R1 budget bound
  switch (ctx.decision) {
    case "error":
      return ctx.retryClass === "transient"; // VP-R1 transient yes; VP-R3 permanent (or unset) no
    case "indeterminate":
      return ctx.retryOnIndeterminate === true; // VP-R4
    case "pass":
    case "fail":
      return false; // terminal authority answer
  }
}

// ── §6.3.3 matching with full verifiedBy → decision resolution ───────────────

/** Resolves a claim's `verifiedBy` reference to the VerifyResult it points at (§6.3.3: decision is read from the resolved result, not the ref). */
export type VerifyResultResolver = (verifiedBy: NonNullable<BundleClaim["verifiedBy"]>) => VerifyResult | null;

function isVerifiedPass(c: BundleClaim, resolve: VerifyResultResolver): boolean {
  if (!c.verifiedBy) return false;
  const vr = resolve(c.verifiedBy);
  return vr != null && vr.decision === "pass";
}

function resolvedVerifyPass(c: BundleClaim, resolve: VerifyResultResolver): VerifyResult | null {
  if (!c.verifiedBy) return null;
  const vr = resolve(c.verifiedBy);
  return vr != null && vr.decision === "pass" ? vr : null;
}

function presentationControlsKeyClaim(bundle: IdentityBundle, claim: BundleClaim): boolean {
  const presentation = bundle.presentation;
  if (presentation === null || typeof presentation !== "object") return false;
  const p = presentation as Record<string, unknown>;
  const publicKeyRaw = keyClaimPublicKey(claim.ref);
  if (publicKeyRaw === null) return false;
  const signedBytes = (() => {
    try {
      return bundlePresentationSignedBytes(bundle);
    } catch {
      return null;
    }
  })();
  if (signedBytes === null) return false;
  switch (p.kind) {
    case "per-claim": {
      if (!Array.isArray(p.signatures)) return false;
      return p.signatures.some((sig) => {
        if (sig === null || typeof sig !== "object") return false;
        const record = sig as Record<string, unknown>;
        return record.ref === claim.ref
          && typeof record.signature === "string"
          && verifiesKeySignature(publicKeyRaw, signedBytes, record.signature);
      });
    }
    case "sr1-root":
      return p.rootClaim === claim.ref
        && typeof p.aggregateSignature === "string"
        && verifiesKeySignature(publicKeyRaw, signedBytes, p.aggregateSignature);
    default:
      return false;
  }
}

function bundlePresentationSignedBytes(bundle: IdentityBundle): Uint8Array {
  const { presentation: _presentation, ...signedScope } = bundle;
  const artifactHash = sha256Hex(canonicalize(signedScope));
  return buildSignedBytes(DOMAIN_SEPARATOR_REGISTRY["dacs-1-bundle-presentation"], artifactHash);
}

function keyClaimPublicKey(ref: ClaimReference): Uint8Array | null {
  const prefix = "key:";
  if (!ref.toLowerCase().startsWith(prefix)) return null;
  const value = ref.slice(prefix.length);
  if (/^[0-9a-f]{64}$/.test(value)) return new Uint8Array(Buffer.from(value, "hex"));
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const publicKeyRaw = new Uint8Array(Buffer.from(value, "base64url"));
  return publicKeyRaw.length === 32 ? publicKeyRaw : null;
}

function verifiesKeySignature(publicKeyRaw: Uint8Array, signedBytes: Uint8Array, signature: string): boolean {
  try {
    const signatureRaw = new Uint8Array(Buffer.from(signature, "base64url"));
    if (signatureRaw.length !== 64) return false;
    return verifyEd25519(publicKeyRaw, signedBytes, signatureRaw);
  } catch {
    return false;
  }
}

function verifyResultProvesClaimControl(claim: BundleClaim, vr: VerifyResult): boolean {
  const scheme = schemeOf(claim.ref);
  if (scheme === "cci-xm") {
    return vr.method === "sr1-link" && vr.data?.sr1ControlLink === true;
  }
  if (scheme === "lei") {
    return vr.method === "vlei-presentation" && vr.data?.holderBinding === true;
  }
  return vr.method === "vc-presentation" && vr.data?.holderBinding === true;
}

/**
 * DACS-1 §6.3.2 step (6): a controlled use of `presentedBy` needs a proof
 * binding the presenter to that identifier. A DACS-2 pass that only confirms a
 * public identifier exists remains valid supporting context, but is not enough
 * for controlled identity or reputation keying.
 */
export function vetControlledPresentedBy(
  bundle: IdentityBundle,
  resolve: VerifyResultResolver,
  now: number,
  selectorRequirement?: ClaimRequirement,
): MatchResult {
  const presented = bundle.claims.find((c) => c.ref === bundle.presentedBy);
  if (!presented) return { ok: false, reason: "controlled presentedBy does not resolve to a claim" };
  const scheme = schemeOf(presented.ref);
  const cr = selectorRequirement ?? { scheme, verificationRequired: scheme !== "key" };
  if (!claimFreshnessAndMaxAgePasses(presented, cr, now)) {
    return { ok: false, reason: "controlled presentedBy claim stale (primary freshness guard)" };
  }
  if (cr.verificationRequired && resolvedVerifyPass(presented, resolve) === null) {
    return { ok: false, reason: "controlled presentedBy verifiedBy does not resolve to decision=pass" };
  }
  if (scheme === "key") {
    return presentationControlsKeyClaim(bundle, presented)
      ? { ok: true }
      : { ok: false, reason: "controlled presentedBy key lacks presentation proof" };
  }
  const vr = resolvedVerifyPass(presented, resolve);
  if (vr === null) {
    return { ok: false, reason: "controlled presentedBy verifiedBy does not resolve to decision=pass" };
  }
  if (!verifyResultProvesClaimControl(presented, vr)) {
    return { ok: false, reason: "controlled presentedBy proof is existence-only" };
  }
  return { ok: true };
}

/**
 * §6.3.3 find_claim, extended: when `verificationRequired`, the claim counts only
 * if its `verifiedBy` RESOLVES to a VerifyResult with decision==="pass" — dacs1's
 * findClaim stops at presence and defers this resolution here.
 */
export function vetFindClaim(
  bundle: IdentityBundle,
  cr: ClaimRequirement,
  resolve: VerifyResultResolver,
  now: number,
): BundleClaim | null {
  for (const c of bundle.claims) {
    if (schemeOf(c.ref) !== cr.scheme.toLowerCase()) continue;
    if (cr.verificationRequired && !isVerifiedPass(c, resolve)) continue;
    if (!claimFreshnessPasses(c, now)) continue;
    if (cr.maxAge !== undefined) {
      if (c.issuedAt === undefined) continue;
      if (now - c.issuedAt > cr.maxAge * 1000) continue;
    }
    return c;
  }
  return null;
}

export type VetAggregationResult = {
  decision: VetDecision;
  errorClass?: "permanent" | "transient" | "counterparty";
};

export function evaluateVetRequirement(
  bundle: IdentityBundle,
  requirement: BundleRequirement,
  resolve: VerifyResultResolver,
  now: number,
): VetAggregationResult {
  const parts: VetAggregationResult[] = [];
  for (const cr of requirement.required) {
    parts.push(classifyClaimRequirement(bundle, cr, resolve, now));
  }
  for (const group of requirement.oneOf ?? []) {
    parts.push(classifyOneOfGroup(bundle, group, resolve, now));
  }
  return classifyAcrossAccumulators(parts);
}

function classifyClaimRequirement(
  bundle: IdentityBundle,
  cr: ClaimRequirement,
  resolve: VerifyResultResolver,
  now: number,
): VetAggregationResult {
  const outcomes: VetAggregationResult[] = [];
  for (const claim of bundle.claims) {
    if (schemeOf(claim.ref) !== cr.scheme.toLowerCase()) continue;
    if (!claimFreshnessPasses(claim, now)) continue;
    if (cr.maxAge !== undefined) {
      if (claim.issuedAt === undefined) continue;
      if (now - claim.issuedAt > cr.maxAge * 1000) continue;
    }
    if (!cr.verificationRequired) return { decision: "pass" };
    if (!claim.verifiedBy) {
      outcomes.push({ decision: "fail", errorClass: "permanent" });
      continue;
    }
    const vr = resolve(claim.verifiedBy);
    if (vr === null) {
      outcomes.push({ decision: "indeterminate" });
      continue;
    }
    if (vr.decision === "pass") return { decision: "pass" };
    outcomes.push({ decision: vr.decision, ...(vr.errorClass !== undefined ? { errorClass: vr.errorClass } : {}) });
  }
  if (outcomes.length === 0) return { decision: "fail", errorClass: "permanent" };
  return classifyWithinOneOf(outcomes);
}

function classifyOneOfGroup(
  bundle: IdentityBundle,
  group: ClaimRequirement[],
  resolve: VerifyResultResolver,
  now: number,
): VetAggregationResult {
  return classifyWithinOneOf(group.map((cr) => classifyClaimRequirement(bundle, cr, resolve, now)));
}

function classifyWithinOneOf(outcomes: VetAggregationResult[]): VetAggregationResult {
  if (outcomes.some((o) => o.decision === "pass")) return { decision: "pass" };
  const error = firstByDecision(outcomes, "error");
  if (error !== undefined) return error;
  const indeterminate = firstByDecision(outcomes, "indeterminate");
  if (indeterminate !== undefined) return indeterminate;
  return { decision: "fail", errorClass: "permanent" };
}

function classifyAcrossAccumulators(parts: VetAggregationResult[]): VetAggregationResult {
  if (parts.length === 0) return { decision: "pass" };
  const fail = firstByDecision(parts, "fail");
  if (fail !== undefined) return { decision: "fail", errorClass: fail.errorClass ?? "permanent" };
  const error = firstByDecision(parts, "error");
  if (error !== undefined) return error;
  const indeterminate = firstByDecision(parts, "indeterminate");
  if (indeterminate !== undefined) return indeterminate;
  return { decision: "pass" };
}

function firstByDecision(outcomes: VetAggregationResult[], decision: VetDecision): VetAggregationResult | undefined {
  return outcomes.find((o) => o.decision === decision);
}

/**
 * §6.3.3 match(bundle, requirement) with MA-1..MA-3 fully resolved:
 *  - MA-1 required + oneOf, each member resolved through vetFindClaim;
 *  - MA-2 presentedBy.scheme must equal primaryClaimSelector;
 *  - MA-3 the resolved presentedBy claim must itself be fresh and verify to decision==="pass"
 *    (the tier-laundering guard — extends dacs1's presence-only check).
 */
export function vetMatch(
  bundle: IdentityBundle,
  requirement: BundleRequirement,
  resolve: VerifyResultResolver,
  now: number,
): MatchResult {
  for (const cr of requirement.required) {
    if (!vetFindClaim(bundle, cr, resolve, now)) return { ok: false, reason: `MA-1 missing required: ${cr.scheme}` };
  }
  for (const group of requirement.oneOf ?? []) {
    if (!group.some((cr) => vetFindClaim(bundle, cr, resolve, now))) {
      return { ok: false, reason: "MA-1 oneOf group unsatisfied" };
    }
  }
  if (requirement.primaryClaimSelector) {
    if (schemeOf(bundle.presentedBy) !== requirement.primaryClaimSelector.toLowerCase()) {
      return { ok: false, reason: "MA-2 presentedBy scheme != primaryClaimSelector" };
    }
    const selectorRequirement = [
      ...requirement.required,
      ...(requirement.oneOf ?? []).flat(),
    ].find((cr) => cr.scheme.toLowerCase() === requirement.primaryClaimSelector!.toLowerCase()) ?? { scheme: requirement.primaryClaimSelector, verificationRequired: false };
    const control = vetControlledPresentedBy(bundle, resolve, now, selectorRequirement);
    if (!control.ok) return { ok: false, reason: `MA-3 ${control.reason}` };
  }
  return { ok: true };
}
