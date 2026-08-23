import { sha256Hex } from "./hash.ts";
import { canonicalize } from "./canonicalize.ts";
import { cf4Encode } from "./logical-address.ts";

// DACS-1 (Identify) — claim references, bundle matching, listing addressing and
// the validation order. Types are the subset the verifier needs; field names
// track the spec (§6.3).

/** A claim reference string: `<scheme>:<identifier>[?<params>]` (§6.3.1). */
export type ClaimReference = string;

export interface BundleClaim {
  ref: ClaimReference;
  verifiedBy?: { anchor: { kind: string; locator: string }; contentHash: string; recipeVersion: number };
  issuedAt?: number;
  expiresAt?: number;
}
export type VerifyResultRef = NonNullable<BundleClaim["verifiedBy"]>;

export interface IdentityBundle {
  bundleVersion: "1";
  presentedBy: ClaimReference;
  presentedAt: number;
  claims: BundleClaim[];
  presentation: unknown;
}

export interface ClaimRequirement {
  scheme: string;
  verificationRequired: boolean;
  maxAge?: number;
  parameters?: Record<string, unknown>;
}

export interface BundleRequirement {
  requirementVersion: "1";
  required: ClaimRequirement[];
  oneOf?: ClaimRequirement[][];
  preferredPresentation?: "sr1-root" | "per-claim" | "session-key" | "any";
  primaryClaimSelector?: string;
}

export type IdentityTier = "institutional" | "verified" | "self-declared";
export type VerifiedClaimPredicate = (claim: BundleClaim) => boolean;

const INSTITUTIONAL_SCHEMES: ReadonlySet<string> = new Set([
  "lei",
  "finra-crd",
  "sam-uei",
  "fedramp",
  "cmmc",
  "naics",
  "cci-lei",
  "cci-finra-crd",
  "cci-sam-uei",
  "cci-fedramp",
  "cci-cmmc",
  "cci-naics",
]);

/** Extract the scheme component (before the first ":") of a claim reference. */
export function schemeOf(ref: ClaimReference): string {
  const i = ref.indexOf(":");
  if (i < 0) throw new Error(`malformed claim reference (no scheme): ${ref}`);
  // §6.3.1: schemes are case-insensitive on read; normalise to lowercase.
  return ref.slice(0, i).toLowerCase();
}

/** §6.3.3 find_claim: exact scheme equality + verification/freshness gates. */
export function findClaim(
  bundle: IdentityBundle,
  cr: ClaimRequirement,
  now: number,
): BundleClaim | null {
  for (const c of bundle.claims) {
    if (schemeOf(c.ref) !== cr.scheme.toLowerCase()) continue;
    if (cr.verificationRequired && (!c.verifiedBy)) continue; // resolution/decision check is downstream
    if (!claimFreshnessAndMaxAgePasses(c, cr, now)) continue;
    return c;
  }
  return null;
}

/**
 * Reference-verifier freshness pre-gate for §6.3.3 find_claim.
 * The full normative window is resolver-aware (VerifyResult.verifiedAt,
 * validUntil, recipeVersion defaultMaxAgeSec, and authority clamping). This
 * substrate-free helper intentionally enforces only the wrapper fail-closed
 * boundary before maxAge: unknown age is stale; expired claims are stale.
 */
export function claimFreshnessPasses(claim: BundleClaim, now: number): boolean {
  if (claim.issuedAt === undefined && claim.expiresAt === undefined) return false;
  if (claim.issuedAt !== undefined && (!Number.isSafeInteger(claim.issuedAt) || claim.issuedAt > now)) return false;
  if (claim.expiresAt !== undefined && (!Number.isSafeInteger(claim.expiresAt) || now > claim.expiresAt)) return false;
  return true;
}

export function claimFreshnessAndMaxAgePasses(claim: BundleClaim, cr: ClaimRequirement, now: number): boolean {
  if (!claimFreshnessPasses(claim, now)) return false;
  if (cr.maxAge !== undefined) {
    if (claim.issuedAt === undefined) return false;
    if (now - claim.issuedAt > cr.maxAge * 1000) return false;
  }
  return true;
}

export function deriveIdentityTier(
  bundle: IdentityBundle,
  now: number,
  isResolvedVerifiedClaim: VerifiedClaimPredicate = () => false,
): IdentityTier {
  let hasVerifiedClaim = false;
  for (const claim of bundle.claims) {
    if (!isVerifiedAndFreshClaim(claim, now, isResolvedVerifiedClaim)) continue;
    if (INSTITUTIONAL_SCHEMES.has(schemeOf(claim.ref))) return "institutional";
    hasVerifiedClaim = true;
  }
  return hasVerifiedClaim ? "verified" : "self-declared";
}

export function isVerifyResultRef(value: unknown): value is VerifyResultRef {
  if (value === null || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.contentHash !== "string") return false;
  if (!Number.isSafeInteger(v.recipeVersion)) return false;
  if (v.anchor === null || typeof v.anchor !== "object") return false;
  const anchor = v.anchor as Record<string, unknown>;
  return typeof anchor.kind === "string" && anchor.kind.length > 0
    && typeof anchor.locator === "string" && anchor.locator.length > 0;
}

function isVerifiedAndFreshClaim(claim: BundleClaim, now: number, isResolvedVerifiedClaim: VerifiedClaimPredicate): boolean {
  if (!isResolvedVerifiedClaim(claim)) return false;
  return claimFreshnessPasses(claim, now);
}

export type MatchResult = { ok: true } | { ok: false; reason: string };

/** §6.3.3 match(bundle, requirement) — required + oneOf + primaryClaimSelector. */
export function matchRequirement(
  bundle: IdentityBundle,
  requirement: BundleRequirement,
  now: number,
): MatchResult {
  for (const cr of requirement.required) {
    if (!findClaim(bundle, cr, now)) return { ok: false, reason: `missing required: ${cr.scheme}` };
  }
  for (const group of requirement.oneOf ?? []) {
    if (!group.some((cr) => findClaim(bundle, cr, now))) {
      return { ok: false, reason: "oneOf group unsatisfied" };
    }
  }
  if (requirement.primaryClaimSelector) {
    if (schemeOf(bundle.presentedBy) !== requirement.primaryClaimSelector.toLowerCase()) {
      return { ok: false, reason: "presentedBy scheme != primaryClaimSelector" };
    }
    // §6.3.3 step 3b: the resolved presentedBy claim must itself be verified and fresh.
    const presented = bundle.claims.find((c) => c.ref === bundle.presentedBy);
    if (!presented) return { ok: false, reason: "presentedBy does not resolve to a claim" };
    if (!presented.verifiedBy) return { ok: false, reason: "presentedBy claim unverified (tier-laundering guard)" };
    const selectorRequirement = [
      ...requirement.required,
      ...(requirement.oneOf ?? []).flat(),
    ].find((cr) => cr.scheme.toLowerCase() === requirement.primaryClaimSelector!.toLowerCase()) ?? { scheme: requirement.primaryClaimSelector, verificationRequired: false };
    if (!claimFreshnessAndMaxAgePasses(presented, selectorRequirement, now)) {
      return { ok: false, reason: "presentedBy claim stale (primary freshness guard)" };
    }
  }
  return { ok: true };
}

// ── Listing addressing (§6.3.4) ──────────────────────────────────────────────

/** Logical address for a listing (§6.3.4): dacs1:{seller}:{listingId}:v{n}. */
export function listingLogicalAddress(
  sellerPrimaryClaim: ClaimReference,
  listingId: string,
  listingVersion: number,
): string {
  return `dacs1:${cf4Encode(sellerPrimaryClaim)}:${cf4Encode(listingId)}:v${listingVersion}`;
}

/**
 * Native address per the spec's Demos binding (§6.3.4 / §6.2):
 *   native_address := "stor-" + sha256(logical_address)
 * NOTE: research-B finds Demos actually derives
 *   stor-{SHA256(deployer:programName:salt).substring(0,40)}  (40-hex, keyed
 * differently). This function implements the SPEC rule; the divergence is
 * reported as finding DACS-VERIFY-0003 (B4-1).
 */
export function nativeAddressPerSpec(logicalAddress: string): string {
  return "stor-" + sha256Hex(logicalAddress);
}

export const LISTING_SIZE_CAP_BYTES = 16_384; // §6.3.4

export type ValidationStep =
  | "schema"
  | "version-supported"
  | "validity-window"
  | "size-cap"
  | "accepted-rails-conditional";

export interface ListingLike {
  dacsVersion?: string;
  listingId?: string;
  listingVersion?: number;
  validity?: { notBefore: number; notAfter?: number };
  pipeline?: { kind: string }[];
  acceptedRails?: unknown[];
  [k: string]: unknown;
}

export type ListingValidation =
  | { ok: true }
  | { ok: false; failedAt: ValidationStep; reason: string };

/**
 * Listing validation order (§6.3.4) — the substrate-free subset: schema
 * presence, version supported, validity window, 16 KB canonical-size cap, and
 * the conditional acceptedRails rule (required iff the pipeline has a pay-*
 * phase — the intake-only pattern). Signature, revocation, bundle conformance,
 * and signer-resolution steps require keys/substrate and are layered above.
 */
export function validateListingStructure(listing: ListingLike, now: number): ListingValidation {
  if (listing.dacsVersion === undefined || !listing.listingId || typeof listing.listingVersion !== "number") {
    return { ok: false, failedAt: "schema", reason: "missing dacsVersion/listingId/listingVersion" };
  }
  if (listing.dacsVersion !== "1") {
    return { ok: false, failedAt: "version-supported", reason: `unsupported dacsVersion ${listing.dacsVersion}` };
  }
  const v = listing.validity;
  if (!v || typeof v.notBefore !== "number") {
    return { ok: false, failedAt: "schema", reason: "missing validity.notBefore" };
  }
  if (now < v.notBefore || (v.notAfter !== undefined && now > v.notAfter)) {
    return { ok: false, failedAt: "validity-window", reason: "now outside [notBefore, notAfter]" };
  }
  const size = Buffer.byteLength(canonicalize(listing), "utf8");
  if (size > LISTING_SIZE_CAP_BYTES) {
    return { ok: false, failedAt: "size-cap", reason: `canonical size ${size} > ${LISTING_SIZE_CAP_BYTES} (§6.3.4)` };
  }
  const hasPayPhase = (listing.pipeline ?? []).some((p) => p.kind.startsWith("pay-"));
  const hasRails = Array.isArray(listing.acceptedRails) && listing.acceptedRails.length > 0;
  if (hasPayPhase && !hasRails) {
    return { ok: false, failedAt: "accepted-rails-conditional", reason: "pipeline has pay-* but acceptedRails missing/empty (§6.3.4 step 8)" };
  }
  return { ok: true };
}
