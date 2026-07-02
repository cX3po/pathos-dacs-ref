import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { canonicalDecimal, isCanonicalDecimal } from "../decimal.ts";

// DACS-3 (Negotiate) — §8.5.2 listing-conformance validation of an
// AgreementDocument against its referenced listing. The value-independent checks
// (currency, price-band/equality, rail, deliverable, pattern) gate here; the two
// committedAt-relative checks (deadline, validity.notAfter) are re-evaluated
// against the ANCHORED committedAt (the SR-2 timestamp, §8.6), never the
// self-reported generatedAt. Signature presence/validity is CA-1..4, a separate
// category — this module is pure value-conformance.

export type PriceTerm = { amount: string; currency: string };
export type PaymentRailRef = string | { railId: string };
export type DecimalPercent = number | string;

/** Listing pricing model (§8.8): fixed price or a negotiable band around a centre. */
export type ListingPricing =
  | { kind: "fixed"; price: PriceTerm }
  | { kind: "negotiable"; bandCenter: PriceTerm; minPct: DecimalPercent; maxPct: DecimalPercent };
type LegacyFixedListingPricing = { kind: "fixed"; amount: string; currency: string };
type ListingPricingInput = ListingPricing | LegacyFixedListingPricing;
type ListingRef = { listingId: string; version: number; contentHash: string };

/** The agreement's deliverable reference (§8.5): type + canonical hash + optional schema. */
export type DeliverableRef = { deliverableType: string; hash: string; schemaUrl?: string };

/** §8.5: optional reference-price snapshot both parties sign; informational, never agreement-validity-bearing. */
export type PriceAnchor = {
  price: string;
  attestationRef: { contentHash: string } & Record<string, unknown>;
} & Record<string, unknown>;

export type AgreementTerms = {
  price: PriceTerm;
  rail?: PaymentRailRef;
  deliverable: DeliverableRef;
  deadline: number; // unix ms
  priceAnchor?: PriceAnchor;
};

export type AgreementDocument = {
  listingRef?: ListingRef;
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope";
  terms: AgreementTerms;
} & Record<string, unknown>;

export type ListingForValidation = {
  pricing: ListingPricingInput;
  acceptedRails?: string[];
  hasPayPhase?: boolean;
  listingId?: string;
  version?: number;
  listingVersion?: number;
  contentHash?: string;
  offering: { deliverable: { deliverableType: string; hash?: string; schemaUrl?: string } & Record<string, unknown> };
  pattern: "fixed-price" | "rfq" | "sealed-envelope";
  pipeline?: Array<{ kind?: string } & Record<string, unknown>>;
  terms: { deadlineSecAfterCommit: number };
  validity?: { notBefore?: number; notAfter?: number };
};

export type AgreementValidation = { ok: true } | { ok: false; failedAt: string; reason: string; decision?: "reject" | "indeterminate" };

/** DeliverableRef.hash = sha256(canonical_JCS(DeliverableSpec)), hex (§9.3 / §8.5.2). Hashed over the listing's offering.deliverable as anchored. */
export function deliverableSpecHash(spec: Record<string, unknown>): string {
  return sha256Hex(canonicalize(spec));
}

export function listingContentHash(listing: ListingForValidation): string {
  const { contentHash: _contentHash, ...payload } = listing as ListingForValidation & Record<string, unknown>;
  return sha256Hex(canonicalize(withoutSignature(payload)));
}

// ── exact signed-decimal arithmetic over CD-1 strings (BigInt fixed-point) ───
// The §8.5.2 band check is "full-precision decimal" and must not use float. We
// cross-multiply (price×100 vs bandCenter×(100±pct)) so division never appears.

type Dec = { neg: boolean; digits: bigint; scale: number };

function parseDec(raw: string): Dec {
  const c = canonicalDecimal(raw);
  const neg = c.startsWith("-");
  const body = neg ? c.slice(1) : c;
  const [int = "0", frac = ""] = body.split(".");
  return { neg: neg && !(int === "0" && frac === ""), digits: BigInt((int || "0") + frac), scale: frac.length };
}

function fmtDec(neg: boolean, digits: bigint, scale: number): string {
  let s = digits.toString();
  if (scale > 0) {
    s = s.padStart(scale + 1, "0");
    s = s.slice(0, s.length - scale) + "." + s.slice(s.length - scale);
  }
  return canonicalDecimal((neg && digits !== 0n ? "-" : "") + s);
}

function cmpDec(a: string, b: string): number {
  const pa = parseDec(a);
  const pb = parseDec(b);
  const scale = Math.max(pa.scale, pb.scale);
  const sa = (pa.neg ? -1n : 1n) * pa.digits * 10n ** BigInt(scale - pa.scale);
  const sb = (pb.neg ? -1n : 1n) * pb.digits * 10n ** BigInt(scale - pb.scale);
  return sa < sb ? -1 : sa > sb ? 1 : 0;
}

function mulDec(a: string, b: string): string {
  const pa = parseDec(a);
  const pb = parseDec(b);
  return fmtDec(pa.neg !== pb.neg, pa.digits * pb.digits, pa.scale + pb.scale);
}

function addSubDec(a: string, b: string, subtract: boolean): string {
  const pa = parseDec(a);
  const pb = parseDec(b);
  const scale = Math.max(pa.scale, pb.scale);
  const sa = (pa.neg ? -1n : 1n) * pa.digits * 10n ** BigInt(scale - pa.scale);
  const sb = (pb.neg !== subtract ? -1n : 1n) * pb.digits * 10n ** BigInt(scale - pb.scale);
  const sum = sa + sb;
  const neg = sum < 0n;
  return fmtDec(neg, neg ? -sum : sum, scale);
}

/** A finite, non-exponent percentage → CD-1 decimal string. Fractional values in hashed listings should be strings, not JSON numbers. */
function percentToDec(pct: DecimalPercent): string {
  const s = typeof pct === "number" ? String(pct) : pct;
  if (typeof pct === "number" && (!Number.isFinite(pct) || /[eE]/.test(s))) throw new Error(`percentage not a plain finite decimal: ${s}`);
  return canonicalDecimal(s);
}

/** Inclusive negotiable band bounds [lower, upper] as CD-1 strings (§8.5.2). Exposed for golden vectors. */
export function negotiableBand(bandCenter: string, minPct: DecimalPercent, maxPct: DecimalPercent): { lower: string; upper: string } {
  // lower = bandCenter×(100−minPct)/100, upper = bandCenter×(100+maxPct)/100 — divided by 100 = scale shift.
  const lowerX100 = mulDec(bandCenter, addSubDec("100", percentToDec(minPct), true));
  const upperX100 = mulDec(bandCenter, addSubDec("100", percentToDec(maxPct), false));
  // divide by 100: subtract 2 from the implied scale by multiplying by "0.01".
  return { lower: mulDec(lowerX100, "0.01"), upper: mulDec(upperX100, "0.01") };
}

function hasFixedPrice(pricing: ListingPricingInput): pricing is { kind: "fixed"; price: PriceTerm } {
  return pricing.kind === "fixed" && "price" in pricing;
}

function listingPriceCurrency(pricing: ListingPricingInput): string {
  return pricing.kind === "fixed" ? ("price" in pricing ? pricing.price.currency : pricing.currency) : pricing.bandCenter.currency;
}

function listingFixedPrice(pricing: ListingPricingInput): PriceTerm {
  if (pricing.kind !== "fixed") throw new Error("listing pricing is not fixed");
  return hasFixedPrice(pricing) ? pricing.price : { amount: pricing.amount, currency: pricing.currency };
}

function railId(rail: PaymentRailRef | undefined): string | undefined {
  return typeof rail === "string" ? rail : rail?.railId;
}

function isNonNegativePercent(pct: DecimalPercent): boolean {
  try {
    return cmpDec(percentToDec(pct), "0") >= 0;
  } catch {
    return false;
  }
}

function listingDeliverableHash(deliverable: ListingForValidation["offering"]["deliverable"]): string {
  const { hash, ...payload } = deliverable;
  const computed = deliverableSpecHash(payload);
  if (hash !== undefined && hash !== computed) {
    throw new Error("listing offering.deliverable.hash does not match canonical deliverable payload hash");
  }
  return computed;
}

function pipelineHasPayPhase(listing: ListingForValidation): boolean | undefined {
  if (listing.pipeline === undefined) return undefined;
  return listing.pipeline.some((step) => typeof step.kind === "string" && step.kind.startsWith("pay-"));
}

function rejects(failedAt: string, reason: string): AgreementValidation {
  return { ok: false, failedAt, reason, decision: "reject" };
}

function isListingRef(value: unknown): value is ListingRef {
  if (value === null || typeof value !== "object") return false;
  const ref = value as Partial<ListingRef>;
  return typeof ref.listingId === "string" && typeof ref.version === "number" && typeof ref.contentHash === "string";
}

/**
 * §8.5.2 listing-conformance validation. `committedAt` is the anchored SR-2
 * commitment timestamp (§8.6), in unix ms — the objective anti-backdating clock,
 * NOT the agreement's self-reported generatedAt.
 */
export function validateAgreement(
  agreement: AgreementDocument,
  listing: ListingForValidation,
  committedAt: number,
): AgreementValidation {
  const t = agreement.terms;

  if (!isListingRef(agreement.listingRef)) {
    return rejects("listingRef", "agreement.listingRef must include listingId, version, and contentHash");
  }
  if (listing.version !== undefined && listing.listingVersion !== undefined && listing.version !== listing.listingVersion) {
    return rejects("listingRef", "listing.version conflicts with listing.listingVersion");
  }
  const listingVersion = listing.version ?? listing.listingVersion;
  let actualListingHash: string;
  try {
    actualListingHash = listingContentHash(listing);
  } catch (e) {
    return rejects("listingRef", `listing contentHash cannot be computed: ${(e as Error).message}`);
  }
  if (
    listing.listingId === undefined ||
    listingVersion === undefined ||
    agreement.listingRef.listingId !== listing.listingId ||
    agreement.listingRef.version !== listingVersion ||
    agreement.listingRef.contentHash !== actualListingHash
  ) {
    return rejects("listingRef", "agreement.listingRef cannot be bound to the listing id/version/contentHash");
  }

  // Currency equality FIRST — a band/equality comparison across currencies MUST be rejected before any amount compare.
  const listingCurrency = listingPriceCurrency(listing.pricing);
  if (t.price.currency !== listingCurrency) {
    return rejects("currency", `agreement currency ${t.price.currency} != listing ${listingCurrency}`);
  }

  // CD-1 (§8.5.1): a signed AgreementDocument amount must already be in minimal canonical form.
  // Cross-implementation vector adapters may canonicalize external fixture shapes before calling
  // this verifier, but the verifier itself rejects malformed signed economic fields.
  if (!isCanonicalDecimal(t.price.amount)) {
    return rejects("price", "terms.price.amount not CD-1 canonical (§8.5.1)");
  }

  // Price-band / equality (CD-1 full-precision).
  try {
    if (listing.pricing.kind === "fixed") {
      if (cmpDec(t.price.amount, listingFixedPrice(listing.pricing).amount) !== 0) {
        return rejects("price", "fixed price != listed price (CD-1)");
      }
    } else {
      const { bandCenter, minPct, maxPct } = listing.pricing;
      if (!isNonNegativePercent(minPct) || !isNonNegativePercent(maxPct)) {
        return rejects("price", "malformed negotiable band: minPct/maxPct must be plain non-negative percentages");
      }
      const { lower } = negotiableBand(bandCenter.amount, minPct, maxPct);
      if (cmpDec(lower, "0") <= 0) {
        // DACS PriceTerm.amount is strictly positive (§9.3). A negotiable band whose lower edge includes
        // zero/non-positive prices is malformed rather than a valid invitation to negotiate at any positive price.
        return rejects("price", "malformed negotiable band: computed lower bound <= 0");
      }
      if (agreement.derivedFromPattern === "fixed-price" && listing.pattern === "fixed-price") {
        // PS-3: a fixed-price agreement over negotiable pricing MUST equal bandCenter exactly, not merely lie within the band.
        if (cmpDec(t.price.amount, bandCenter.amount) !== 0) {
          return rejects("price", "PS-3: fixed-price over negotiable must equal bandCenter exactly");
        }
      } else {
        // price×100 ≥ bandCenter×(100−minPct) AND price×100 ≤ bandCenter×(100+maxPct) — inclusive, no division.
        const priceX100 = mulDec(t.price.amount, "100");
        const lowerX100 = mulDec(bandCenter.amount, addSubDec("100", percentToDec(minPct), true));
        const upperX100 = mulDec(bandCenter.amount, addSubDec("100", percentToDec(maxPct), false));
        if (cmpDec(priceX100, lowerX100) < 0) return rejects("price", "price below band lower bound");
        if (cmpDec(priceX100, upperX100) > 0) return rejects("price", "price above band upper bound");
      }
    }
  } catch (e) {
    return rejects("price", `price comparison failed: ${(e as Error).message}`);
  }

  // Rail acceptance. §8.5.2(3): rail is present iff the listing pipeline has a pay-* phase.
  const pipelinePayPhase = pipelineHasPayPhase(listing);
  if (pipelinePayPhase !== undefined && listing.hasPayPhase !== undefined && listing.hasPayPhase !== pipelinePayPhase) {
    return rejects("rail", "listing hasPayPhase contradicts pipeline pay-* phases");
  }
  const hasPayPhase = pipelinePayPhase ?? listing.hasPayPhase ?? true;
  const acceptedRails = listing.acceptedRails ?? [];
  if (!hasPayPhase && acceptedRails.length > 0) {
    return rejects("rail", "zero-pay listing cannot advertise acceptedRails");
  }
  const selectedRail = railId(t.rail);
  if (!hasPayPhase) {
    if (selectedRail !== undefined) return rejects("rail", "zero-pay listing forbids terms.rail");
  } else if (selectedRail === undefined) {
    return rejects("rail", "pay-* listing requires terms.rail");
  } else if (!acceptedRails.includes(selectedRail)) {
    return rejects("rail", `rail ${selectedRail} not in listing.acceptedRails`);
  }

  // Deliverable conformance: deliverableType + canonical hash + schemaUrl (both absent, or both present and equal).
  const od = listing.offering.deliverable;
  if (t.deliverable.deliverableType !== od.deliverableType) {
    return rejects("deliverable", "deliverableType != listing offering.deliverable kind");
  }
  try {
    if (t.deliverable.hash !== listingDeliverableHash(od)) {
      return rejects("deliverable", "deliverable hash != listing offering.deliverable hash");
    }
  } catch (e) {
    return rejects("deliverable", `deliverable hash comparison failed: ${(e as Error).message}`);
  }
  const aSchema = t.deliverable.schemaUrl;
  const lSchema = od.schemaUrl;
  if ((aSchema === undefined) !== (lSchema === undefined) || (aSchema !== undefined && aSchema !== lSchema)) {
    return rejects("deliverable", "schemaUrl mismatch");
  }

  // Negotiation pattern.
  if (
    agreement.derivedFromPattern !== listing.pattern &&
    !(agreement.derivedFromPattern === "fixed-price" && listing.pattern === "fixed-price" && listing.pricing.kind === "negotiable")
  ) {
    return rejects("pattern", "derivedFromPattern != listing pipeline pattern");
  }

  if (!Number.isFinite(committedAt)) {
    return { ok: false, failedAt: "committedAt", reason: "committedAt unavailable for post-anchor deadline/expiry checks", decision: "indeterminate" };
  }

  // committedAt-relative checks (anchored committedAt, NOT generatedAt).
  if (t.deadline > committedAt + listing.terms.deadlineSecAfterCommit * 1000) {
    return rejects("deadline", "deadline > committedAt + deadlineSecAfterCommit");
  }
  if (listing.validity?.notAfter !== undefined && listing.validity.notAfter < committedAt) {
    return rejects("notAfter", "listing.validity.notAfter < committedAt (expired between read and commit)");
  }

  // priceAnchor (optional): absence MUST NOT cause rejection; when present, price MUST be CD-1 and
  // attestationRef.contentHash MUST be present. `!= null` treats a JSON `null` the same as absent
  // (a verifier consuming external agreement JSON may see `"priceAnchor": null`) — not a crash.
  if (t.priceAnchor != null) {
    if (!isCanonicalDecimal(t.priceAnchor.price)) {
      return rejects("priceAnchor", "priceAnchor.price not CD-1 canonical");
    }
    if (typeof t.priceAnchor.attestationRef?.contentHash !== "string" || t.priceAnchor.attestationRef.contentHash.length === 0) {
      return rejects("priceAnchor", "priceAnchor.attestationRef.contentHash missing");
    }
  }

  return { ok: true };
}
