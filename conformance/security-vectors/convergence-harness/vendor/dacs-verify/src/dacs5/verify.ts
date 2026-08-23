import { sha256Hex } from "../hash.ts";
import { type ClaimReference } from "../dacs1.ts";
import { cf4Encode } from "../logical-address.ts";
import type { PriceTerm } from "../dacs4/settlement.ts";
import {
  bundleHash,
  verifyBundle,
  type AgreementPriceResolver,
  type AnchoredByRole,
  type AttestationBundle,
  type AttestationRef,
  type BundleDecision,
  type BundleKeyResolver,
  type BundleOutcome,
  type RatingResolver,
} from "./bundle.ts";

export type BundleFetch = (storAddress: string) => AttestationBundle | null | undefined;

export type ConsumptionVerdict = "unified" | "one-sided" | "divergent" | "absent";

export interface ConsumptionResult {
  verdict: ConsumptionVerdict;
  buyer?: { bundle: AttestationBundle; decision: BundleDecision };
  seller?: { bundle: AttestationBundle; decision: BundleDecision };
  abortedBySelfRole?: "buyer" | "seller";
  abortedByOtherRole?: "buyer" | "seller";
}

export type SessionState =
  | "draft"
  | "vet-pending"
  | "vet-completed"
  | "vet-failed"
  | "negotiate-pending"
  | "negotiate-completed"
  | "negotiate-failed"
  | "commit-pending"
  | "commit-completed"
  | "commit-failed"
  | "settle-pending"
  | "settle-completed"
  | "settle-asymmetric"
  | "settle-failed"
  | "rate-pending"
  | "rate-completed"
  | "substrate-failure-paused"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other"
  | "finalised";

export type TerminalState =
  | "finalised"
  | "vet-failed"
  | "negotiate-failed"
  | "commit-failed"
  | "settle-failed"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other";

export type ErrorClass =
  | "permanent"
  | "transient"
  | "counterparty"
  | "substrate"
  | "settlement-atomicity";

export interface ReputationDerivation {
  derivationVersion: "1";
  partyPrimaryClaim: ClaimReference;
  windowStart: number;
  windowEnd: number;
  bundleCount: number;
  metrics: {
    completionRate: number | null;
    counterpartyDisputeRate: number | null;
    averageBuyerRating: number | null;
    averageSellerRating: number | null;
    observedTransactionalVolume: PriceTerm[];
  };
  computedAt: number;
  windowingBasis: "finalisedAt" | "sr2-anchor-timestamp";
  bundleRefs: AttestationRef[];
}

const transitionSet = (states: SessionState[]): ReadonlySet<SessionState> => new Set(states);

const LEGAL_TRANSITIONS: ReadonlyMap<SessionState, ReadonlySet<SessionState>> = new Map([
  ["draft", transitionSet(["vet-pending"])],
  ["vet-pending", transitionSet(["vet-completed", "vet-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["vet-completed", transitionSet(["negotiate-pending"])],
  ["negotiate-pending", transitionSet(["negotiate-completed", "negotiate-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["negotiate-completed", transitionSet(["commit-pending"])],
  ["commit-pending", transitionSet(["commit-completed", "commit-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["commit-completed", transitionSet(["settle-pending"])],
  // §10.3.1 ST-8 (R4-A): settle-pending may enter the non-terminal `settle-asymmetric` on the HTLC-9
  // dest-revealed-source-unclaimed condition (in addition to the prior settle-completed/-failed/abort/pause edges).
  ["settle-pending", transitionSet(["settle-completed", "settle-asymmetric", "settle-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  // §10.3.1 ST-8/R6-6: from settle-asymmetric, htlc-claim finality resolves to settle-completed; window expiry
  // goes to settle-failed; SR-2 unavailability while anchoring the :resolved record may pause and later resume.
  ["settle-asymmetric", transitionSet(["settle-completed", "settle-failed", "substrate-failure-paused"])],
  ["settle-completed", transitionSet(["rate-pending", "finalised"])],
  ["rate-pending", transitionSet(["rate-completed", "finalised"])],
  ["rate-completed", transitionSet(["finalised"])],
  ["substrate-failure-paused", transitionSet(["vet-pending", "negotiate-pending", "commit-pending", "settle-pending", "settle-asymmetric", "failed-substrate"])],
]);

export const TERMINAL_STATES: ReadonlySet<SessionState> = new Set([
  "finalised",
  "vet-failed",
  "negotiate-failed",
  "commit-failed",
  "settle-failed",
  "failed-substrate",
  "aborted-by-self",
  "aborted-by-other",
]);

export function bundleAddress(jobId: string, role: "buyer" | "seller" | "orchestrator"): string {
  // §10.4.2: each role anchors at stor-{sha256(jobId + "-bundle-" + role)}.
  return `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`;
}

export function ratingAddress(jobId: string, rater: ClaimReference): string {
  return `dacs5:rating:${jobId}:${cf4Encode(rater)}`;
}

export function twoSidedLookup(jobId: string, fetch: BundleFetch): { buyer?: AttestationBundle; seller?: AttestationBundle } {
  const buyer = fetch(bundleAddress(jobId, "buyer"));
  const seller = fetch(bundleAddress(jobId, "seller"));
  const result: { buyer?: AttestationBundle; seller?: AttestationBundle } = {};
  // §10.4.3(a): consumers MUST fetch both party-specific bundle addresses. The fetched bundle's embedded jobId MUST
  // match the looked-up jobId — the address is jobId-derived (§10.4.2), so a bundle for another session returned at
  // this address (replay / misreturn) is ignored, not consumed.
  // §10.4.2 (R5-1, b26a420): `anchoredByRole` is excluded from the bundle hash, so the SIGNATURE no longer binds it.
  // Integrity of the field is instead an ADDRESS CROSS-CHECK: a copy fetched from the role-derived address MUST carry
  // anchoredByRole === that role; a consumer MUST reject a copy whose anchoredByRole does not match the address it was
  // fetched from (else a copy could be relabelled to flip derive()'s §10.5.1 perspective read). Mismatch → not consumed.
  if (buyer !== null && buyer !== undefined && buyer.jobId === jobId && buyer.anchoredByRole === "buyer") result.buyer = buyer;
  if (seller !== null && seller !== undefined && seller.jobId === jobId && seller.anchoredByRole === "seller") result.seller = seller;
  return result;
}

// §10.4.2/§10.11: a bundle at a role's address is that role's bundle ONLY if the EXTERNALLY-KNOWN party for that role
// (from the session/agreement the consumer is auditing) is a signer. The bundle's own `parties` role labels are
// untrusted — a signer can relabel its own claim into the "buyer" slot — so anchoring binds to the expected claim, NOT
// to the self-declared role. The §10.11 abort outcome is recorded from the signer's perspective, so a misattributed
// anchor would flip abort provenance and corrupt reputation.
function signedBy(bundle: AttestationBundle, expectedClaim: ClaimReference): boolean {
  return bundle.signatures.some((s) => s.party === expectedClaim);
}

export function consumeBundles(
  jobId: string,
  fetch: BundleFetch,
  resolveKey: BundleKeyResolver,
  expected: { buyer: ClaimReference; seller: ClaimReference },
): ConsumptionResult {
  const fetched = twoSidedLookup(jobId, fetch);
  // A side counts as present (for the verdict and abort provenance) ONLY if the expected party for that role is a signer
  // AND the bundle cryptographically verifies (decision "pass"). Storage is untrusted: a relabelled, merely-claimed, or
  // forged/unverifiable bundle MUST NOT drive abort provenance or reputation.
  const buyerDecision = fetched.buyer !== undefined && signedBy(fetched.buyer, expected.buyer) ? verifyBundle(fetched.buyer, resolveKey) : undefined;
  const sellerDecision = fetched.seller !== undefined && signedBy(fetched.seller, expected.seller) ? verifyBundle(fetched.seller, resolveKey) : undefined;
  const found: { buyer?: AttestationBundle; seller?: AttestationBundle } = {};
  // buyerDecision is only "pass" when fetched.buyer was defined and verified (see above), so the assertion is sound.
  if (buyerDecision === "pass") found.buyer = fetched.buyer!;
  if (sellerDecision === "pass") found.seller = fetched.seller!;

  if (found.buyer === undefined && found.seller === undefined) {
    // §10.4.3(a): neither expected address yielded a bundle for this session.
    return { verdict: "absent" };
  }

  if (found.buyer !== undefined && found.seller === undefined) {
    // §10.4.3(b)/§10.11: missing side is aborted-by-self; present signer is aborted-by-other.
    return {
      verdict: "one-sided",
      buyer: { bundle: found.buyer, decision: buyerDecision! },
      abortedBySelfRole: "seller",
      abortedByOtherRole: "buyer",
    };
  }

  if (found.buyer === undefined && found.seller !== undefined) {
    // §10.4.3(b)/§10.11: missing side is aborted-by-self; present signer is aborted-by-other.
    return {
      verdict: "one-sided",
      seller: { bundle: found.seller, decision: sellerDecision! },
      abortedBySelfRole: "buyer",
      abortedByOtherRole: "seller",
    };
  }

  const buyer = found.buyer!;
  const seller = found.seller!;
  const buyerEntry = { bundle: buyer, decision: buyerDecision! };
  const sellerEntry = { bundle: seller, decision: sellerDecision! };

  if (bundleHash(buyer) === bundleHash(seller)) {
    // §10.4.3(c): canonically equal bundles are the unified session bundle.
    return { verdict: "unified", buyer: buyerEntry, seller: sellerEntry };
  }

  // §10.4.3(d): canonically divergent bundles are a consumer-side disputed verdict;
  // both bundles stand on their own signatures for per-party policy.
  return { verdict: "divergent", buyer: buyerEntry, seller: sellerEntry };
}

export function isLegalTransition(from: SessionState, to: SessionState): boolean {
  // ST-1/ST-6/ST-7 (§10.3.1): only table-listed forward transitions are legal,
  // except substrate-failure-paused resume to the paused pending phase or failed-substrate.
  return LEGAL_TRANSITIONS.get(from)?.has(to) ?? false;
}

export function stateToOutcome(state: TerminalState, errorClass?: ErrorClass): BundleOutcome | null;
export function stateToOutcome(state: SessionState, errorClass?: ErrorClass): BundleOutcome | null;
export function stateToOutcome(state: SessionState, errorClass?: ErrorClass): BundleOutcome | null {
  switch (state) {
    case "finalised":
      // §10.3.1: finalised maps to completed.
      return "completed";
    case "failed-substrate":
      // §10.3.1: failed-substrate maps to failed-substrate.
      return "failed-substrate";
    case "aborted-by-self":
      // §10.3.1: aborted-by-self maps to aborted-by-self.
      return "aborted-by-self";
    case "aborted-by-other":
      // §10.3.1: aborted-by-other maps to aborted-by-other.
      return "aborted-by-other";
    case "vet-failed":
    case "negotiate-failed":
    case "commit-failed":
    case "settle-failed":
      if (errorClass === "permanent" || errorClass === "transient") {
        // §10.3.1: permanent failures and exhausted transient failures map to failed-perm.
        return "failed-perm";
      }
      if (errorClass === "counterparty" || errorClass === "settlement-atomicity") {
        // §10.3.1: counterparty and settlement-atomicity failures map to failed-counterparty.
        return "failed-counterparty";
      }
      // §10.3.1: terminal phase-failed states need a specified mapped error class.
      return null;
    default:
      // ST-6 (§10.3.1): non-terminal states do not derive bundle outcomes.
      return null;
  }
}

export interface ReputationResolvers {
  // §10.5.1 fetch_and_verify_rating: returns the verified RatingRecord, or null on unreadable/mismatched/invalid
  // (the spec's "exclude" path). Signature + anchor verification live HERE; derive() does the binding/range/dedup.
  resolveRating?: RatingResolver;
  // §10.5.1 fetch_and_verify_agreement: returns the verified DACS-3 agreement price, or null to exclude that bundle.
  resolveAgreement?: AgreementPriceResolver;
}

// §10.5.1 perspective_flip — re-interpret a counterparty-anchored bundle's `outcome` relative to the SCORED party.
// completed / failed-substrate are perspective-invariant; the abort and perm/counterparty faults swap so the
// aborter/at-fault party takes the hit and the victim does not (the §10.11 guarantee R4-B restored).
function perspectiveFlip(o: BundleOutcome): BundleOutcome {
  switch (o) {
    case "aborted-by-self":
      return "aborted-by-other";
    case "aborted-by-other":
      return "aborted-by-self";
    case "failed-perm":
      return "failed-counterparty";
    case "failed-counterparty":
      return "failed-perm";
    case "completed":
      return "completed";
    case "failed-substrate":
      return "failed-substrate";
  }
}

const REPUTATION_PARTY_ROLES: ReadonlySet<AnchoredByRole> = new Set(["buyer", "seller"]);
const TERMINAL_REPUTATION_OUTCOMES: ReadonlySet<BundleOutcome> = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
]);

function hasRequiredTerminalSigners(bundle: AttestationBundle): boolean {
  if (!TERMINAL_REPUTATION_OUTCOMES.has(bundle.outcome)) return true;

  const required = new Set<ClaimReference>();
  for (const party of bundle.parties) {
    if (party.role === "buyer" || party.role === "seller") required.add(party.primaryClaim);
  }
  if (required.size < 2) return false;

  const present = new Set(bundle.signatures.map((signature) => signature.party));
  for (const claim of required) {
    if (!present.has(claim)) return false;
  }
  return true;
}

// §10.4.3(d)/§10.5.1 guard (ii): two copies of one jobId "canonically diverge" only when they CONTRADICT each other
// about what happened — NOT when they merely record the same event from each anchorer's perspective. The ONLY field a
// two-sided pair legitimately records differently per anchorer is the top-level `outcome` (each anchorer states the
// abort/fault from its own side); the buyer↔seller involution `perspective_flip` (aborted-by-self↔aborted-by-other,
// failed-perm↔failed-counterparty) maps one frame onto the other. `selfCopy` is already in the scored party's frame, so
// the counterparty copy AGREES iff `selfCopy.outcome === perspectiveFlip(counterpartyCopy.outcome)`. Comparing raw
// `outcome` would falsely flag a perspective-consistent abort pair (seller `aborted-by-self` vs buyer `aborted-by-other`)
// as a dispute and wrongly exclude a clean session. The `phaseSummary` IS in the §10.4.1 shared canonical form (both
// anchorers record it identically — it is a factual description of each phase, not a per-party fault attribution), so it
// is compared RAW: any difference in a phase entry's `outcome` or `errorClass` is a genuine contradiction → divergence.
// Advisory-field skew (finalisedAt, ratingRefs, amendment order) is intentionally NOT compared — it is not a divergence.
function canonicallyDiverges(selfCopy: AttestationBundle, counterpartyCopy: AttestationBundle): boolean {
  if (selfCopy.outcome !== perspectiveFlip(counterpartyCopy.outcome)) return true;
  if (selfCopy.phaseSummary.length !== counterpartyCopy.phaseSummary.length) return true;
  for (let i = 0; i < selfCopy.phaseSummary.length; i += 1) {
    const left = selfCopy.phaseSummary[i]!;
    const right = counterpartyCopy.phaseSummary[i]!;
    if (left.outcome !== right.outcome || left.errorClass !== right.errorClass) return true;
  }
  return false;
}

export function deriveReputation(
  party: ClaimReference,
  resolvePartyRole: (jobId: string) => AnchoredByRole | undefined,
  bundles: AttestationBundle[],
  windowStart: number,
  windowEnd: number,
  computedAt: number,
  resolvers: ReputationResolvers = {},
): ReputationDerivation {
  // §10.5.1 derive(party, bundles, windowStart, windowEnd). CONTRACT: `bundles` are VERIFIED, consume-produced session
  // bundles — verification is the §10.4.3 consumption boundary (consumeBundles gates on verifyBundle "pass"). derive() is
  // still the METRIC boundary, so it re-asserts the §10.5.1 reconciliation guards locally: non-abort copies missing the
  // buyer/seller signer set are dropped, canonically divergent self/counterparty copies are excluded, and only buyer/seller
  // anchored copies can contribute a reputation perspective. `resolvePartyRole(jobId)` is the EXTERNALLY-KNOWN role the
  // scored party plays in THAT session (buyer/seller) — the consumer always knows it from the audited session/agreement,
  // exactly as consumeBundles takes `expected`. It is PER-JOB on purpose: a party can be the buyer in some sessions and the
  // seller in others within one window, so a single derivation-wide role would misread the off-role sessions. The spec
  // algorithm reads role_of_party from copies[0].parties, but those labels are producer-signed and UNTRUSTED (§10.4.2/§10.11):
  // a verified-but-relabelled bundle could otherwise misname the party's role, miss its self_copy, and perspective_flip its
  // own outcome — inverting abort attribution. So role comes from `resolvePartyRole`, not the bundle. A job whose role the
  // consumer does not supply (undefined) is not in the audited set → skipped. (`anchoredByRole` is trusted here per the
  // §10.4.2 contract that it matches the role-derived anchor address, validated when fetched two-sided.)
  // WINDOW: inclusive `finalisedAt` filter. SCOPED: every bundle the party is a PARTY to (NOT only the ones it anchored —
  // that pre-R4-B narrowing was the defect). Two-sided anchoring (§10.4.2) can place TWO copies of one jobId in the input,
  // each recording `outcome` from ITS anchorer's perspective; the per-jobId reconciliation below collapses to one
  // authoritative, perspective-adjusted outcome per jobId so an abort is counted once and attributed to the aborter.
  const scoped: AttestationBundle[] = [];
  for (const b of bundles) {
    if (!b.parties.some((p) => p.primaryClaim === party)) continue;
    if (b.finalisedAt < windowStart || b.finalisedAt > windowEnd) continue;
    scoped.push(b);
  }

  // Per-jobId reconciliation (§10.5.1 L3242): one authoritative bundle + perspective-adjusted outcome per jobId.
  const groups = new Map<string, AttestationBundle[]>();
  for (const b of scoped) {
    const g = groups.get(b.jobId);
    if (g === undefined) groups.set(b.jobId, [b]);
    else g.push(b);
  }
  const reconciled: AttestationBundle[] = [];
  const outcomes: BundleOutcome[] = [];
  for (const copies of groups.values()) {
    // role the scored party plays in THIS job, from the externally-known per-job binding (NOT self-declared parties).
    const role = resolvePartyRole(copies[0]!.jobId);
    if (role === undefined) continue; // job not in the consumer's audited set → not scored.
    if (!REPUTATION_PARTY_ROLES.has(role)) continue; // §10.5.1 guard (iii): orchestrator reputation is out of scope.
    const usableCopies = copies.filter((bundle) => hasRequiredTerminalSigners(bundle));
    if (usableCopies.length === 0) continue; // §10.5.1 guard (i): single-signed non-abort copies are dropped.
    // self_copy = the party's OWN anchored copy for this job, identified by that trusted role.
    const selfCopy = usableCopies.find((b) => b.anchoredByRole === role);
    const counterpartyCopy = usableCopies.find((b) => REPUTATION_PARTY_ROLES.has(b.anchoredByRole) && b.anchoredByRole !== role);
    if (selfCopy !== undefined && counterpartyCopy !== undefined && canonicallyDiverges(selfCopy, counterpartyCopy)) {
      continue; // §10.5.1 guard (ii): contradictory self/counterparty copies exclude the whole jobId from all metrics.
    }
    if (selfCopy !== undefined) {
      // The scored party's OWN anchored copy is present → `outcome` is read literally.
      reconciled.push(selfCopy);
      outcomes.push(selfCopy.outcome);
    } else if (counterpartyCopy !== undefined) {
      // Only a counterparty-anchored copy exists (e.g. §10.11 suppression) → re-interpret via perspective_flip.
      reconciled.push(counterpartyCopy);
      outcomes.push(perspectiveFlip(counterpartyCopy.outcome));
    }
  }

  const ordered = reconciled
    .map((bundle, i) => ({ bundle, outcome: outcomes[i]!, contentHash: bundleHash(bundle) }))
    .sort((a, b) => a.contentHash.localeCompare(b.contentHash));
  const orderedBundles = ordered.map((entry) => entry.bundle);
  const orderedOutcomes = ordered.map((entry) => entry.outcome);

  const completed = orderedOutcomes.filter((o) => o === "completed").length;
  const failedCounterparty = orderedOutcomes.filter((o) => o === "failed-counterparty").length;
  const failedSubstrate = orderedOutcomes.filter((o) => o === "failed-substrate").length;
  const abortedByOther = orderedOutcomes.filter((o) => o === "aborted-by-other").length;
  const partyFaultDenom = orderedOutcomes.length - failedSubstrate;
  const counterpartyFaultCount = abortedByOther + failedCounterparty;

  const { averageBuyerRating, averageSellerRating } = aggregateRatings(orderedBundles, party, resolvers.resolveRating);
  const observedTransactionalVolume = aggregateVolume(orderedBundles, resolvers.resolveAgreement);
  const bundleRefs = ordered
    .map(({ bundle, contentHash }) => ({
      kind: "dacs-5-bundle",
      id: bundle.jobId,
      contentHash,
    }));

  return {
    derivationVersion: "1",
    partyPrimaryClaim: party,
    windowStart,
    windowEnd,
    bundleCount: reconciled.length,
    metrics: {
      completionRate: partyFaultDenom > 0 ? completed / partyFaultDenom : null,
      counterpartyDisputeRate: partyFaultDenom > 0 ? counterpartyFaultCount / partyFaultDenom : null,
      averageBuyerRating,
      averageSellerRating,
      observedTransactionalVolume,
    },
    computedAt,
    windowingBasis: "finalisedAt",
    bundleRefs,
  };
}

// §10.5.1 (L3285) + Rating de-duplication (L3344): walk each reconciled bundle's ratingRefs; bind each fetched record
// to the session; aggregate AT MOST ONE rating per (rater, jobId, targetRole) — last-writer-wins by ratedAt — then
// average only those whose target is the scored party, split by targetRole. Null (no signal) when none qualify.
function aggregateRatings(
  reconciled: AttestationBundle[],
  party: ClaimReference,
  resolveRating: RatingResolver | undefined,
): { averageBuyerRating: number | null; averageSellerRating: number | null } {
  if (resolveRating === undefined) return { averageBuyerRating: null, averageSellerRating: null };
  const deduped = new Map<string, { value: number; target: ClaimReference; targetRole: "buyer" | "seller"; ratedAt: number }>();
  for (const b of reconciled) {
    const parties = new Set(b.parties.map((p) => p.primaryClaim));
    for (const ratingRef of b.ratingRefs ?? []) {
      const r = resolveRating(ratingRef);
      if (r === null) continue;                                   // fetch_and_verify failed → exclude
      if (r.jobId !== b.jobId) continue;                          // not this session
      if (!Number.isInteger(r.value) || r.value < 1 || r.value > 5) continue; // RT-2: out-of-range excluded
      if (!parties.has(r.rater)) continue;                        // rater was not a party here
      if (r.rater === party) continue;                            // no self-rating toward one's own score
      const key = JSON.stringify([r.rater, r.jobId, r.targetRole]);
      const prior = deduped.get(key);
      if (prior === undefined || r.ratedAt >= prior.ratedAt) {    // last-writer-wins by ratedAt (ties: later wins)
        deduped.set(key, { value: r.value, target: r.target, targetRole: r.targetRole, ratedAt: r.ratedAt });
      }
    }
  }
  const seller: number[] = [];
  const buyer: number[] = [];
  for (const r of deduped.values()) {
    if (r.target !== party) continue;
    if (r.targetRole === "seller") seller.push(r.value);
    else buyer.push(r.value);
  }
  return {
    averageSellerRating: seller.length > 0 ? seller.reduce((a, v) => a + v, 0) / seller.length : null,
    averageBuyerRating: buyer.length > 0 ? buyer.reduce((a, v) => a + v, 0) / buyer.length : null,
  };
}

// §10.5.1 (L3327): sum agreement.terms.price by currency over reconciled bundles whose agreementRef resolves. The
// DACS-3 fetch+hash-verify+parse lives in the injected resolver (caller-supplied / L4 DACS-3 verifier); a null result
// excludes that bundle. Without a resolver, volume is empty (no signal). Amounts are CD-1 canonical decimals.
function aggregateVolume(reconciled: AttestationBundle[], resolveAgreement: AgreementPriceResolver | undefined): { amount: string; currency: string }[] {
  if (resolveAgreement === undefined) return [];
  const byCurrency = new Map<string, bigint>();   // currency → summed value scaled to SCALE fractional digits
  const order: string[] = [];
  for (const b of reconciled) {
    if (b.agreementRef === undefined) continue;
    const price = resolveAgreement(b.agreementRef);
    if (price === null) continue;
    const scaled = scaleDecimal(price.amount);
    if (scaled === null) continue;                  // unparseable amount → exclude
    if (!byCurrency.has(price.currency)) order.push(price.currency);
    byCurrency.set(price.currency, (byCurrency.get(price.currency) ?? 0n) + scaled);
  }
  return order.map((currency) => ({ amount: unscaleDecimal(byCurrency.get(currency)!), currency }));
}

// Fixed-scale decimal arithmetic for volume summation. SCALE digits of fraction is ample for on-chain asset amounts
// (18-decimal ERC-20s included); inputs are CD-1 canonical (no sign/exponent), so parsing is a split on ".".
const VOLUME_SCALE = 18;
function scaleDecimal(amount: string): bigint | null {
  if (!/^\d+(\.\d+)?$/.test(amount)) return null;
  const [intPart, fracPart = ""] = amount.split(".");
  if (fracPart.length > VOLUME_SCALE) return null; // more precision than we track → refuse rather than truncate
  const padded = fracPart.padEnd(VOLUME_SCALE, "0");
  return BigInt(intPart! + padded);
}
function unscaleDecimal(scaled: bigint): string {
  const s = scaled.toString().padStart(VOLUME_SCALE + 1, "0");
  const intPart = s.slice(0, s.length - VOLUME_SCALE);
  const fracPart = s.slice(s.length - VOLUME_SCALE).replace(/0+$/, "");
  return fracPart.length > 0 ? `${intPart}.${fracPart}` : intPart;
}
