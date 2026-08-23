import { canonicalize } from "../canonicalize.ts";
import { sha256Hex, contentHashSignedScope } from "../hash.ts";
import { verifyArtifactSignatureWithSeparator } from "../signing.ts";
import { matchRequirement, schemeOf, type IdentityBundle } from "../dacs1.ts";
import { canonicalDecimal, assertPositiveAmount, isCanonicalDecimal } from "../decimal.ts";
import { dacsXSeparator } from "./separators.ts";
import type {
  DisputeRecord,
  DisputeOutcome,
  DisputedBundleRef,
  ArbitrationRule,
  RemedyDecision,
  SessionReputationContribution,
  ReputationReweight,
} from "./types.ts";

/** Ed25519 raw public keys are exactly 32 bytes; anything else is malformed
 *  input the verifier cannot evaluate (→ surfaces as `error`, not `fail`). */
function assertEd25519Key(raw: Uint8Array, role: string): void {
  if (raw.length !== 32) throw new Error(`malformed ${role} public key: expected 32 bytes, got ${raw.length}`);
}

// DACS-X dispute verification — pure, read-only. This module NEVER holds a
// private key and NEVER signs (ISC-38); it only verifies signatures, hashes,
// and credential matches that were produced elsewhere. It composes the existing
// DACS primitives: §7.7 signing, §7.2 content hashing, DACS-1/2 matchRequirement,
// CD-1 decimal. No new cryptography.

export type DisputeCheck = { ok: true } | { ok: false; reason: string };

const fromB64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));

/** Content hash of a DACS-X artifact's signed scope (signature field omitted). */
export function disputeRecordHash(record: DisputeRecord): string {
  return contentHashSignedScope(record as unknown as Record<string, unknown>, "signature");
}
export function disputeOutcomeHash(outcome: DisputeOutcome): string {
  return contentHashSignedScope(outcome as unknown as Record<string, unknown>, "signature");
}

/**
 * Verify a DisputeRecord:
 *   (1) its §7.7 signature verifies against the initiator's resolved public key
 *       under the dacs-x-dispute-record separator, and
 *   (2) it pins at least one KNOWN AttestationBundle by exact (jobId, bundleHash)
 *       — so a dispute cannot point at a bundle and then have that bundle altered.
 *
 * The initiator key is resolved out-of-band from `record.initiator` (claim→key
 * resolution is substrate-dependent and stays outside this read-only verifier).
 */
export function verifyDisputeRecord(
  record: DisputeRecord,
  initiatorPublicKeyRaw: Uint8Array,
  knownBundles: DisputedBundleRef[],
): DisputeCheck {
  if (record.dacsXVersion !== "1") return { ok: false, reason: `unsupported dacsXVersion ${record.dacsXVersion}` };
  // initiator must be a well-formed claim reference (has a scheme).
  try {
    schemeOf(record.initiator);
  } catch {
    return { ok: false, reason: "initiator is not a well-formed claim reference" };
  }
  assertEd25519Key(initiatorPublicKeyRaw, "initiator"); // malformed key → error, not fail

  const sig = verifyArtifactSignatureWithSeparator({
    separator: dacsXSeparator("dacs-x-dispute-record"),
    doc: record as unknown as Record<string, unknown>,
    publicKeyRaw: initiatorPublicKeyRaw,
    signatureRaw: fromB64u(record.signature),
    signatureFields: ["signature"],
  });
  if (!sig.ok) return { ok: false, reason: sig.reason ?? "dispute-record signature did not verify" };

  if (record.disputed.length === 0) return { ok: false, reason: "dispute references no bundle" };
  for (const ref of record.disputed) {
    const knownJob = knownBundles.some((b) => b.jobId === ref.jobId);
    if (!knownJob) return { ok: false, reason: `unknown jobId in dispute: ${ref.jobId}` };
    const knownPair = knownBundles.some((b) => b.jobId === ref.jobId && b.bundleHash === ref.bundleHash);
    if (!knownPair) {
      return { ok: false, reason: `bundle hash mismatch for ${ref.jobId} — dispute pinned to a different bundle` };
    }
  }
  const contestedShape = validateContestedClaimShape(record);
  if (!contestedShape.ok) return contestedShape;
  return { ok: true };
}

function validateContestedClaimShape(record: DisputeRecord): DisputeCheck {
  if (record.contestedClaim !== "divergent-bundle") return { ok: true };
  if (record.disputed.length < 2) {
    return { ok: false, reason: "divergent-bundle dispute requires at least two bundle refs" };
  }
  if (new Set(record.disputed.map((ref) => ref.jobId)).size !== 1) {
    return { ok: false, reason: "divergent-bundle dispute refs must share one jobId" };
  }
  if (new Set(record.disputed.map((ref) => ref.bundleHash)).size < 2) {
    return { ok: false, reason: "divergent-bundle dispute refs must carry different bundle hashes" };
  }
  return { ok: true };
}

/**
 * Verify an arbitrator is legitimately credentialed for THIS dispute:
 *   (a) the agreed ArbitrationRule hashes to the rule-ref the DisputeRecord
 *       pinned (§8.4.3) — a swapped/weakened rule produces a different hash and
 *       is rejected, even though the arbitrator's own credentials are valid, and
 *   (b) the arbitrator's DACS-1 identity bundle satisfies the rule's requirement
 *       (reuses DACS-1/2 matchRequirement — no new identity machinery), and
 *   (c) if the rule names an explicit arbitrator allow-set, the arbitrator's
 *       primary claim is in it.
 */
export function verifyArbitratorCredential(
  arbitratorBundle: IdentityBundle,
  record: DisputeRecord,
  agreedRule: ArbitrationRule,
  now: number,
): DisputeCheck {
  // JCS content hash of the agreed rule — identical §7.2 pipeline used
  // everywhere in DACS (sha256 over the RFC 8785 canonical form).
  const computedRuleRef = sha256Hex(canonicalize(agreedRule));
  if (computedRuleRef !== record.arbitration.ruleRef) {
    return { ok: false, reason: "arbitration rule-ref mismatch — arbitrator set was swapped after agreement" };
  }
  if (agreedRule.arbitrators && agreedRule.arbitrators.length > 0) {
    if (!agreedRule.arbitrators.includes(arbitratorBundle.presentedBy)) {
      return { ok: false, reason: `arbitrator ${arbitratorBundle.presentedBy} not in the agreed allow-set` };
    }
  }
  const m = matchRequirement(arbitratorBundle, agreedRule.requirement, now);
  if (!m.ok) return { ok: false, reason: `arbitrator credential: ${m.reason}` };
  return { ok: true };
}

/** Validate a remedy decision's economic fields (CD-1 / §9.3 / bounds). */
export function validateRemedy(remedy: RemedyDecision): DisputeCheck {
  switch (remedy.kind) {
    case "refund-ordered": {
      if (!remedy.asset || typeof remedy.asset !== "string") {
        return { ok: false, reason: "refund missing asset" };
      }
      if (!isCanonicalDecimal(remedy.amount)) {
        return { ok: false, reason: `refund amount is not CD-1 canonical: ${JSON.stringify(remedy.amount)}` };
      }
      try {
        assertPositiveAmount(remedy.amount); // §9.3: strictly > 0
      } catch (e) {
        return { ok: false, reason: `refund amount invalid: ${(e as Error).message}` };
      }
      return { ok: true };
    }
    case "reputation-corrected": {
      let c: string;
      try {
        c = canonicalDecimal(remedy.weightMultiplier);
      } catch (e) {
        return { ok: false, reason: `weightMultiplier not a canonical decimal: ${(e as Error).message}` };
      }
      if (c !== remedy.weightMultiplier) {
        return { ok: false, reason: `weightMultiplier not CD-1 canonical: ${JSON.stringify(remedy.weightMultiplier)}` };
      }
      const n = Number(c);
      if (!(n >= 0 && n <= 1)) return { ok: false, reason: `weightMultiplier ${c} outside [0,1]` };
      return { ok: true };
    }
    case "no-fault":
      return { ok: true };
    default:
      return { ok: false, reason: `unknown remedy kind: ${(remedy as { kind: string }).kind}` };
  }
}

/**
 * Verify a DisputeOutcome:
 *   (1) it binds to the DisputeRecord by content hash and disputeId,
 *   (2) its §7.7 signature verifies against the arbitrator's public key under
 *       the dacs-x-dispute-outcome separator, and
 *   (3) its remedy is economically valid.
 */
export function verifyDisputeOutcome(
  outcome: DisputeOutcome,
  arbitratorPublicKeyRaw: Uint8Array,
  record: DisputeRecord,
): DisputeCheck {
  if (outcome.dacsXVersion !== "1") return { ok: false, reason: `unsupported dacsXVersion ${outcome.dacsXVersion}` };
  if (outcome.disputeId !== record.disputeId) {
    return { ok: false, reason: "outcome.disputeId does not match the DisputeRecord" };
  }
  if (outcome.disputeRecordHash !== disputeRecordHash(record)) {
    return { ok: false, reason: "outcome.disputeRecordHash does not match the DisputeRecord" };
  }
  assertEd25519Key(arbitratorPublicKeyRaw, "arbitrator"); // malformed key → error, not fail
  const sig = verifyArtifactSignatureWithSeparator({
    separator: dacsXSeparator("dacs-x-dispute-outcome"),
    doc: outcome as unknown as Record<string, unknown>,
    publicKeyRaw: arbitratorPublicKeyRaw,
    signatureRaw: fromB64u(outcome.signature),
    signatureFields: ["signature"],
  });
  if (!sig.ok) return { ok: false, reason: sig.reason ?? "dispute-outcome signature did not verify" };
  return validateRemedy(outcome.remedy);
}

/**
 * DACS-5 §10.5 — consume an arbitrated outcome and derive the disputed session's
 * reweighted reputation. NON-DESTRUCTIVE: the prior weight is preserved and an
 * effective weight is derived, carrying the outcome hash as provenance. This is
 * the safer default for a dispute system (the record must show *why* the weight
 * changed) and still defeats dispute-farming, because a session is reweighted
 * once per arbitrated outcome and the provenance is auditable.
 *
 * OPEN QUESTION for the group: whether the ratified DACS-5 wants a destructive
 * supersede or an append-only event log with derived current weight. This
 * prototype implements the latter shape and does NOT assert a spec mandate.
 */
export function reputationReweight(
  prior: SessionReputationContribution,
  outcome: DisputeOutcome,
): ReputationReweight {
  let effectiveWeight = prior.weight;
  switch (outcome.remedy.kind) {
    case "refund-ordered":
      effectiveWeight = 0; // a refund means delivery was not as agreed → contribution voided
      break;
    case "reputation-corrected":
      effectiveWeight = prior.weight * Number(canonicalDecimal(outcome.remedy.weightMultiplier));
      break;
    case "no-fault":
      effectiveWeight = prior.weight; // stands, but now adjudicated → immune to re-farming
      break;
  }
  return {
    jobId: prior.jobId,
    priorWeight: prior.weight,
    effectiveWeight,
    adjudicated: true,
    adjudicatedBy: disputeOutcomeHash(outcome),
  };
}
