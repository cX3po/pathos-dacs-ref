import type { ClaimReference, BundleRequirement } from "../dacs1.ts";

// DACS-X (dispute / execution-verification) — PROPOSED extension types (§11.2.1).
//
// Field names follow DACS conventions: camelCase, claim references as strings
// (§6.3.1), content hashes as lowercase-hex sha256 of the JCS canonical form
// (§7.2). Every signed artifact carries its Ed25519 signature as base64url of
// the raw 64-byte value and is domain-separated under the SIG-4 `dacs-x-*`
// namespace. Per §7.1, fractional quantities (a reputation multiplier, a refund
// amount) are carried as CD-1 decimal STRINGS, never bare JSON numbers.

/** A reference to a contested AttestationBundle (DACS-5 §10). */
export interface DisputedBundleRef {
  jobId: string;
  /** sha256 hex of the bundle's signed scope (§7.2 content hash). */
  bundleHash: string;
}

export type ContestedClaimKind =
  | "non-delivery"
  | "mis-delivery"
  | "mis-classified-error"
  | "contested-amendment"
  | "divergent-bundle" // the §10.4.3 two-sided-bundle disagreement
  | "asymmetric-settlement"; // HTLC-9 dest-revealed-source-unclaimed (§9.5.4/§9.8)

export type RequestedRemedyKind = "refund" | "reputation-correction" | "no-fault";

/**
 * The arbitration rule the parties agreed to at agreement time (§8.4.3).
 * Its content hash is the `rule-ref` a DisputeRecord pins to — binding the
 * arbitrator requirement BEFORE any dispute exists is what prevents either
 * party from swapping arbitrators after the outcome is known.
 */
export interface ArbitrationRule {
  /** Requirement an arbitrator's DACS-1 identity bundle must satisfy (DACS-1/2). */
  requirement: BundleRequirement;
  /** Optional explicit arbitrator allow-set, by primary claim reference. */
  arbitrators?: ClaimReference[];
  policyVersion: number;
}

/** dispute-open — signed by the initiating party's primary claim. */
export interface DisputeRecord {
  dacsXVersion: "1";
  disputeId: string;
  /** The initiating party's primary claim reference (§6.3). */
  initiator: ClaimReference;
  /** One or more bundles under dispute. */
  disputed: DisputedBundleRef[];
  contestedClaim: ContestedClaimKind;
  requestedRemedy: RequestedRemedyKind;
  /** Pins the agreed ArbitrationRule by content hash (§8.4.3 rule-ref). */
  arbitration: { ruleRef: string };
  openedAt: number;
  /** Ed25519 sig (base64url, raw) over the signed scope, dacs-x-dispute-record. */
  signature: string;
}

export interface RefundOrder {
  kind: "refund-ordered";
  /** CD-1 canonical decimal, strictly > 0 (§9.3). */
  amount: string;
  /** Asset / rail identifier; opaque to the verifier. */
  asset: string;
}

export interface ReputationCorrection {
  kind: "reputation-corrected";
  /** CD-1 canonical decimal in [0,1]; multiplier on the disputed contribution. */
  weightMultiplier: string;
  favors: "initiator" | "respondent";
}

export interface NoFault {
  kind: "no-fault";
}

// NOTE: the former `CorrectionAmendmentOrder` remedy (`correction-ordered`) was
// REMOVED to track Round-4 R4-A / Round-5 R5-3. The HTLC-9 asymmetric settlement
// (`dest-revealed-source-unclaimed`) no longer resolves through a DACS-X
// `correction` amendment; it resolves at the SETTLEMENT layer via the
// non-terminal §10.3.1 ST-8 `settle-asymmetric` state (→ terminal `completed`
// on htlc-claim, → terminal `failed-counterparty` on window expiry). A dispute
// over the window-expired terminal outcome therefore uses a standard remedy
// (refund / reputation-correction / no-fault), not a settlement correction.

export type RemedyDecision = RefundOrder | ReputationCorrection | NoFault;

/** Arbitrator-signed outcome — supersedes/annotates the disputed bundle (§10.10). */
export interface DisputeOutcome {
  dacsXVersion: "1";
  disputeId: string;
  /** sha256 hex of the DisputeRecord's signed scope — binds outcome to open. */
  disputeRecordHash: string;
  /** The arbitrator's primary claim reference. */
  arbitrator: ClaimReference;
  remedy: RemedyDecision;
  decidedAt: number;
  /** Ed25519 sig (base64url, raw) over the signed scope, dacs-x-dispute-outcome. */
  signature: string;
}

/**
 * A DACS-5 §10.5 session reputation contribution BEFORE adjudication — the
 * reweight input. In-memory derivation state, never signed or hashed.
 */
export interface SessionReputationContribution {
  jobId: string;
  /** Raw contribution weight from the (possibly disputed) session. */
  weight: number;
}

/**
 * Result of reweighting a contribution against an arbitrated outcome.
 *
 * NON-DESTRUCTIVE by design: the prior weight is PRESERVED (audit trail) and an
 * effective weight is derived from the remedy. A dispute record must be able to
 * show *why* a weight changed, so overwriting the original in place would defeat
 * the purpose. Whether the ratified standard ultimately wants a destructive
 * supersede or an append-only event log is an OPEN QUESTION for the group — this
 * prototype takes the non-destructive default and flags it.
 */
export interface ReputationReweight {
  jobId: string;
  /** Pre-dispute weight, retained for the audit trail. */
  priorWeight: number;
  /** Weight after adjudication, derived from the remedy. */
  effectiveWeight: number;
  adjudicated: true;
  /** Content hash of the DisputeOutcome that produced this reweight (provenance). */
  adjudicatedBy: string;
}

// ── §8.7 transcript disclosure — DACS-X step 3 (arbitrator-disclosure) ────────
//
// §8.7 ("A future DACS standard (proposed DACS-X dispute) MAY require selective
// transcript disclosure under signed party agreement or arbitrator order") is the
// spec hook this realises. Per steward sign-off DP-1: the full §8.7 transcript is
// disclosed to the NAMED ARBITRATOR ONLY, producing NO presentable artifact (it
// is structurally separate from §11.2.7 claim-disclosure — different object
// [transcript vs claims], different audience [arbitrator vs counterparty], no
// minimised claim set out). Built from existing primitives only (§7.7 signing,
// §7.2 hashing, DACS-1 claim refs) — DP-4 "no new cryptography".

/** One signed message in a §8.3.3 channel, referenced by its envelope hash. */
export interface ChannelMessageRef {
  /** Per-channel monotonic sequence (§8.3.3), starts at 1. */
  sequence: number;
  /** The message author's primary claim reference (CH-3). */
  author: ClaimReference;
  /** sha256 hex of the §8.3.3 message envelope (the signed scope). */
  envelopeHash: string;
}

/** A signature over a §8.7 / DACS-X scope: signer's claim + base64url raw Ed25519. */
export interface PartySignature {
  signer: ClaimReference;
  /** base64url of the raw 64-byte Ed25519 signature. */
  signature: string;
}

/**
 * §8.7 ChannelTranscript — the ordered sequence of signed channel messages,
 * private to channel members. Signed over "dacs-transcript:v1:" ||
 * sha256(JCS(transcript_without_signatures)) per §7.7. The artifact DACS-X step 3
 * discloses to the arbitrator.
 */
export interface ChannelTranscript {
  transcriptVersion: "1";
  channelId: string;
  members: ClaimReference[];
  messages: ChannelMessageRef[];
  generatedAt: number;
  /** One §8.7 signature per channel member (CH-3 authenticity). */
  signatures: PartySignature[];
}

/** How a disclosure is authorized (DP-1: "signed party agreement or arbitrator order"). */
export type DisclosureAuthority = "party-agreement" | "arbitrator-order";

/**
 * dacs-x-disclosure-grant — authorizes disclosing ONE §8.7 transcript to ONE
 * named arbitrator for ONE dispute. NON-PRESENTABLE: this is the authorization,
 * not a re-anchorable disclosure bundle; the verifier consumes it and yields a
 * boolean "transcript X may be shown to arbitrator Y", nothing re-presentable.
 *   - authority "party-agreement": signed by ALL transcript members (consent).
 *   - authority "arbitrator-order": signed by the credentialed arbitrator.
 */
export interface DisclosureGrant {
  dacsXVersion: "1";
  disputeId: string;
  /** Binds to the open dispute (§11.2.1 step 1) — same hash as the outcome binds. */
  disputeRecordHash: string;
  /** §7.2 content hash of the disclosed transcript's signed scope — anti-substitution. */
  transcriptHash: string;
  /** The ONLY permitted recipient — MUST be the credentialed arbitrator (DP-1). */
  recipient: ClaimReference;
  authority: DisclosureAuthority;
  grantedAt: number;
  /** party-agreement: one per member; arbitrator-order: one (the arbitrator). */
  signatures: PartySignature[];
}
