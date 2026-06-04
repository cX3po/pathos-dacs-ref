/**
 * DACS-5 Verify — AttestationBundle
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §10.4
 *
 * Normative requirements:
 *   §10.4.2 — TWO-SIDED ANCHORING
 *     buyer:  stor-{sha256(jobId + "-bundle-buyer")}
 *     seller: stor-{sha256(jobId + "-bundle-seller")}
 *     Divergence between the two = dispute signal.
 *
 *   §10.4.1 — CONSUMER VERIFICATION (this is what verify.ts does):
 *     Verifiers MUST recompute the canonical form, the bundle hash, the
 *     prefixed signed_bytes, and verify each signature.
 *
 *   §10.4.3 — TWO-SIDED LOOKUP
 *     Consumers MUST query both party-specific addresses.
 *     Unilateral bundle ⇒ `aborted-by-self` for the non-signer.
 *
 *   Domain separator: "dacs5-bundle:v1:" (preserved from reference impl per §10.4.2 comment;
 *     will harmonize to "dacs-bundle:v2:" later — backwards compat MUST be honored).
 */

import type { IdentityBundle, ClaimRef } from './identity.js';
import type { CompositeVerificationRecord, VerifyResult, AttestationRef } from './verify-result.js';

/** The phase outcomes captured in a session record. */
export type PhaseOutcome = 'pass' | 'fail' | 'indeterminate' | 'aborted-by-counterparty' | 'aborted-by-self' | 'failed-substrate';

/** A single phase that ran during the session. */
export interface PhaseRecord {
  phaseId: string; // e.g. "vet-credentials", "negotiate-fixed-price", "pay-x402", "deliver-attested-payload"
  startedAt: string; // ISO 8601
  endedAt: string;   // ISO 8601
  outcome: PhaseOutcome;
  /** Attestations produced or referenced during this phase */
  attestations: AttestationRef[];
  /** Free-text or structured detail */
  detail?: Record<string, unknown>;
}

/** Final session state per §10.3.1. */
export type SessionState =
  | 'completed'
  | 'aborted-by-buyer'
  | 'aborted-by-seller'
  | 'failed-substrate-paused'
  | 'failed-verification'
  | 'failed-settlement'
  | 'failed-delivery'
  | 'expired';

/** The AttestationBundle anchored at TWO party-specific addresses (§10.4.2). */
export interface AttestationBundle {
  v: 'dacs-5-bundle:0.1';
  /** The job/session id — same across both parties' bundles */
  jobId: string;
  /** Which party this bundle is from */
  role: 'buyer' | 'seller' | 'orchestrator';
  /** The DACS-1 IdentityBundle of the bundle author (without their signature on this bundle) */
  party: IdentityBundle;
  /** The counterparty's primary claim (full bundle is in the counterparty's anchor) */
  counterparty: { primary: ClaimRef };
  /** Final state of the session */
  state: SessionState;
  /** Phases that ran */
  phases: PhaseRecord[];
  /** Composite vet result (DACS-2) — may be absent if no vet ran */
  verification?: CompositeVerificationRecord;
  /** Per-claim verify results for fine-grained reputation derivation (§10.5.1) */
  verifyResults?: VerifyResult[];
  /** When the bundle was finalised (ISO 8601) */
  finalisedAt: string;
  /** Signature over JCS-canonical(bundle without `signature`), prefixed with "dacs5-bundle:v1:" || bundleHash */
  signature?: string; // base64 ed25519
  /** If orchestrator-distinct-from-parties: their cosignature */
  orchestratorSignature?: string;
}

// ───────────────────────────────────────────────────────────────────────────
// DACS v0.1 §10.4 conformant bundle shape — MIGRATION TARGET (2026-06-03).
// The `AttestationBundle` above predates the §10.4 freeze and has drifted (see
// memory/reports/dacs-baseline-review-2026-06-03.md §C). These types match current
// spec §10.4 exactly. Migration in progress: verify-bundle + the DACS-VERIFY-0004
// emitter move onto these, then the legacy shape is removed. Additive for now so the
// existing suite stays green through the migration.
// ───────────────────────────────────────────────────────────────────────────

/** §10.4 terminal bundle outcome (distinct from the live SessionState). */
export type BundleOutcome =
  | 'completed'
  | 'failed-perm'
  | 'failed-counterparty'
  | 'failed-substrate'
  | 'aborted-by-self'
  | 'aborted-by-other';

/** §10.3 live session state (spec names; replaces the legacy SessionState above). */
export type SessionStateV1 =
  | 'draft'
  | 'vet-pending' | 'vet-completed' | 'vet-failed'
  | 'negotiate-pending' | 'negotiate-completed' | 'negotiate-failed'
  | 'commit-pending' | 'commit-completed' | 'commit-failed'
  | 'settle-pending' | 'settle-completed' | 'settle-failed'
  | 'rate-pending' | 'rate-completed'
  | 'finalised'
  | 'aborted-by-self' | 'aborted-by-other'
  | 'substrate-failure-paused' | 'failed-substrate';

/** §10.4 chain transaction reference. */
export interface ChainTxRef {
  chainId: string;
  txHash: string;
}

/** §10.4 BundleParty — one entry per signing party. */
export interface BundleParty {
  role: 'buyer' | 'seller' | 'orchestrator';
  bundleHash: string;
  primaryClaim: ClaimRef;
}

/** §10.4 BundlePhaseEntry — per-phase summary (phase-level outcome is ok|fail). */
export interface BundlePhaseEntry {
  index: number;
  kind: string; // PhaseType — closed set across DACS-2..5
  outcome: 'ok' | 'fail';
  errorClass?: 'permanent' | 'transient' | 'counterparty' | 'substrate' | 'settlement-atomicity';
  txRefs?: ChainTxRef[];
  attestationRef?: AttestationRef;
}

/** §10.4 BundleSignature — structured per signer (vs the legacy scalar sig fields). */
export interface BundleSignature {
  party: ClaimRef; // primary claim of the signer
  algorithm: 'ed25519' | 'ecdsa-secp256k1' | 'sr1-aggregate';
  value: string; // signature over the "dacs-bundle:v1:" || bundleHash payload (§10.4.1)
}

/** §10.4 AttestationBundle (v0.1-conformant). Signed under "dacs-bundle:v1:" per §10.4.1. */
export interface AttestationBundleV1 {
  bundleVersion: '1';
  jobId: string;
  outcome: BundleOutcome;
  /** §10.4 (R4-B): role of the party that anchored THIS copy; `outcome` is from this party's
   *  perspective (matches the §10.4.2 role-derived anchor address). Required + signed. */
  anchoredByRole: 'buyer' | 'seller' | 'orchestrator';
  listingRef: { listingId: string; version: number; contentHash: string };
  agreementRef?: AttestationRef;
  parties: BundleParty[];
  phaseSummary: BundlePhaseEntry[];
  vetRecords: AttestationRef[];
  settlementEvidence: AttestationRef[];
  amendments?: AttestationRef[];
  ratingRefs?: AttestationRef[];
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  finalisedAt: number;
  signatures: BundleSignature[];
}

/**
 * Compute the two storage anchor addresses for a bundle's jobId (§10.4.2).
 *
 *   buyer:  stor-{sha256(jobId + "-bundle-buyer")}
 *   seller: stor-{sha256(jobId + "-bundle-seller")}
 *
 * Implementation lives in src/lib/bundle-anchors.ts (not in this types-only file).
 */
export type BundleAnchorPair = {
  buyer: string;  // "stor-<hex>"
  seller: string; // "stor-<hex>"
};

/** What the verifier returns — closed shape, predictable for downstream tooling. */
export interface VerifyVerdict {
  decision: 'pass' | 'fail' | 'indeterminate';
  jobId: string;
  steps: VerifyStep[];
  /** SHA-256 hex of the canonical bundle bytes the verifier hashed */
  canonicalBundleHash: string;
  /** Public keys that successfully verified */
  signersVerified: string[]; // base64 pubkeys
  /** AttestationRefs that resolved + content-hash matched */
  attestationsVerified: number;
  /** AttestationRefs that did not resolve or content-hash mismatched */
  attestationsFailed: number;
}

/** A single step in the verifier's walk. */
export interface VerifyStep {
  step: string;
  /**
   * `pass` | `fail` | `indeterminate` — the three §7.5.1 decision values that
   * roll up into the final verdict (any fail → fail; else any indeterminate → indeterminate; else pass).
   *
   * `skipped` — informational only; recorded in the step log so the user sees
   * that a check was deliberately not run, but does NOT affect the rollup decision.
   * Used when the caller explicitly opts out of a check (e.g. skipTwoSidedLookup=true
   * for offline file verification). The verifier still surfaces the scope limit in
   * the detail so downstream consumers can choose how to treat it.
   */
  outcome: 'pass' | 'fail' | 'indeterminate' | 'skipped';
  detail: string;
}
