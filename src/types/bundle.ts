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
  outcome: 'pass' | 'fail' | 'indeterminate';
  detail: string;
}
