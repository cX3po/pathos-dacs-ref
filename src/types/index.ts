/**
 * DACS reference implementation — type barrel
 *
 * Re-exports every DACS type used across the codebase, anchored to spec sections.
 *
 * Import from this file rather than the individual modules so the spec
 * section references are co-located here.
 */

// DACS-1 Identify
export type {
  ClaimRef,
  ClaimReference,
  PresentationKind,
  PresentationSignature,
  BundleClaim,
  VerifyResultRef,
  IdentityBundle,
  LegacyIdentityBundle,
  BundleHash,
} from './identity.js';
export type { Listing, UnsignedListing, BundleRequirement, SubstrateRequirement } from './listing.js';

// DACS-2 Vet
export type { VerifyDecision, VerifyResult, AttestationRef, CompositeVerificationRecord, ComponentSignature, SupplementarySignal, VerificationWarning, WarningCode } from './verify-result.js';
export { isPass, isFail, isIndeterminate, isError } from './verify-result.js';

// DACS-5 Verify
export type { AttestationBundle, BundleAnchorPair, PhaseOutcome, PhaseRecord, SessionState, VerifyStep, VerifyVerdict } from './bundle.js';
