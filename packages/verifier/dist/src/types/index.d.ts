/**
 * DACS reference implementation — type barrel
 *
 * Re-exports every DACS type used across the codebase, anchored to spec sections.
 *
 * Import from this file rather than the individual modules so the spec
 * section references are co-located here.
 */
export type { ClaimRef, ClaimReference, PresentationKind, PresentationSignature, BundleClaim, VerifyResultRef, IdentityBundle, LegacyIdentityBundle, BundleHash, } from './identity.js';
export type { Listing, UnsignedListing, BundleRequirement, SubstrateRequirement } from './listing.js';
export type { VerifyDecision, VerifyResult, DahrAttestation, LegacyAttestationRef, AttestationRef, CompositeVerificationRecord } from './verify-result.js';
export { isPass, isFail, isIndeterminate, isError } from './verify-result.js';
export type { AttestationBundle, BundleAnchorPair, PhaseOutcome, PhaseRecord, SessionState, VerifyStep, VerifyVerdict } from './bundle.js';
