/**
 * @pathos-labs/dacs-verifier — stable programmatic surface.
 *
 * Everything here is a re-export of the repository's verifier: one implementation, compiled
 * into this package by scripts/build-verifier-package.mts. The shape of `verifyDocument()`'s
 * result is versioned by VERIFIER_API_VERSION and described by schemas/verify-verdict.schema.json.
 */
export {
  VERIFIER_API_VERSION,
  classifyBundle,
  exitCodeFor,
  indeterminateVerdict,
  isLoadError,
  loadBundleSource,
  normaliseV1Verdict,
  verifyDocument,
} from '../../../src/lib/verify-document.js';
export type {
  BundleKind,
  BundleSource,
  LoadedBundle,
  VerifyDocumentOptions,
  VerifyDocumentResult,
} from '../../../src/lib/verify-document.js';
export { verifyBundleV1, verifyBundleV1Full, computeAnchorPairV1 } from '../../../src/lib/verify-bundle-v1.js';
export type { BundleV1Verdict, BundleV1FullVerdict, VerifyBundleV1Options } from '../../../src/lib/verify-bundle-v1.js';
export { verifyBundle, computeAnchorPair } from '../../../src/lib/verify-bundle.js';
export type { VerifyBundleOptions } from '../../../src/lib/verify-bundle.js';
export type { AttestationBundle, VerifyStep, VerifyVerdict } from '../../../src/types/index.js';
export type { AttestationBundleV1 } from '../../../src/types/bundle.js';

export const PACKAGE_NAME = '@pathos-labs/dacs-verifier';
export const PACKAGE_VERSION = '0.1.0';
