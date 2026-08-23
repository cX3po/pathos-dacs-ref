/**
 * DACS-1 Identify — TypeScript types
 *
 * Spec source: DACS-1 v0.1 §6.3 (VERIFIED against memory/dacs_review/DACS-1-IDENTIFY.md
 * §6.3.2 lines 98-160, 2026-06-07 re-pin cutover).
 *
 * Identity-claim references use a scheme:identifier[?params] grammar (§6.3.1).
 * The IdentityBundle is an ordered set of claims a party presents about itself, with
 * verification metadata, plus a presentation signature.
 *
 * Four permitted presentation kinds (§6.3.2):
 *   - siwd        (Sign-In With Demos — preferred): wallet signs the SIWD message carrying
 *                 `dacs:<hex>` (= hex(signed_bytes)) as an EIP-4361 Resources entry
 *   - per-claim   : each claim's key independently signs `signed_bytes`
 *   - session-key : an ephemeral session key signs `signed_bytes`; optional rootBinding
 *   - sr1-root    : a single SR-1 aggregate signature co-signs the whole bundle
 *
 * Domain-separated payload (all four kinds bind to the same payload, §6.3.2 / DACS-1:149):
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash       (single-hash)
 *   bundle_hash  := sha256(JCS(bundle with `presentation` omitted)), hex
 */

/**
 * An identity claim reference. Grammar per §6.3.1.
 * `ClaimReference` is the spec name; `ClaimRef` is retained as an alias for backwards
 * compatibility with the rest of the reference impl (listing/bundle types import it).
 */
export interface ClaimReference {
  /** Closed v1 scheme registry — see §6.3.1 Table */
  scheme:
    | 'key'        // Registered self-signing Ed25519 key form
    | 'cci-xm'     // Demos cross-model CCI context
    | 'cci-web2'
    | 'cci-pqc'
    | 'cci-ud'
    | 'cci-nomis'
    | 'cci-humanpassport'
    | 'cci-ethos'
    | 'cci-tlsn'
    | 'cci'        // Legacy reference-implementation read compatibility only
    | 'evm-key'    // Generic EVM signing key
    | 'sol-key'    // Generic Solana key
    | 'did'        // W3C DID
    | 'erc8004'    // ERC-8004 agent NFT
    | 'lei'        // Legal Entity Identifier (GLEIF)
    | 'finra-crd'  // FINRA broker-dealer CRD number
    | 'sam-uei'    // SAM.gov Unique Entity ID
    | 'fedramp'    // FedRAMP authorization
    | 'naics'      // North American Industry Classification System
    | 'cmmc'       // Cybersecurity Maturity Model Certification
    | 'stor-cred'; // Storage-Program-backed extensibility surface
  /** Scheme-specific identifier */
  identifier: string;
  /** Optional query-string params (§6.3.1) */
  params?: Record<string, string>;
}

/** Spec alias — `ClaimRef` is the historical name used across the reference impl. */
export type ClaimRef = ClaimReference;

/**
 * A reference to a DACS-2 VerifyResult that verifies a claim (§6.3.2 `verifiedBy`).
 * The reader fetches from `anchor.locator`, re-canonicalises, and confirms the contentHash.
 */
export interface VerifyResultRef {
  anchor: { kind: string; locator: string };
  contentHash: string; // sha256 hex of the RFC 8785 canonical VerifyResult
  recipeVersion?: string;
}

/** §6.3.2 BundleClaim — a single claim entry with verification metadata. */
export interface BundleClaim {
  ref: ClaimReference;
  /** DACS-2 result reference (§6.3.2) */
  verifiedBy?: VerifyResultRef;
  /** unix ms when the verification was performed */
  issuedAt?: number;
  /** unix ms; presenter upper bound — narrows the authority window only (§6.3.2 Freshness window) */
  expiresAt?: number;
  /** scheme-specific */
  metadata?: Record<string, unknown>;
}

/**
 * Four permitted presentation kinds (§6.3.2). `sr1-root` is the v0.1 addition —
 * a single SR-1 aggregate signature over `signed_bytes` covering the whole bundle.
 */
export type PresentationKind = 'siwd' | 'per-claim' | 'session-key' | 'sr1-root';

/**
 * §6.3.2 presentation signature — discriminated union over the four kinds.
 * All four bind to the same domain-separated `signed_bytes` (§6.3.2).
 */
export type PresentationSignature =
  | { kind: 'siwd'; message: string; signature: string; address: string }
  | { kind: 'per-claim'; signatures: { ref: ClaimReference; signature: string }[] }
  | { kind: 'session-key'; key: string; signature: string; rootBinding?: string }
  | { kind: 'sr1-root'; rootClaim: ClaimReference; aggregateSignature: string };

/**
 * A DACS-1 IdentityBundle (v0.1 §6.3.2) — an ordered set of claims a party presents
 * about itself, with verification metadata, plus a presentation signature.
 *
 * Normative requirements (§6.3.2):
 *   - `claims` is non-empty and order is meaningful
 *   - `presentedBy` MUST resolve to a member of `claims` by canonical scheme+identifier (:172)
 *   - `presentedAt` is informational/diagnostic ONLY — verifiers MUST NOT gate on it (:110)
 *   - session freshness/replay is bound by `sessionNonce` (or the SIWD Nonce), not `presentedAt`
 *   - bundle_hash = sha256(JCS(bundle with `presentation` omitted)), hex (:157)
 *   - signed_bytes = "dacs-bundle-presentation:v1:" || bundle_hash (:149)
 */
export interface IdentityBundle {
  /** Schema version — v0.1 (:106). */
  bundleVersion: '1';
  /** The primary identity claim within `claims` (§6.3.2 :108). */
  presentedBy: ClaimReference;
  /** unix MILLISECONDS; informational/diagnostic only — verifiers MUST NOT gate on it (:110). */
  presentedAt: number;
  /**
   * Session-binding nonce for per-claim / session-key presentations; top-level so it enters
   * bundle_hash (§6.3.2 :112). SIWD conveys the nonce in the SIWD message Nonce field instead.
   */
  sessionNonce?: string;
  /** Non-empty; order is meaningful (:114). */
  claims: BundleClaim[];
  /** Presentation signature (omitted from bundle_hash). */
  presentation: PresentationSignature;
}

/**
 * @deprecated Legacy (pre-v0.1) identity-bundle shape, retained ONLY so the legacy
 * `AttestationBundle` (DACS-5 legacy reference impl) can still be READ under dual-accept
 * (§10.4.2 backwards-compat). New code MUST emit the v0.1 `IdentityBundle` above.
 *
 * The legacy shape used `primary`/`claims: ClaimRef[]`/`issuedAt` (ISO string) and a COMPOSITE
 * bundle-presentation signed_bytes (`sep || bundleHash || JCS(payload)`); v0.1 corrects this to
 * the single-hash form (§6.3.2 :149). Do NOT add new consumers of this type.
 */
export interface LegacyIdentityBundle {
  /** Schema version — "dacs-1:0.1" (legacy reference-impl tag). */
  v: 'dacs-1:0.1';
  /** Primary claim — the one against which reputation accumulates (per §10.5.1) */
  primary: ClaimRef;
  /** Supporting claims (LEI, FINRA, SAM, etc.) */
  claims: ClaimRef[];
  /** When the bundle was assembled (ISO 8601) */
  issuedAt: string;
  /** Optional expiry (ISO 8601). If absent, bundle does not expire on its own. */
  expiresAt?: string;
  /** Presentation envelope (legacy flat shape) */
  presentation: {
    kind: 'siwd' | 'per-claim' | 'session-key';
    signature?: string; // base64
    claimSignatures?: Record<number, string>; // index into `claims` -> base64 sig
    sessionPubkey?: string; // base64
    sessionAuthSig?: string; // base64
  };
}

/**
 * Computed at signature time (v0.1 §6.3.2 :149,:157):
 *   bundle_hash  := SHA-256(JCS-canonical(bundle with `presentation` omitted))
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash       (single-hash — hash ONLY)
 *
 * (NOTE: v0.7 used a COMPOSITE form `sep || bundleHash || JCS(payload)`. v0.1 corrected this to
 *  the single-hash form above — see DACS-1-IDENTIFY.md:149. Every signer/verifier builds the
 *  single-hash payload.)
 */
export type BundleHash = Uint8Array; // 32 bytes
