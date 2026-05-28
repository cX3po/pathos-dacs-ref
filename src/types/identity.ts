/**
 * DACS-1 Identify — TypeScript types
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §6.3
 *
 * Identity-claim references use a scheme:identifier[?params] grammar (§6.3.1).
 * The IdentityBundle binds a set of claims under a single primary claim.
 *
 * Three permitted presentation kinds (§6.3.2):
 *   - SIWD (Sign-In With Demos): single signature over the entire bundle hash
 *   - per-claim: each claim independently signed
 *   - session-key: ephemeral key authorized by the primary-claim key
 *
 * All three sign over JCS canonical form of payload prefixed with
 *   "dacs-bundle-presentation:v1:" || bundleHash
 */

/** An identity claim reference. Grammar per §6.3.1. */
export interface ClaimRef {
  /** Closed v1 scheme registry — see §6.3.1 Table */
  scheme:
    | 'cci'        // Demos CCI native context
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

/** Three permitted presentation kinds (§6.3.2). */
export type PresentationKind = 'siwd' | 'per-claim' | 'session-key';

/**
 * An IdentityBundle binds one or more claims under a primary claim.
 *
 * Normative requirements (§6.3.2):
 *   - MUST include exactly one primary claim
 *   - MUST be signed with the presentation kind declared in `presentation.kind`
 *   - Signature input MUST be:
 *       JCS-canonical(payload) prefixed with "dacs-bundle-presentation:v1:" || bundleHash
 *   - bundleHash = SHA-256 of JCS-canonical form of payload (without signatures)
 */
export interface IdentityBundle {
  /** Schema version — currently "dacs-1:0.1" */
  v: 'dacs-1:0.1';
  /** Primary claim — the one against which reputation accumulates (per §10.5.1) */
  primary: ClaimRef;
  /** Supporting claims (LEI, FINRA, SAM, etc.) */
  claims: ClaimRef[];
  /** When the bundle was assembled (ISO 8601) */
  issuedAt: string;
  /** Optional expiry (ISO 8601). If absent, bundle does not expire on its own. */
  expiresAt?: string;
  /** Presentation envelope */
  presentation: {
    kind: PresentationKind;
    /** For SIWD: single signature.  For per-claim: signature MUST appear in `claimSignatures`.  For session-key: ephemeral pubkey + authorization signature. */
    signature?: string; // base64
    claimSignatures?: Record<number, string>; // index into `claims` -> base64 sig
    sessionPubkey?: string; // base64
    sessionAuthSig?: string; // base64
  };
}

/**
 * Computed at signature time:
 *   bundleHash := SHA-256(JCS-canonical(payload without `presentation.signature*`))
 *
 * Then the signed bytes are:
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundleHash || JCS-canonical(payload)
 *
 * (Note the prefix is over the entire canonical form, not just the hash — see §6.3.2.)
 */
export type BundleHash = Uint8Array; // 32 bytes
