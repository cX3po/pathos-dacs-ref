/**
 * DACS-1 Listing document — TypeScript types
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §6.3.4
 *
 * Normative requirements (LP-1..LP-4, LR-1..LR-3):
 *   LP-1: Listing publishers MUST anchor via SR-2 before indexing
 *   LP-2: Sign with a key referenced in `seller.identity.claims`
 *   LP-3: Maintain monotonically increasing `version` for the same `id`
 *   LP-4: Publish revocation markers (separate stor- address) when listing is withdrawn
 *
 *   LR-1: Readers MUST pin the (id, version, contentHash) tuple per session
 *   LR-2: 9-step validation order, halt-on-first-failure
 *   LR-3: Refuse revoked listings
 *
 * Size cap: 16 KB JCS-canonical (enforced in listing-pub CLI before anchoring).
 */

import type { ClaimRef } from './identity.js';

/** Capability the substrate MUST provide (SR-1..SR-5, §5). */
export type SubstrateRequirement =
  | 'sr-1-keyed-storage'         // Cross-substrate primary-claim keying
  | 'sr-2-anchored-storage'      // Anchored bytes-to-locator
  | 'sr-3-consensus-backed-proxy' // Validator-set fetched + signed HTTPS
  | 'sr-4-bilateral-channel'     // Identity-keyed, confidential, authenticated channel
  | 'sr-5-cross-chain-settlement'; // Atomic settlement bridge

/** A requirement on a counterparty's IdentityBundle (§6.3.3 matcher). */
export interface BundleRequirement {
  /** Schemes the counterparty's primary claim MUST be one of */
  primaryAcceptable: ClaimRef['scheme'][];
  /** Required supporting claims (each MUST be present in the counterparty's bundle) */
  requiredClaims: ClaimRef['scheme'][];
  /** Optional supporting claims (matched if present, not required) */
  optionalClaims?: ClaimRef['scheme'][];
  /** Verification recipes required per claim (DACS-2 §7.4) */
  verificationRecipes: Record<ClaimRef['scheme'], string>; // scheme -> recipeId@version
}

/** The Listing document (§6.3.4). */
export interface Listing {
  /** Schema version */
  v: 'dacs-1-listing:0.1';
  /** Stable id (e.g. UUID v7, lexicographically sortable) */
  id: string;
  /** Monotonically increasing per id (LP-3) */
  version: number;
  /**
   * Stable CF-4 logical address carried on the anchored record (§6.3.4(b)).
   * On Demos this is metadata, never the Storage Program write-input name.
   */
  logical_address: string;
  /** The seller's identity reference (the seller's full IdentityBundle is presented at engagement, not embedded here) */
  seller: {
    identity: { primary: ClaimRef };
  };
  /** What the seller is offering */
  capability: {
    /** Short capability key (e.g. "analyze-csv", "fx-rfq-quote") */
    key: string;
    /** Free-text description */
    description: string;
    /** Input MIME or schema */
    input?: string;
    /** Output MIME or schema */
    output?: string;
  };
  /** Pricing */
  price: {
    /** Unit price as decimal string (PC-1: no float) */
    amount: string;
    /** Currency / token symbol */
    currency: string;
    /** Per-unit basis (e.g. "row", "request", "deal") */
    perUnit: string;
  };
  /** Substrate capabilities the listing depends on */
  requiredCapabilities: SubstrateRequirement[];
  /** Bundle requirements on the buyer */
  buyerRequirements: BundleRequirement;
  /** Settlement rails accepted (rail registry id@version) */
  acceptedRails: string[]; // e.g. ["pay-x402@1", "pay-evm-erc20@1"]
  /** Negotiation patterns accepted */
  acceptedNegotiation: ('negotiate-fixed-price' | 'negotiate-rfq' | 'negotiate-sealed-envelope')[];
  /** When this listing version was published (ISO 8601) */
  publishedAt: string;
  /** Optional expiry */
  expiresAt?: string;
  /** Signature of JCS-canonical form of payload (without `signature` field), prefixed with "dacs-listing:v1:" */
  signature?: string; // base64 ed25519
}

/** Helper type — the listing without its signature, used for canonicalization input. */
export type UnsignedListing = Omit<Listing, 'signature'>;
