/**
 * DACS-5 envelope-receipt verifier — core logic
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1 §10.4
 *
 * Pulled out of cli/verify.ts so the verifier can be unit-tested without going
 * through process.argv + process.exit. The CLI is a thin wrapper.
 *
 * Normative invariants enforced here:
 *   §7.5.1 — decision ∈ {pass, fail, indeterminate}; NEVER coerced
 *   §7.5.2 — every AttestationRef MUST have its anchored bytes re-hashed and matched
 *   §10.4.1 — verifier MUST recompute canonical form + bundleHash + signed_bytes; verify signatures
 *   §10.4.2 — bundle is anchored at TWO addresses (buyer + seller); compute deterministically
 *   §10.4.3 — consumer queries BOTH party-specific addresses; unilateral ⇒ aborted-by-self
 */
import type { AttestationBundle, VerifyStep, VerifyVerdict } from '../types/index.js';
import { fetchAnchored } from '../demos/storage.js';
/** Step recorder — accumulates the verify walk for the final verdict. */
export declare class StepLog {
    steps: VerifyStep[];
    add(step: string, outcome: 'pass' | 'fail' | 'indeterminate' | 'skipped', detail: string): void;
    hasFailure(): boolean;
    hasIndeterminate(): boolean;
    rollupDecision(): VerifyVerdict['decision'];
}
export interface VerifyBundleOptions {
    /** Demos RPC URL for fetching anchored bundles + attestation refs */
    rpc?: string;
    /** When true, skip the §10.4.2 two-sided anchor lookup (used for --bundle-file verification) */
    skipTwoSidedLookup?: boolean;
    /** Pre-fetched counterparty bundle (used when caller already has both sides) */
    counterpartyBundle?: AttestationBundle;
    /**
     * Inject a custom fetchAnchored implementation — used by tests to mock
     * the chain layer without making real RPC calls. Default uses the live
     * Demos SDK fetchAnchored.
     */
    fetchAnchoredImpl?: typeof fetchAnchored;
}
/** Convert hex (with optional 0x prefix) to a Uint8Array. Strict — rejects non-hex chars. */
export declare function hexToBytes(hex: string): Uint8Array;
/** Convert bytes to hex (no 0x prefix). */
export declare function bytesToHex(b: Uint8Array): string;
/**
 * Compute the §10.4.2 two-sided anchors from a jobId.
 *
 *   buyer  := stor-{sha256(jobId + "-bundle-buyer")}
 *   seller := stor-{sha256(jobId + "-bundle-seller")}
 *
 * The derivation is pure — given the same jobId, every verifier produces the same pair.
 */
export declare function computeAnchorPair(jobId: string): {
    buyer: string;
    seller: string;
};
/**
 * Resolve the ed25519 public key for a DACS-1 IdentityBundle's primary claim.
 *
 * v0.2 supports `scheme: 'cci'` only. On Demos, the CCI primary-claim identifier
 * IS the ed25519 public key as 64 hex chars (with optional 0x prefix). For other
 * schemes (ERC-8004, LEI, etc.) we return null — the caller marks signature
 * verification as `indeterminate` with reason "scheme not supported in v0.2".
 */
export declare function resolvePrimaryClaimPubkey(bundle: AttestationBundle): {
    pubkey: Uint8Array;
    source: string;
} | null;
/** The full §10.4.1 walk. */
export declare function verifyBundle(bundle: AttestationBundle, options?: VerifyBundleOptions): Promise<VerifyVerdict>;
