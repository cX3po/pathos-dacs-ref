/**
 * §10.4 AttestationBundle (v0.1) acceptance verifier.
 *
 * Consumes a current-spec `AttestationBundleV1` (the §10.4 shape a reference-impl contributor pinned as the
 * cross-impl fixture, DACS-Standard #117/#99) — distinct from the legacy verify-bundle.ts
 * path. Performs the §10.4.1 checks that don't require a chain:
 *   - structural validation of the §10.4 shape (incl. outcome ∈ enum, party/signature shapes);
 *   - bundleHash = sha256(JCS(bundle with `signatures` omitted)), hex (the signed scope);
 *   - required-signer rule (§10.4.1): non-abort outcomes require buyer + seller (+ a
 *     distinct orchestrator if present) AND no unlisted signers; aborted-by-* outcomes MAY
 *     be single-signed (§10.11) but every signer must still be a listed party;
 *   - signature verification over "dacs-bundle:v1:" || bundleHash, *when* algorithm is
 *     ed25519 AND the signer's claim identifier resolves to a 32-byte key. Illustrative
 *     fixtures using placeholder DIDs (or non-ed25519 labels) are `unverifiable`, not `fail`.
 *
 * Two-sided anchoring / divergence (§10.4.2/§10.4.3) is a cross-bundle concern handled by
 * the caller comparing two single-side verdicts; this function verifies ONE bundle.
 */
import type { AttestationBundleV1, BundleSignature, CurrentAttestationBundle } from '../types/bundle.js';
import { fetchAnchored } from '../demos/storage.js';
/**
 * §10.4.2 two-sided anchor derivation for a v0.1 bundle's jobId — identical contract to the
 * legacy `computeAnchorPair` in verify-bundle.ts:
 *   buyer  := stor-{sha256(jobId + "-bundle-buyer")}
 *   seller := stor-{sha256(jobId + "-bundle-seller")}
 */
export declare function computeAnchorPairV1(jobId: string): {
    buyer: string;
    seller: string;
};
export type SigCheck = {
    party: string;
    decision: 'pass' | 'fail' | 'unverifiable';
    reason?: string;
};
export type BundleV1Verdict = {
    /**
     * CONSUMER CONTRACT (§7.5.1, do-not-collapse): ONLY `accept` is success. Treat BOTH `reject`
     * (hard failure — invalid signature / structural / unlisted signer) AND `indeterminate`
     * (undecidable — unresolvable key / placeholder DID / unsupported algorithm) as NOT-accepted.
     * Never write `decision !== 'reject'` to mean success — that would wrongly accept `indeterminate`.
     */
    decision: 'accept' | 'reject' | 'indeterminate';
    bundleHash: string;
    structurallyValid: boolean;
    signerRuleSatisfied: boolean;
    /** True iff there is >=1 signature and EVERY signature cryptographically verified. */
    cryptographicallyVerified: boolean;
    signatureChecks: SigCheck[];
    reasons: string[];
};
/**
 * A ClaimReference is either a non-empty bare-DID string or { scheme, identifier, params? }.
 * The key includes canonicalised params so two claims that differ only in params don't collide.
 */
export declare function claimKey(c: unknown): string | null;
/**
 * Decode a 64-byte ed25519 signature from canonical base64 OR base64url (separate grammars).
 * A 64-byte payload is exactly 86 significant chars: canonical base64 ends "==", base64url has
 * no padding. Anything else (mixed alphabet, wrong padding, wrong length) → null.
 */
export declare function decodeEd25519Sig(v: unknown): Uint8Array | null;
/**
 * Verify a single §10.4 AttestationBundleV1.
 *
 * `requireSignatures` (default true, ENFORCING): every signature must cryptographically
 * verify for `accept`. Pass `false` (FIXTURE mode) for non-normative illustrative fixtures
 * whose signers are placeholder DIDs (or non-ed25519) that can't be crypto-verified — there
 * `accept` means structurally valid + signer-set rule satisfied + no hard signature failure;
 * `cryptographicallyVerified` reports the real crypto status regardless of mode.
 */
export declare function verifyBundleV1(bundle: AttestationBundleV1 | CurrentAttestationBundle, opts?: {
    requireSignatures?: boolean;
    resolvePublicKey?: (claim: BundleSignature['party']) => Uint8Array | null;
}): BundleV1Verdict;
/** Three-valued outcome for one §7.5.2 step / the two-sided anchoring step. */
type ChainOutcome = 'pass' | 'fail' | 'indeterminate';
export interface VerifyBundleV1Options {
    /** Demos RPC URL for fetching anchored bundles + attestation refs. */
    rpc?: string;
    /**
     * Skip the §10.4.2/§10.4.3 two-sided anchor lookup. EXACTLY like legacy verifyBundle's
     * `skipTwoSidedLookup`: only set this when the caller has deliberately opted into offline
     * verification (e.g. receipt-archive audit). When false (default), an UNANCHORED bundle is
     * `indeterminate`, NEVER a silent pass.
     */
    skipTwoSidedLookup?: boolean;
    /** Inject a custom fetchAnchored — tests use this to mock the chain. */
    fetchAnchoredImpl?: typeof fetchAnchored;
    /**
     * Enforcing vs fixture mode for the structural+signature stage of BOTH the local bundle AND
     * the two chain-anchored counterparty copies (see verifyBundleV1).
     *
     * DEFAULT = undefined ⇒ ENFORCING (requireSignatures:true) everywhere. The two-sided check
     * (FIX 3) NO LONGER hardcodes fixture mode for the anchored copies — a counterparty anchor with
     * placeholder/unverifiable signatures is `fail` unless the CALLER explicitly opted into fixture
     * mode by passing `requireSignatures:false`. This flag is threaded to verifyV1TwoSided so the
     * anchored copies are verified under the SAME mode the caller chose for the local bundle.
     */
    requireSignatures?: boolean;
}
/** The full v0.1 verdict: the single-bundle verdict PLUS the chain-side results. */
export interface BundleV1FullVerdict extends BundleV1Verdict {
    /** §10.4.2/§10.4.3 — null when skipped. */
    twoSided: {
        outcome: ChainOutcome | 'skipped';
        detail: string;
    };
    /** §7.5.2 — REAL fetched-and-content-hashed counts (no longer hardcoded). */
    attestationsVerified: number;
    attestationsFailed: number;
    /** Per-ref §7.5.2 step log. */
    attestationSteps: {
        ref: string;
        outcome: ChainOutcome;
        detail: string;
    }[];
    /** Final rollup across structural+sig, two-sided, and the attestation walk (§7.5.1). */
    rollup: ChainOutcome;
}
/**
 * Full v0.1 verification — the contract the CLI MUST use for `bundleVersion:"1"` bundles.
 * Runs the single-bundle structural+signature check, the §10.4.2/§10.4.3 two-sided anchoring
 * (unless explicitly skipped via `skipTwoSidedLookup`), and the §7.5.2 AttestationRef walk, then
 * rolls them up with §7.5.1 precedence (any fail → fail; else any indeterminate → indeterminate;
 * else pass). This brings the v0.1 path to parity with the legacy verifyBundle path.
 */
export declare function verifyBundleV1Full(bundle: AttestationBundleV1, options?: VerifyBundleV1Options): Promise<BundleV1FullVerdict>;
export {};
