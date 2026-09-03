/**
 * RFC 8785 JSON Canonicalization Scheme (JCS)
 *
 * Used by DACS for every place a hash-stable canonical form is required:
 *   - DACS-1 Listing (§6.3.4) — JCS-canonical bytes are what gets anchored + size-capped at 16 KB
 *   - DACS-1 IdentityBundle (§6.3.2) — JCS-canonical of payload is what bundleHash hashes
 *   - DACS-2 VerifyResult, CompositeVerificationRecord (§7.5, §7.7) — JCS before signing
 *   - DACS-5 AttestationBundle (§10.4.1) — JCS before computing bundleHash and signing
 *
 * Implementation: thin wrapper around the `canonicalize` npm package (RFC 8785 implementation).
 *
 * Spec note: §14.6 universal signature scheme test vectors include canonicalization
 * round-trip tests. This module is the surface those vectors exercise.
 */
/** Return JCS canonical UTF-8 bytes for any JSON value. Throws if input contains non-JSON-encodable values. */
export declare function jcsCanonical(value: unknown): Uint8Array;
/** SHA-256 of JCS canonical bytes for a value. Returns 32-byte hash. */
export declare function jcsHash(value: unknown): Uint8Array;
/** Hex-encoded SHA-256 of JCS canonical bytes — convenience for logs/receipts. */
export declare function jcsHashHex(value: unknown): string;
