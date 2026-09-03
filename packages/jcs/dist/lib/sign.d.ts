/**
 * ed25519 signing with DACS domain separation
 *
 * Spec source: DACS v0.7 §7.7 (universal signature scheme).
 *
 * Every DACS signature is:
 *   sig := Ed25519.sign(domain_separator || body_or_hash, privKey)
 *
 * where `domain_separator` is from the closed registry in src/domain-sep.ts
 * (§7.7 closure rule).
 *
 * Wraps `@noble/ed25519` to enforce the domain-separator discipline. Callers
 * cannot sign or verify with an unknown separator.
 */
import { type DomainSeparator } from '../domain-sep.js';
/**
 * Sign `body` with `separator` and `privKey`.
 *
 * For DACS-1 IdentityBundle and DACS-5 AttestationBundle:
 *   pass `intermediateHash` = the bundleHash, and `body` = JCS canonical bytes of payload.
 *   Per §6.3.2 / §10.4.2: signed_bytes = separator || bundleHash || JCS(payload).
 *
 * For DACS-1 Listing and most DACS-2 / DACS-3 / DACS-4 signatures:
 *   omit `intermediateHash`; signed_bytes = separator || JCS(payload).
 *
 * Throws if separator is not in the §7.7 closed registry, OR if it is a read-only
 * LEGACY_READ_SEPARATOR (those are admitted on the verify/read path only — emission MUST use a
 * current DOMAIN_SEPARATORS entry; see assertEmittableSeparator).
 */
export declare function sign(separator: DomainSeparator | string, body: Uint8Array, privKey: Uint8Array, intermediateHash?: Uint8Array): Uint8Array;
/**
 * Verify `sig` against `body` with `separator` and `pubKey`.
 *
 * Returns true iff the signature is valid AND the separator is in the §7.7 closed registry.
 * Returns false (NOT throws) on unknown separator — verifier callers MUST distinguish
 * "signature invalid" from "unknown separator" themselves if needed; we treat both as
 * a verification failure for the purpose of DACS-5 §10.4.1 walk.
 */
export declare function verify(separator: DomainSeparator | string, sig: Uint8Array, body: Uint8Array, pubKey: Uint8Array, intermediateHash?: Uint8Array): boolean;
/** Generate a fresh ed25519 keypair. */
export declare function generateKeypair(): {
    privKey: Uint8Array;
    pubKey: Uint8Array;
};
