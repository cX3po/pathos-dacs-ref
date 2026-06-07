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

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { buildSignedBytes, type DomainSeparator, assertKnownSeparator, assertEmittableSeparator } from '../domain-sep.js';

// @noble/ed25519 v2 requires a sync sha512 to be wired in for sync sign/verify.
// Per @noble/ed25519@2.3.x API: etc.sha512Sync = (...m) => sha512(etc.concatBytes(...m));
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

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
export function sign(
  separator: DomainSeparator | string,
  body: Uint8Array,
  privKey: Uint8Array,
  intermediateHash?: Uint8Array
): Uint8Array {
  assertEmittableSeparator(separator);
  const signedBytes = buildSignedBytes(separator, body, intermediateHash);
  return ed25519.sign(signedBytes, privKey);
}

/**
 * Verify `sig` against `body` with `separator` and `pubKey`.
 *
 * Returns true iff the signature is valid AND the separator is in the §7.7 closed registry.
 * Returns false (NOT throws) on unknown separator — verifier callers MUST distinguish
 * "signature invalid" from "unknown separator" themselves if needed; we treat both as
 * a verification failure for the purpose of DACS-5 §10.4.1 walk.
 */
export function verify(
  separator: DomainSeparator | string,
  sig: Uint8Array,
  body: Uint8Array,
  pubKey: Uint8Array,
  intermediateHash?: Uint8Array
): boolean {
  try {
    assertKnownSeparator(separator);
  } catch {
    return false;
  }
  const signedBytes = buildSignedBytes(separator, body, intermediateHash);
  try {
    return ed25519.verify(sig, signedBytes, pubKey);
  } catch {
    return false;
  }
}

/** Generate a fresh ed25519 keypair. */
export function generateKeypair(): { privKey: Uint8Array; pubKey: Uint8Array } {
  const privKey = ed25519.utils.randomPrivateKey();
  const pubKey = ed25519.getPublicKey(privKey);
  return { privKey, pubKey };
}
