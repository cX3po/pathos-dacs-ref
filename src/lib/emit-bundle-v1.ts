/**
 * DACS-5 AttestationBundle EMISSION — v0.1 only (§10.4.1).
 *
 * This is the sanctioned emission path post-cutover (re-pin step 5): the reference impl emits
 * ONLY the v0.1 `AttestationBundleV1`. The legacy `AttestationBundle` (`dacs-5-bundle:0.1`) is
 * @deprecated and is RETAINED for dual-accept READS only (§10.4.2 backwards-compat) — there is
 * no legacy emitter.
 *
 * Signing (§10.4.1 + R5-1):
 *   bundle_hash  := sha256(JCS(bundle with `signatures` AND `anchoredByRole` omitted)), hex
 *   signed_bytes := "dacs-bundle:v1:" || bundle_hash                  (single-hash)
 * Each party's primary-claim key signs `signed_bytes`. This is byte-for-byte what
 * verifyBundleV1 reconstructs and verifies (SIG-2), so emit -> verify round-trips. The signed
 * scope is the SHARED bundleSignedScopeHashV1 definition (anchoredByRole excluded per R5-1).
 */
import type { AttestationBundleV1, BundleSignature } from '../types/bundle.js';
import type { ClaimReference } from '../types/identity.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { sign } from './sign.js';
import { bundleSignedScopeHashV1 } from './bundle-signed-scope-v1.js';

const enc = new TextEncoder();

/** A signer: the primary claim it presents + the ed25519 private key that controls it. */
export interface BundleSigner {
  party: ClaimReference | string; // §B.1 — string "Scheme:Identifier" is the canonical claim form
  privKey: Uint8Array;
  algorithm?: BundleSignature['algorithm']; // default 'ed25519'
}

/**
 * Emit a signed v0.1 AttestationBundleV1. `unsigned` is the full §10.4 bundle minus `signatures`.
 * Returns the bundle with one signature per supplied signer, each over
 * "dacs-bundle:v1:" || bundle_hash (single-hash, §10.4.1).
 */
export function emitAttestationBundleV1(
  unsigned: Omit<AttestationBundleV1, 'signatures'>,
  signers: BundleSigner[],
): AttestationBundleV1 {
  if (!signers.length) throw new Error('emitAttestationBundleV1: at least one signer is required (§10.4.1)');
  const bundleHash = bundleSignedScopeHashV1(unsigned); // signed scope = bundle without `signatures` AND `anchoredByRole` (R5-1)
  const signatures: BundleSignature[] = signers.map((s) => ({
    party: s.party,
    algorithm: s.algorithm ?? 'ed25519',
    value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), s.privKey)).toString('base64'),
  }));
  return { ...unsigned, signatures };
}
