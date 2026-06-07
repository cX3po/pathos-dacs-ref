/**
 * DACS-1 IdentityBundle presentation — sign + verify (v0.1 §6.3.2).
 *
 * Spec source: DACS-1 v0.1 §6.3.2 (VERIFIED, memory/dacs_review/DACS-1-IDENTIFY.md:147-159).
 *
 * The v0.1 domain-separated payload is SINGLE-HASH (corrected from the v0.7 composite form):
 *
 *   bundle_hash  := sha256(JCS(bundle with `presentation` omitted)), hex          (:157)
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash                 (:149)
 *
 * All four presentation kinds bind to the SAME `signed_bytes` (:147):
 *   - per-claim   — each per-claim signature signs `signed_bytes` (:151)
 *   - session-key — the session key signs `signed_bytes`; if `rootBinding` is set, the root key
 *                   additionally signs "dacs-session-binding:v1:" || session_key || bundle_hash (:152)
 *   - sr1-root    — the SR-1 aggregate signature signs `signed_bytes` (:153)
 *   - siwd        — the wallet signs the SIWD message which carries `dacs:<hex(signed_bytes)>`
 *                   as an EIP-4361 Resources entry (:154)
 *
 * This module implements the bytes-level scheme + the two presentation kinds whose signatures
 * are raw ed25519 over `signed_bytes` (per-claim, session-key). siwd/sr1-root require Demos-wallet
 * / SR-1 aggregate infrastructure not present in this reference impl; for those kinds the helpers
 * compute + expose `signed_bytes` (so callers can drive the wallet/SR-1 signer) but do not produce
 * or cryptographically verify the outer signature here.
 */
import * as ed25519 from '@noble/ed25519';
import type { IdentityBundle, ClaimReference, PresentationSignature } from '../types/identity.js';
import { DOMAIN_SEPARATORS, buildSignedBytes } from '../domain-sep.js';
import { jcsHash } from '../jcs.js';
import { bytesToHex, hexToBytes } from './verify-bundle.js';
// Importing sign.js wires @noble/ed25519's required sync sha512 (etc.sha512Sync) as a side effect,
// so the low-level ed25519.sign/verify primitives used below are usable synchronously.
import './sign.js';

const enc = new TextEncoder();

/**
 * bundle_hash = sha256(JCS(bundle with `presentation` omitted)), 32 bytes (§6.3.2 :157).
 * The presentation field is the ONLY field omitted from the canonical form.
 */
export function bundleHashBytes(bundle: IdentityBundle): Uint8Array {
  // Strip the presentation field (and only that) before canonicalising.
  const { presentation: _omit, ...unsigned } = bundle;
  void _omit;
  return jcsHash(unsigned);
}

/** Hex-encoded bundle_hash (§6.3.2 :157). */
export function bundleHashHex(bundle: IdentityBundle): string {
  return bytesToHex(bundleHashBytes(bundle));
}

/**
 * signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash  (§6.3.2 :149, SINGLE-HASH).
 * `bundle_hash` is the ASCII hex string (not the raw 32 bytes) — concatenated as UTF-8 with the
 * separator, matching the §B.7 `domain_separator || artifact_hash` (hex string) convention
 * used everywhere else in this impl (CORE.md:266) and by verify-bundle-v1.ts for DACS-5.
 */
export function presentationSignedBytes(bundle: IdentityBundle): Uint8Array {
  const hashHex = bundleHashHex(bundle);
  return buildSignedBytes(DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, enc.encode(hashHex));
}

/**
 * The EIP-4361 Resources URI a SIWD message MUST carry (§6.3.2 :154,:159):
 *   dacs:<hex>  where <hex> = lowercase-hex(signed_bytes)
 * i.e. dacs: followed by hex("dacs-bundle-presentation:v1:" || bundle_hash).
 */
export function siwdResourceUri(bundle: IdentityBundle): string {
  return `dacs:${bytesToHex(presentationSignedBytes(bundle))}`;
}

/**
 * Sign a per-claim presentation: every key in `claimKeys` signs the SINGLE-HASH `signed_bytes`.
 * `claimKeys` maps each signing claim's ed25519 key to the ClaimReference it covers.
 */
export function signPerClaimPresentation(
  bundle: Omit<IdentityBundle, 'presentation'>,
  claimKeys: { ref: ClaimReference; privKey: Uint8Array }[],
): PresentationSignature {
  const signed = presentationSignedBytesFromUnsigned(bundle);
  return {
    kind: 'per-claim',
    signatures: claimKeys.map(({ ref, privKey }) => ({
      ref,
      signature: Buffer.from(edSignPrimitive(signed, privKey)).toString('base64'),
    })),
  };
}

/**
 * Sign a session-key presentation: the session key signs `signed_bytes`. If `rootKey` is supplied,
 * the root key additionally signs the COMPOSITE "dacs-session-binding:v1:" || session_key || bundle_hash
 * (§6.3.2 :152) and the result is carried in `rootBinding`.
 */
export function signSessionKeyPresentation(
  bundle: Omit<IdentityBundle, 'presentation'>,
  sessionPrivKey: Uint8Array,
  sessionPubKeyHex: string,
  rootPrivKey?: Uint8Array,
): PresentationSignature {
  const signed = presentationSignedBytesFromUnsigned(bundle);
  const out: Extract<PresentationSignature, { kind: 'session-key' }> = {
    kind: 'session-key',
    key: sessionPubKeyHex,
    signature: Buffer.from(edSignPrimitive(signed, sessionPrivKey)).toString('base64'),
  };
  if (rootPrivKey) {
    const hashBytes = bundleHashBytesFromUnsigned(bundle);
    // COMPOSITE: sep || session_key (hex) || bundle_hash (hex).
    const composite = buildSignedBytes(
      DOMAIN_SEPARATORS.SESSION_BINDING,
      enc.encode(sessionPubKeyHex + bytesToHex(hashBytes)),
    );
    out.rootBinding = Buffer.from(edSignPrimitive(composite, rootPrivKey)).toString('base64');
  }
  return out;
}

export type PresentationCheck = {
  decision: 'pass' | 'fail' | 'unverifiable';
  reason?: string;
  /** per-claim/session-key signature checks */
  signatureChecks?: { who: string; decision: 'pass' | 'fail' | 'unverifiable'; reason?: string }[];
};

/**
 * Verify an IdentityBundle presentation (§6.3.2). Recomputes bundle_hash + signed_bytes
 * independently (SIG-2) and verifies the kind-appropriate signature(s).
 *
 * - presentedBy MUST resolve to a member of `claims` (:172).
 * - per-claim   — every listed signature must verify over signed_bytes against its claim key.
 * - session-key — the session key must verify over signed_bytes; rootBinding (if present) must
 *                 verify over the composite session-binding payload against `rootKey`.
 * - siwd/sr1-root — `unverifiable` here (requires Demos-wallet / SR-1 infra); the caller drives
 *                   those via siwdResourceUri() + the wallet / SR-1 verifier.
 *
 * `keyResolver` resolves a ClaimReference to its raw ed25519 key (cci scheme = raw hex key);
 * a claim that does not resolve to a 32-byte key is `unverifiable`, not `fail`.
 */
export function verifyBundlePresentation(
  bundle: IdentityBundle,
  opts: { rootKeyHex?: string; keyResolver?: (ref: ClaimReference) => Uint8Array | null } = {},
): PresentationCheck {
  const resolver = opts.keyResolver ?? defaultCciKeyResolver;

  // presentedBy must resolve to a listed claim (§6.3.2 :172).
  const claimsKeySet = new Set(bundle.claims.map((c) => claimKey(c.ref)));
  if (!claimsKeySet.has(claimKey(bundle.presentedBy))) {
    return { decision: 'fail', reason: 'presentedBy does not resolve to a member of claims (§6.3.2)' };
  }

  const signed = presentationSignedBytes(bundle);
  const p = bundle.presentation;

  if (p.kind === 'siwd' || p.kind === 'sr1-root') {
    return {
      decision: 'unverifiable',
      reason: `presentation.kind="${p.kind}" requires Demos-wallet / SR-1 infrastructure not present in this reference impl; ` +
        `use siwdResourceUri()/SR-1 verifier. signed_bytes binding is computed and available.`,
    };
  }

  if (p.kind === 'per-claim') {
    if (!p.signatures.length) return { decision: 'fail', reason: 'per-claim presentation has no signatures' };
    const checks = p.signatures.map((s) => {
      const kb = resolver(s.ref);
      if (!kb) return { who: claimKey(s.ref), decision: 'unverifiable' as const, reason: 'claim does not resolve to a 32-byte ed25519 key' };
      const sig = decodeB64Sig(s.signature);
      if (!sig) return { who: claimKey(s.ref), decision: 'fail' as const, reason: 'signature is not a valid 64-byte signature' };
      const ok = edVerifyRaw(signed, sig, kb);
      return { who: claimKey(s.ref), decision: ok ? ('pass' as const) : ('fail' as const), reason: ok ? undefined : 'does not verify over signed_bytes' };
    });
    if (checks.some((c) => c.decision === 'fail')) return { decision: 'fail', reason: 'a per-claim signature failed', signatureChecks: checks };
    if (checks.some((c) => c.decision === 'unverifiable')) return { decision: 'unverifiable', reason: 'a per-claim signer did not resolve to a key', signatureChecks: checks };
    return { decision: 'pass', signatureChecks: checks };
  }

  // session-key
  const sessKb = hexKey(p.key);
  if (!sessKb) return { decision: 'fail', reason: 'session-key.key is not a 32-byte hex ed25519 key' };
  const sessSig = decodeB64Sig(p.signature);
  if (!sessSig) return { decision: 'fail', reason: 'session-key.signature is not a valid 64-byte signature' };
  if (!edVerifyRaw(signed, sessSig, sessKb)) {
    return { decision: 'fail', reason: 'session key does not verify over signed_bytes' };
  }
  if (p.rootBinding !== undefined) {
    if (!opts.rootKeyHex) return { decision: 'unverifiable', reason: 'rootBinding present but no rootKeyHex supplied to verify it' };
    const rootKb = hexKey(opts.rootKeyHex);
    if (!rootKb) return { decision: 'fail', reason: 'rootKeyHex is not a 32-byte hex ed25519 key' };
    const rootSig = decodeB64Sig(p.rootBinding);
    if (!rootSig) return { decision: 'fail', reason: 'rootBinding is not a valid 64-byte signature' };
    const hashBytes = bundleHashBytes(bundle);
    const composite = buildSignedBytes(DOMAIN_SEPARATORS.SESSION_BINDING, enc.encode(p.key + bytesToHex(hashBytes)));
    if (!edVerifyRaw(composite, rootSig, rootKb)) {
      return { decision: 'fail', reason: 'rootBinding does not verify over the session-binding composite payload (§6.3.2)' };
    }
  }
  return { decision: 'pass' };
}

// ── internal helpers ────────────────────────────────────────────────────────

function bundleHashBytesFromUnsigned(bundle: Omit<IdentityBundle, 'presentation'>): Uint8Array {
  return jcsHash(bundle);
}
function presentationSignedBytesFromUnsigned(bundle: Omit<IdentityBundle, 'presentation'>): Uint8Array {
  return buildSignedBytes(DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, enc.encode(bytesToHex(bundleHashBytesFromUnsigned(bundle))));
}

// noble sign/verify over the fully-built signed_bytes (which already carries the domain
// separator via buildSignedBytes), so we do not double-prepend a separator. The separator
// discipline is enforced at construction time (buildSignedBytes only takes registry separators).
function edSignPrimitive(msg: Uint8Array, privKey: Uint8Array): Uint8Array {
  return ed25519.sign(msg, privKey);
}
function edVerifyRaw(msg: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pubKey);
  } catch {
    return false;
  }
}

function claimKey(c: ClaimReference): string {
  const id = c.scheme === 'cci' ? c.identifier.replace(/^0x/i, '').toLowerCase() : c.identifier;
  return `${c.scheme}:${id}`;
}

/** Default resolver: only `cci` claims (raw 64-hex ed25519 key) resolve to a key. */
function defaultCciKeyResolver(ref: ClaimReference): Uint8Array | null {
  if (ref.scheme !== 'cci') return null;
  return hexKey(ref.identifier);
}

function hexKey(hex: string): Uint8Array | null {
  const clean = hex.replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) return null;
  try {
    return hexToBytes(clean);
  } catch {
    return null;
  }
}

function decodeB64Sig(v: string): Uint8Array | null {
  try {
    const out = new Uint8Array(Buffer.from(v, 'base64'));
    return out.length === 64 ? out : null;
  } catch {
    return null;
  }
}
