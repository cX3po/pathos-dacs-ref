import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { canonicalize, withoutSignature } from "./canonicalize.ts";
import { sha256Hex } from "./hash.ts";

// DACS §7.7 — universal domain-separated signing.
//   signed_bytes := domain_separator || artifact_hash
//   domain_separator := "dacs-" || artifact_kind || ":v" || version || ":"
//   artifact_hash    := lowercase hex sha256 of the JCS canonical form
//                       (signature field(s) omitted)
// The separator and hash are concatenated as UTF-8 byte sequences with NO
// separator byte (the separator is a UTF-8 string, the hash an ASCII hex
// string). §7.7 declares this registry CLOSED; SIG-4 requires any unlisted
// artifact kind to use a "dacs-x-..." separator.

export const DOMAIN_SEPARATOR_REGISTRY = Object.freeze({
  "dacs-1-listing": "dacs-listing:v1:",
  "dacs-1-revocation": "dacs-revocation:v1:",
  "dacs-1-bundle-presentation": "dacs-bundle-presentation:v1:",
  "dacs-2-verifyresult": "dacs-verifyresult:v1:",
  "dacs-2-composite": "dacs-composite:v1:",
  "dacs-2-recipe": "dacs-recipe:v1:",
  "dacs-3-channelmsg": "dacs-channelmsg:v1:",
  "dacs-3-agreement": "dacs-agreement:v1:",
  "dacs-3-commitment": "dacs-commitment:v1:",
  "dacs-3-transcript": "dacs-transcript:v1:",
  "dacs-4-evidence": "dacs-evidence:v1:",
  "dacs-4-amendment": "dacs-amendment:v1:",
  "dacs-4-rail": "dacs-rail:v1:",
  "dacs-4-entitlement": "dacs-entitlement:v1:",
  "dacs-5-bundle": "dacs-bundle:v1:",
  "dacs-5-rating": "dacs-rating:v1:",
} as const);

export type ArtifactKind = keyof typeof DOMAIN_SEPARATOR_REGISTRY;

const REGISTERED_SEPARATORS: ReadonlySet<string> = new Set(
  Object.values(DOMAIN_SEPARATOR_REGISTRY),
);

/**
 * True iff `separator` is in the §7.7 closed registry. A separator that is used
 * in the spec body but absent here is a registry inconsistency (see findings).
 */
export function isRegisteredSeparator(separator: string): boolean {
  return REGISTERED_SEPARATORS.has(separator);
}

/** Build the §7.7 signed-bytes payload from a separator and a sha256 hex hash. */
export function buildSignedBytes(separator: string, artifactHashHex: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(artifactHashHex)) {
    throw new Error("artifact hash must be 64 lowercase-hex chars (sha256)");
  }
  return Buffer.concat([
    Buffer.from(separator, "utf8"),
    Buffer.from(artifactHashHex, "ascii"),
  ]);
}

/** Verify an Ed25519 signature given a raw 32-byte public key. */
export function verifyEd25519(
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKeyRaw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const key = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKeyRaw).toString("base64url") },
    format: "jwk",
  });
  return nodeVerify(null, message, key, signature);
}

export interface ArtifactSignatureCheck {
  kind: ArtifactKind;
  /** The document, signature field(s) included; the signed scope omits them. */
  doc: Record<string, unknown>;
  publicKeyRaw: Uint8Array;
  signatureRaw: Uint8Array;
  /** Signature field name(s) to omit from the signed scope (default both). */
  signatureFields?: string[];
}

export interface ArtifactSignatureResult {
  ok: boolean;
  separator: string;
  artifactHash: string;
  reason?: string;
}

export interface ArtifactSignatureCheckBySeparator {
  /** The §7.7 (or SIG-4 extension) domain separator string, used verbatim. */
  separator: string;
  doc: Record<string, unknown>;
  publicKeyRaw: Uint8Array;
  signatureRaw: Uint8Array;
  signatureFields?: string[];
}

/**
 * §7.7 verification given an explicit domain separator: canonicalize the signed
 * scope, hash it, build the domain-separated payload, verify Ed25519. This is
 * the general path — it accepts ANY separator, including the SIG-4 `dacs-x-*`
 * extension separators that are not in the spec's closed registry. Registry
 * membership is NOT checked here; callers that require a registered kind use
 * {@link verifyArtifactSignature}.
 */
export function verifyArtifactSignatureWithSeparator(
  c: ArtifactSignatureCheckBySeparator,
): ArtifactSignatureResult {
  const separator = c.separator;
  const signedScope = withoutSignature(c.doc, ...(c.signatureFields ?? []));
  const artifactHash = sha256Hex(canonicalize(signedScope));
  const signedBytes = buildSignedBytes(separator, artifactHash);
  let ok = false;
  let reason: string | undefined;
  try {
    ok = verifyEd25519(c.publicKeyRaw, signedBytes, c.signatureRaw);
    if (!ok) reason = "Ed25519 signature did not verify against signed bytes";
  } catch (e) {
    reason = `verification error: ${(e as Error).message}`;
  }
  return reason === undefined ? { ok, separator, artifactHash } : { ok, separator, artifactHash, reason };
}

/**
 * Full §7.7 verification path for a REGISTERED artifact kind: resolves the
 * separator from the closed §7.7 registry, then delegates to
 * {@link verifyArtifactSignatureWithSeparator}.
 */
export function verifyArtifactSignature(c: ArtifactSignatureCheck): ArtifactSignatureResult {
  return verifyArtifactSignatureWithSeparator({
    separator: DOMAIN_SEPARATOR_REGISTRY[c.kind],
    doc: c.doc,
    publicKeyRaw: c.publicKeyRaw,
    signatureRaw: c.signatureRaw,
    // Omit the key entirely when absent (exactOptionalPropertyTypes): never pass undefined.
    ...(c.signatureFields !== undefined ? { signatureFields: c.signatureFields } : {}),
  });
}
