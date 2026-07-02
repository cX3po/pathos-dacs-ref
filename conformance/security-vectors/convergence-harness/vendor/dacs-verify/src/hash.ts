import { createHash } from "node:crypto";
import { canonicalize, withoutSignature } from "./canonicalize.ts";

/** Lowercase hex sha256 of raw bytes or a UTF-8 string. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * DACS "content hash" (§7.2): sha256 hex of the RFC 8785 JCS canonical form.
 * Pass the document with its signature field(s) already removed, or use
 * {@link contentHashSignedScope}.
 */
export function contentHash(doc: unknown): string {
  return sha256Hex(canonicalize(doc));
}

/** Content hash over the signed scope (signature field(s) omitted). */
export function contentHashSignedScope<T extends Record<string, unknown>>(
  doc: T,
  ...signatureFields: string[]
): string {
  return sha256Hex(canonicalize(withoutSignature(doc, ...signatureFields)));
}
