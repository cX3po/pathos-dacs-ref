/**
 * DACS v0.7 universal signature scheme — domain separators (§7.7)
 *
 * Closed registry. The §7.7 closure rule: callers passing an unknown separator
 * MUST fail. This file is the single source of truth.
 *
 * Every signature produced by any DACS implementation has the form:
 *
 *   signed_bytes := <domain_separator> || <payload_hash_or_payload_bytes>
 *
 * The exact body after the separator depends on the artifact (see each constant's comment).
 *
 * v1 list extracted from DACS v0.7 §7.7. When v2 ships, this file gains a sibling map
 * and consumers MUST support both (§10.4.2 backwards-compat note).
 */

/** Closed registry — 17 separators. Adding new ones requires DACS spec revision. */
export const DOMAIN_SEPARATORS = {
  // DACS-1 Identify
  LISTING: 'dacs-listing:v1:',                              // signed_bytes = sep || JCS(unsignedListing)
  BUNDLE_PRESENTATION: 'dacs-bundle-presentation:v1:',      // signed_bytes = sep || bundleHash || JCS(payload)
  SESSION_KEY_AUTH: 'dacs-session-key-auth:v1:',            // signed_bytes = sep || sessionPubkey

  // DACS-2 Vet
  ATTESTATION_REF: 'dacs-attestation-ref:v1:',              // signed_bytes = sep || JCS(attestationRef)
  COMPOSITE_VERIFY: 'dacs-composite-verify:v1:',            // signed_bytes = sep || JCS(record)
  CONSENSUS_PROXY_COMMIT: 'dacs-cbp-commit:v1:',            // signed_bytes = sep || responseHash || JCS(requestSpec)

  // DACS-3 Negotiate
  CHANNEL_MSG: 'dacs-channelmsg:v1:',                       // signed_bytes = sep || JCS(envelope) — every channel message
  AGREEMENT: 'dacs-agreement:v1:',                          // signed_bytes = sep || JCS(agreementDocument)
  COMMIT_AGREEMENT: 'dacs-commit-agreement:v1:',            // signed_bytes = sep || agreementHash || JCS(commitContext)
  SEALED_ENVELOPE_OPEN: 'dacs-sealed-envelope-open:v1:',    // signed_bytes = sep || envelopeContentHash
  RULE_REF_COMMIT: 'dacs-rule-ref:v1:',                     // signed_bytes = sep || ruleContentHash

  // DACS-4 Settle
  SETTLEMENT_EVIDENCE: 'dacs-settlement-evidence:v1:',      // signed_bytes = sep || JCS(evidence)
  PAYMENT_AUTH: 'dacs-payment-auth:v1:',                    // signed_bytes = sep || JCS(authPayload)
  DELIVERY_RECEIPT: 'dacs-delivery-receipt:v1:',            // signed_bytes = sep || JCS(deliveryPayload)

  // DACS-5 Verify
  BUNDLE_DACS5: 'dacs5-bundle:v1:',                         // signed_bytes = sep || bundleHash (per §10.4.2 — preserved from reference impl)
  REPUTATION_ATTESTATION: 'dacs-reputation:v1:',            // signed_bytes = sep || JCS(repBlob)
  SESSION_RECORD: 'dacs-session-record:v1:',                // signed_bytes = sep || JCS(sessionRecord)
} as const;

export type DomainSeparator = (typeof DOMAIN_SEPARATORS)[keyof typeof DOMAIN_SEPARATORS];
export type DomainSeparatorKey = keyof typeof DOMAIN_SEPARATORS;

/** §7.7 closure rule. Throws on unknown separator. */
export function assertKnownSeparator(sep: string): asserts sep is DomainSeparator {
  const known: string[] = Object.values(DOMAIN_SEPARATORS);
  if (!known.includes(sep)) {
    throw new Error(
      `Unknown domain separator: "${sep}". DACS §7.7 declares a closed v1 registry. ` +
      `Known separators: ${known.join(', ')}`
    );
  }
}

/** Build the signed_bytes for a payload + separator + optional intermediate hash. */
export function buildSignedBytes(
  separator: DomainSeparator,
  bodyBytes: Uint8Array,
  intermediateHash?: Uint8Array
): Uint8Array {
  const sepBytes = new TextEncoder().encode(separator);
  if (intermediateHash) {
    const out = new Uint8Array(sepBytes.length + intermediateHash.length + bodyBytes.length);
    out.set(sepBytes, 0);
    out.set(intermediateHash, sepBytes.length);
    out.set(bodyBytes, sepBytes.length + intermediateHash.length);
    return out;
  }
  const out = new Uint8Array(sepBytes.length + bodyBytes.length);
  out.set(sepBytes, 0);
  out.set(bodyBytes, sepBytes.length);
  return out;
}
