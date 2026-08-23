/**
 * partner-kit/domain-sep.mjs — DACS v0.1 universal-signature domain separators (CORE §B.7).
 *
 * NON-NORMATIVE partner-kit port of `src/domain-sep.ts` (pathos-dacs-ref) — the closed
 * v0.1 registry, the read-only legacy set, the SIG-4 `dacs-x-` extensions, and the
 * PATH-OS Labs extension siblings, with the same closure rules:
 *  - assertKnownSeparator: unknown separator MUST fail (§B.7 / SIG-1..4 closure).
 *  - assertEmittableSeparator: read-only legacy separators MUST never sign new artifacts.
 * The normative source of truth is the DACS spec + the reference impl; see MANIFEST.json
 * for the exact source commit this port was taken from.
 */

export const DOMAIN_SEPARATORS = {
  LISTING: 'dacs-listing:v1:',
  BUNDLE_PRESENTATION: 'dacs-bundle-presentation:v1:',
  SESSION_BINDING: 'dacs-session-binding:v1:',
  COMPOSITE_VERIFY: 'dacs-composite:v1:',
  CHANNEL_MSG: 'dacs-channelmsg:v1:',
  AGREEMENT: 'dacs-agreement:v1:',
  COMMIT_AGREEMENT: 'dacs-commitment:v1:',
  SETTLEMENT_EVIDENCE: 'dacs-evidence:v1:',
  BUNDLE: 'dacs-bundle:v1:',
  REPUTATION_ATTESTATION: 'dacs-rating:v1:',
};

/** Read-only (§10.4.2 backwards-compat): verify/read path ONLY, never emission. */
export const LEGACY_READ_SEPARATORS = {
  BUNDLE_DACS5: 'dacs5-bundle:v1:',
};

/** SIG-4 `dacs-x-` extension separators (kinds not in the v0.1 closed table). */
export const DACS_X_EXTENSION_SEPARATORS = {
  ATTESTATION_REF: 'dacs-x-attestation-ref:v1:',
  CONSENSUS_PROXY_COMMIT: 'dacs-x-cbp-commit:v1:',
  RULE_REF_COMMIT: 'dacs-x-rule-ref:v1:',
  PAYMENT_AUTH: 'dacs-x-payment-auth:v1:',
  DELIVERY_RECEIPT: 'dacs-x-delivery-receipt:v1:',
  SESSION_RECORD: 'dacs-x-session-record:v1:',
  SEALED_ENVELOPE_OPEN: 'dacs-x-sealed-envelope-open:v1:',
  CLAIM_COMMIT: 'dacs-x-claim-commit:v1:',
  CLAIM_REVEAL: 'dacs-x-claim-reveal:v1:',
  CONSENT: 'dacs-x-consent:v1:',
  DISPUTE_BUNDLE: 'dacs-x-dispute-bundle:v1:',
};

/** PATH-OS Labs extension separators (non-normative siblings, distinguishable by map). */
export const PATHOS_EXTENSION_SEPARATORS = {
  CROSS_VPS_ATTESTATION: 'dacs-cross-vps-attestation:v1:',
  BRIDGE_RELEASE_ATTESTATION: 'dacs-bridge-release-attestation:v1:',
  TANK_LOCK_ATTESTATION: 'dacs-tank-lock-attestation:v1:',
  TANK_REFUND_ATTESTATION: 'dacs-tank-refund-attestation:v1:',
};

/** §B.7 closure rule — throws on any separator outside the four maps above. */
export function assertKnownSeparator(sep) {
  const known = [
    ...Object.values(DOMAIN_SEPARATORS),
    ...Object.values(LEGACY_READ_SEPARATORS),
    ...Object.values(DACS_X_EXTENSION_SEPARATORS),
    ...Object.values(PATHOS_EXTENSION_SEPARATORS),
  ];
  if (!known.includes(sep)) {
    throw new Error(
      `Unknown domain separator: "${sep}". DACS §B.7 declares a closed v0.1 registry; ` +
      `experimental kinds MUST use the dacs-x-<kind>:v1: form (SIG-4).`
    );
  }
}

const LEGACY_READ_SET = new Set(Object.values(LEGACY_READ_SEPARATORS));

/** True iff `sep` is a read-only legacy separator. */
export function isLegacyReadSeparator(sep) {
  return LEGACY_READ_SET.has(sep);
}

/** Emission-path closure: everything assertKnownSeparator admits EXCEPT read-only legacy. */
export function assertEmittableSeparator(sep) {
  if (isLegacyReadSeparator(sep)) {
    throw new Error(
      `Refusing to sign under read-only legacy separator "${sep}". ` +
      `LEGACY_READ_SEPARATORS are admitted on the VERIFY/read path only (§10.4.2 backwards-compat); ` +
      `emission MUST use a current DOMAIN_SEPARATORS entry (canonical: "${DOMAIN_SEPARATORS.BUNDLE}").`
    );
  }
  assertKnownSeparator(sep);
}

/** signed_bytes := separator || [intermediateHash ||] body — byte-identical to src/domain-sep.ts. */
export function buildSignedBytes(separator, bodyBytes, intermediateHash) {
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
