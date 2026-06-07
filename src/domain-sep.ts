/**
 * DACS v0.1 universal signature scheme — domain separators (CORE §B.7)
 *
 * Closed registry. The §B.7 / SIG-1..4 closure rule: callers passing a separator
 * outside the registry (or the sanctioned `dacs-x-` extension form) MUST fail.
 * This file is the single source of truth.
 *
 * Every signature produced by any DACS implementation has the form:
 *
 *   signed_bytes := <domain_separator> || <artifact_hash>            (single-hash, the common case)
 *   signed_bytes := <domain_separator> || <h1> || <h2> || …          (composite — sanctioned exceptions, CORE §B.7)
 *
 * The exact body after the separator depends on the artifact (see each constant's comment).
 *
 * v1 list aligned to the v0.1 §B.7 closed registry (CORE.md:237-259), VERIFIED against the
 * published spec copy 2026-06-07. `version_tag` is the MAJOR version: every v0.1..v0.x kind
 * signs under `:v1:` and the registry stays frozen across minor bumps (CORE §B.7 version_tag binding).
 * When a v2 MAJOR ships, this file gains a sibling map and consumers MUST support both (SIG-5).
 *
 * SIG-4 extension rule: an artifact kind NOT in the v0.1 table MUST use a separator of the form
 * `dacs-x-<kind>:v1:` until accepted into a future registry version. The PATHOS_EXTENSION and
 * DACS_X_EXTENSION maps below carry those; they are admitted by assertKnownSeparator() but a
 * spec-conformance auditor can distinguish them from the closed §B.7 set by their map of origin.
 */

/**
 * v0.1 §B.7 closed-registry separators that this reference impl uses, aligned to CORE.md:237-259.
 * (The full §B.7 registry has 20 entries; this map carries only the kinds our code signs/verifies
 * plus the ones it has historically declared, each now mapped to its canonical v0.1 string.)
 * Adding new ones requires a DACS spec revision — use the `dacs-x-` extension form for experiments.
 */
export const DOMAIN_SEPARATORS = {
  // DACS-1 Identify
  LISTING: 'dacs-listing:v1:',                              // §6.3.4 — signed_bytes = sep || JCS-hash(unsignedListing)
  BUNDLE_PRESENTATION: 'dacs-bundle-presentation:v1:',      // §6.3.2 — signed_bytes = sep || bundle_hash (single-hash)
  SESSION_BINDING: 'dacs-session-binding:v1:',             // §6.3.2 — COMPOSITE: sep || session_key || bundle_hash (session-key root binding)

  // DACS-2 Vet
  COMPOSITE_VERIFY: 'dacs-composite:v1:',                   // §7.7 — DACS-2 composite verification record

  // DACS-3 Negotiate
  CHANNEL_MSG: 'dacs-channelmsg:v1:',                       // §8.3.3 — every channel message
  AGREEMENT: 'dacs-agreement:v1:',                          // §8.5 — DACS-3 agreement document
  COMMIT_AGREEMENT: 'dacs-commitment:v1:',                  // §8.6 — DACS-3 commitment record

  // DACS-4 Settle
  SETTLEMENT_EVIDENCE: 'dacs-evidence:v1:',                 // §9.7 — DACS-4 settlement evidence

  // DACS-5 Verify
  BUNDLE: 'dacs-bundle:v1:',                                // §10.4.1 — DACS-5 attestation bundle: sep || bundle_hash (single-hash). Canonical EMISSION separator.
  REPUTATION_ATTESTATION: 'dacs-rating:v1:',                // §10.6 — DACS-5 rating record
} as const;

/**
 * READ-ONLY legacy separators (§10.4.2 backwards-compat).
 *
 * Before the v0.1 §B.7 cutover, the reference-impl legacy `AttestationBundle`
 * (`v: 'dacs-5-bundle:0.1'`) signed its bundle under the separator `dacs5-bundle:v1:`.
 * The §B.7 alignment (2026-06-07) replaced that with the canonical `dacs-bundle:v1:` for
 * EMISSION. Real pre-cutover artifacts on disk / on chain are still sealed under the OLD
 * string — so to honor §10.4.2 backwards-compatible READS we MUST keep recognising it.
 *
 * IMPORTANT: this map is for READING legacy `dacs-5-bundle:0.1` bundles ONLY. No code path
 * EMITS under these separators — new bundles always sign under `DOMAIN_SEPARATORS.BUNDLE`.
 * These are admitted by `assertKnownSeparator()` so the legacy verify path can pass the old
 * string to `verify()`, but they are intentionally NOT part of `DOMAIN_SEPARATORS` (the
 * canonical closed registry the emitters draw from).
 */
export const LEGACY_READ_SEPARATORS = {
  BUNDLE_DACS5: 'dacs5-bundle:v1:',                         // pre-cutover DACS-5 AttestationBundle signing separator (read-only)
} as const;

/**
 * SIG-4 extension separators for artifact kinds NOT in the v0.1 §B.7 closed registry.
 * CORE.md:265: "An artifact kind not in the v0.1 table MUST use a domain separator of the form
 * `dacs-x-<kind>:v1:` until accepted into a future version of the registry."
 *
 * These were declared in the legacy v0.7 registry under non-conformant names
 * (`dacs-attestation-ref`, `dacs-cbp-commit`, `dacs-rule-ref`, `dacs-payment-auth`,
 * `dacs-delivery-receipt`, `dacs-session-record`, `dacs-sealed-envelope-open`). None of them
 * has a clear v0.1 §B.7 registry entry, so per SIG-4 they move to the `dacs-x-` extension prefix.
 * (None of these are currently produced/verified by any signer in this repo — they are reserved
 * surfaces — so the move is registry-hygiene only with no signed-artifact impact.)
 */
export const DACS_X_EXTENSION_SEPARATORS = {
  ATTESTATION_REF: 'dacs-x-attestation-ref:v1:',
  CONSENSUS_PROXY_COMMIT: 'dacs-x-cbp-commit:v1:',
  RULE_REF_COMMIT: 'dacs-x-rule-ref:v1:',
  PAYMENT_AUTH: 'dacs-x-payment-auth:v1:',
  DELIVERY_RECEIPT: 'dacs-x-delivery-receipt:v1:',
  SESSION_RECORD: 'dacs-x-session-record:v1:',
  SEALED_ENVELOPE_OPEN: 'dacs-x-sealed-envelope-open:v1:',

  // dacs-disclose (selective-disclosure follow-on for DACS-1 §11.2.7) — SIG-4 extension
  // surface, salted-hash claim commitments + audience/challenge-bound reveals (no ZK/L2PS/FHE).
  //   CLAIM_COMMIT body  := salt_i || JCS(claim_i)             (attester-produced; see src/lib/disclose.ts)
  //   CLAIM_REVEAL body  := verifier_id || consent_receipt_id || nonce || expiry || commitment_i  (audience-bound)
  CLAIM_COMMIT: 'dacs-x-claim-commit:v1:',
  CLAIM_REVEAL: 'dacs-x-claim-reveal:v1:',
} as const;

/**
 * PATH-OS Labs extension separators — NOT part of the normative DACS v0.7 §7.7
 * closed registry, kept in a sibling map so the "exactly 17 spec separators"
 * invariant stays meaningful. These are admitted by assertKnownSeparator() and
 * usable by sign()/verify() exactly like spec separators, but a verifier auditing
 * spec-conformance can distinguish them by their map of origin.
 *
 * CROSS_VPS_ATTESTATION closes the DAHR single-node-relay trust gap (src/demos/dahr.ts):
 * one independent node signs its OWN response hash so an n-of-m quorum can agree.
 */
export const PATHOS_EXTENSION_SEPARATORS = {
  CROSS_VPS_ATTESTATION: 'dacs-cross-vps-attestation:v1:',  // signed_bytes = sep || utf8(responseHashHex)
  BRIDGE_RELEASE_ATTESTATION: 'dacs-bridge-release-attestation:v1:', // signed_bytes = sep || utf8(sha256-hex(JCS(releaseCommitment)))
  TANK_LOCK_ATTESTATION: 'dacs-tank-lock-attestation:v1:',  // signed_bytes = sep || utf8(sha256-hex(JCS(tankLockCommitment)))
  TANK_REFUND_ATTESTATION: 'dacs-tank-refund-attestation:v1:', // signed_bytes = sep || utf8(sha256-hex(JCS(tankRefundCommitment)))
} as const;

export type DomainSeparator =
  | (typeof DOMAIN_SEPARATORS)[keyof typeof DOMAIN_SEPARATORS]
  | (typeof LEGACY_READ_SEPARATORS)[keyof typeof LEGACY_READ_SEPARATORS]
  | (typeof DACS_X_EXTENSION_SEPARATORS)[keyof typeof DACS_X_EXTENSION_SEPARATORS]
  | (typeof PATHOS_EXTENSION_SEPARATORS)[keyof typeof PATHOS_EXTENSION_SEPARATORS];
export type DomainSeparatorKey = keyof typeof DOMAIN_SEPARATORS;

/**
 * §B.7 closure rule. Throws on unknown separator. Admits the closed v0.1 §B.7 registry
 * PLUS the SIG-4 `dacs-x-` extension separators (DACS_X_EXTENSION_SEPARATORS and the
 * PATH-OS Labs extension siblings) — all three maps follow the registry-or-`dacs-x-` discipline.
 */
export function assertKnownSeparator(sep: string): asserts sep is DomainSeparator {
  const known: string[] = [
    ...Object.values(DOMAIN_SEPARATORS),
    ...Object.values(LEGACY_READ_SEPARATORS),
    ...Object.values(DACS_X_EXTENSION_SEPARATORS),
    ...Object.values(PATHOS_EXTENSION_SEPARATORS),
  ];
  if (!known.includes(sep)) {
    throw new Error(
      `Unknown domain separator: "${sep}". DACS §B.7 declares a closed v0.1 registry; ` +
      `experimental kinds MUST use the dacs-x-<kind>:v1: form (SIG-4). ` +
      `Known separators: ${known.join(', ')}`
    );
  }
}

/** The set of `LEGACY_READ_SEPARATORS` strings — read/verify-only, never emittable. */
const LEGACY_READ_SET: ReadonlySet<string> = new Set(Object.values(LEGACY_READ_SEPARATORS));

/** True iff `sep` is a read-only legacy separator (admitted on the verify/read path only). */
export function isLegacyReadSeparator(sep: string): boolean {
  return LEGACY_READ_SET.has(sep);
}

/**
 * EMISSION-path closure rule (strictly tighter than `assertKnownSeparator`).
 *
 * `LEGACY_READ_SEPARATORS` (e.g. `dacs5-bundle:v1:`) exist ONLY so the legacy VERIFY/read path
 * can recognise pre-cutover artifacts already sealed under the old string. They must NEVER be
 * used to PRODUCE a new signature: no code path emits under a retired separator. `sign()` (and
 * any other emission path) MUST call this — it admits every separator `assertKnownSeparator`
 * does EXCEPT the read-only legacy set, which it rejects with a distinct, actionable message.
 */
export function assertEmittableSeparator(sep: string): asserts sep is DomainSeparator {
  if (isLegacyReadSeparator(sep)) {
    throw new Error(
      `Refusing to sign under read-only legacy separator "${sep}". ` +
      `LEGACY_READ_SEPARATORS are admitted on the VERIFY/read path only (§10.4.2 backwards-compat); ` +
      `emission MUST use a current DOMAIN_SEPARATORS entry (canonical: "${DOMAIN_SEPARATORS.BUNDLE}").`
    );
  }
  assertKnownSeparator(sep);
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
