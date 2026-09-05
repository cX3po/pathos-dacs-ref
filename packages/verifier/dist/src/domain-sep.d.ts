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
 * v0.1 §B.7 closed-registry separators that this reference impl uses, aligned to CORE §B.7.
 * This map carries the §B.7 kinds our code signs/verifies — including the DACS-5 fault-bundle +
 * BundleBinding separators added to the §B.7 table by #248. The full normative §B.7 closed registry
 * (23 entries as of #248) is defined in CORE §B.7; this map is the subset this impl actually uses,
 * and it is the single source of truth those signers draw from (see src/lib/bundle-binding-v1.ts).
 * Adding new ones requires a DACS spec revision — use the `dacs-x-` extension form for experiments.
 */
export declare const DOMAIN_SEPARATORS: {
    readonly LISTING: "dacs-listing:v1:";
    readonly BUNDLE_PRESENTATION: "dacs-bundle-presentation:v1:";
    readonly SESSION_BINDING: "dacs-session-binding:v1:";
    readonly COMPOSITE_VERIFY: "dacs-composite:v1:";
    readonly CHANNEL_MSG: "dacs-channelmsg:v1:";
    readonly AGREEMENT: "dacs-agreement:v1:";
    readonly COMMIT_AGREEMENT: "dacs-commitment:v1:";
    readonly SETTLEMENT_EVIDENCE: "dacs-evidence:v1:";
    readonly BUNDLE: "dacs-bundle:v1:";
    readonly REPUTATION_ATTESTATION: "dacs-rating:v1:";
    readonly BUNDLE_BINDING: "dacs-bundle-binding:v1:";
    readonly FAULT_BUNDLE: "dacs-fault-bundle:v1:";
    readonly FAULT_BUNDLE_POINTER: "dacs-fault-bundle-pointer:v1:";
};
/** Additive post-v0.1 registry entries used by the v0.3/v0.4 artifact types. Kept
 * separate so callers auditing the frozen legacy subset do not see a moving count. */
export declare const ADDITIVE_DOMAIN_SEPARATORS: {
    readonly PAYEE_BOUND_AGREEMENT: "dacs-payee-bound-agreement:v1:";
    readonly FINALITY_COMMITMENT: "dacs-finality-commitment:v1:";
    readonly EVIDENCE_BOUND_FAULT_BUNDLE: "dacs-evidence-bound-fault-bundle:v1:";
    readonly EVIDENCE_BOUND_FAULT_BUNDLE_POINTER: "dacs-evidence-bound-fault-bundle-pointer:v1:";
};
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
export declare const LEGACY_READ_SEPARATORS: {
    readonly BUNDLE_DACS5: "dacs5-bundle:v1:";
};
/**
 * SIG-4 extension separators for artifact kinds NOT in the v0.1 §B.7 closed registry.
 * CORE.md:265: "An artifact kind not in the v0.1 table MUST use a domain separator of the form
 * `dacs-x-<kind>:v1:` until accepted into a future version of the registry."
 *
 * These were declared in the legacy v0.7 registry under non-conformant names
 * (`dacs-attestation-ref`, `dacs-cbp-commit`, `dacs-rule-ref`, `dacs-payment-auth`,
 * `dacs-delivery-receipt`, `dacs-session-record`, `dacs-sealed-envelope-open`). None of them
 * has a clear v0.1 §B.7 registry entry, so per SIG-4 they move to the `dacs-x-` extension prefix.
 * AGENT_IDENTITY is emitted and verified by src/adapters/demos/identity.ts; the others remain
 * reserved surfaces, so their move is registry hygiene with no signed-artifact impact.
 */
export declare const DACS_X_EXTENSION_SEPARATORS: {
    readonly AGENT_IDENTITY: "dacs-x-agent-identity:v1:";
    readonly ATTESTATION_REF: "dacs-x-attestation-ref:v1:";
    readonly CONSENSUS_PROXY_COMMIT: "dacs-x-cbp-commit:v1:";
    readonly RULE_REF_COMMIT: "dacs-x-rule-ref:v1:";
    readonly PAYMENT_AUTH: "dacs-x-payment-auth:v1:";
    readonly DELIVERY_RECEIPT: "dacs-x-delivery-receipt:v1:";
    readonly SESSION_RECORD: "dacs-x-session-record:v1:";
    readonly SEALED_ENVELOPE_OPEN: "dacs-x-sealed-envelope-open:v1:";
    readonly CLAIM_COMMIT: "dacs-x-claim-commit:v1:";
    readonly CLAIM_REVEAL: "dacs-x-claim-reveal:v1:";
    readonly CONSENT: "dacs-x-consent:v1:";
    readonly DISPUTE_BUNDLE: "dacs-x-dispute-bundle:v1:";
    readonly AP2_MOCK_RECEIPT: "dacs-x-ap2-receipt:v1:";
};
/**
 * Reviewed additive SIG-4 extensions. Kept separate from the legacy-counted
 * DACS_X_EXTENSION_SEPARATORS map so adding a reviewed surface cannot silently
 * change the frozen compatibility inventory asserted by existing vectors.
 */
export declare const REVIEWED_DACS_X_EXTENSION_SEPARATORS: {
    /** Private-channel wire envelope: sep || UTF8(sha256hex(JCS(unsigned envelope))). */
    readonly CHANNEL_ENVELOPE: "dacs-x-channel-envelope:v1:";
};
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
export declare const PATHOS_EXTENSION_SEPARATORS: {
    readonly CROSS_VPS_ATTESTATION: "dacs-cross-vps-attestation:v1:";
    readonly BRIDGE_RELEASE_ATTESTATION: "dacs-bridge-release-attestation:v1:";
    readonly TANK_LOCK_ATTESTATION: "dacs-tank-lock-attestation:v1:";
    readonly TANK_REFUND_ATTESTATION: "dacs-tank-refund-attestation:v1:";
    readonly DELIVERY_RECEIPT: "pathos-delivery-receipt:v1:";
};
export type DomainSeparator = (typeof DOMAIN_SEPARATORS)[keyof typeof DOMAIN_SEPARATORS] | (typeof ADDITIVE_DOMAIN_SEPARATORS)[keyof typeof ADDITIVE_DOMAIN_SEPARATORS] | (typeof LEGACY_READ_SEPARATORS)[keyof typeof LEGACY_READ_SEPARATORS] | (typeof DACS_X_EXTENSION_SEPARATORS)[keyof typeof DACS_X_EXTENSION_SEPARATORS] | (typeof REVIEWED_DACS_X_EXTENSION_SEPARATORS)[keyof typeof REVIEWED_DACS_X_EXTENSION_SEPARATORS] | (typeof PATHOS_EXTENSION_SEPARATORS)[keyof typeof PATHOS_EXTENSION_SEPARATORS];
export type DomainSeparatorKey = keyof typeof DOMAIN_SEPARATORS;
/**
 * §B.7 closure rule. Throws on unknown separator. Admits the closed v0.1 §B.7 registry
 * PLUS the SIG-4 `dacs-x-` extension separators (DACS_X_EXTENSION_SEPARATORS and the
 * PATH-OS Labs extension siblings) — all three maps follow the registry-or-`dacs-x-` discipline.
 */
export declare function assertKnownSeparator(sep: string): asserts sep is DomainSeparator;
/** True iff `sep` is a read-only legacy separator (admitted on the verify/read path only). */
export declare function isLegacyReadSeparator(sep: string): boolean;
/**
 * EMISSION-path closure rule (strictly tighter than `assertKnownSeparator`).
 *
 * `LEGACY_READ_SEPARATORS` (e.g. `dacs5-bundle:v1:`) exist ONLY so the legacy VERIFY/read path
 * can recognise pre-cutover artifacts already sealed under the old string. They must NEVER be
 * used to PRODUCE a new signature: no code path emits under a retired separator. `sign()` (and
 * any other emission path) MUST call this — it admits every separator `assertKnownSeparator`
 * does EXCEPT the read-only legacy set, which it rejects with a distinct, actionable message.
 */
export declare function assertEmittableSeparator(sep: string): asserts sep is DomainSeparator;
/** Build the signed_bytes for a payload + separator + optional intermediate hash. */
export declare function buildSignedBytes(separator: DomainSeparator, bodyBytes: Uint8Array, intermediateHash?: Uint8Array): Uint8Array;
