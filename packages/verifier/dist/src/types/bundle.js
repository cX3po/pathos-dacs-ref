/**
 * DACS-5 Verify — AttestationBundle
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §10.4
 *
 * Normative requirements:
 *   §10.4.2 — TWO-SIDED ANCHORING
 *     buyer:  stor-{sha256(jobId + "-bundle-buyer")}
 *     seller: stor-{sha256(jobId + "-bundle-seller")}
 *     Divergence between the two = dispute signal.
 *
 *   §10.4.1 — CONSUMER VERIFICATION (this is what verify.ts does):
 *     Verifiers MUST recompute the canonical form, the bundle hash, the
 *     prefixed signed_bytes, and verify each signature.
 *
 *   §10.4.3 — TWO-SIDED LOOKUP
 *     Consumers MUST query both party-specific addresses.
 *     Unilateral bundle ⇒ `aborted-by-self` for the non-signer.
 *
 *   Domain separator: "dacs-bundle:v1:" (v0.1 §B.7 registry alignment 2026-06-07 — the legacy
 *     `dacs5-bundle:v1:` separator was folded into the canonical `dacs-bundle:v1:`; backwards
 *     compat is honored by RE-SEALING legacy bundles under the canonical separator on read/emit).
 */
export {};
