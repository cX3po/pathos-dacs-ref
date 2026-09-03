/**
 * DACS-1 Identify — TypeScript types
 *
 * Spec source: DACS-1 v0.1 §6.3 (VERIFIED against memory/dacs_review/DACS-1-IDENTIFY.md
 * §6.3.2 lines 98-160, 2026-06-07 re-pin cutover).
 *
 * Identity-claim references use a scheme:identifier[?params] grammar (§6.3.1).
 * The IdentityBundle is an ordered set of claims a party presents about itself, with
 * verification metadata, plus a presentation signature.
 *
 * Four permitted presentation kinds (§6.3.2):
 *   - siwd        (Sign-In With Demos — preferred): wallet signs the SIWD message carrying
 *                 `dacs:<hex>` (= hex(signed_bytes)) as an EIP-4361 Resources entry
 *   - per-claim   : each claim's key independently signs `signed_bytes`
 *   - session-key : an ephemeral session key signs `signed_bytes`; optional rootBinding
 *   - sr1-root    : a single SR-1 aggregate signature co-signs the whole bundle
 *
 * Domain-separated payload (all four kinds bind to the same payload, §6.3.2 / DACS-1:149):
 *   signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash       (single-hash)
 *   bundle_hash  := sha256(JCS(bundle with `presentation` omitted)), hex
 */
export {};
