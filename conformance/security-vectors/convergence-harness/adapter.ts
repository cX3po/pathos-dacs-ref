/**
 * ConvergenceAdapter — the contract every independent DACS implementation implements so that its
 * results can be compared against other impls on a shared bundle corpus.
 *
 * The convergence harness (./harness.mts) runs EVERY registered adapter over EVERY corpus bundle and
 * reports two metrics:
 *
 *   PRIMARY   — canonical bundle-hash agreement. KEY-FREE and impl-agnostic: every impl independently
 *               computes the §10.4.1 / R5-1 canonical bundle signed-scope hash. If two impls agree on
 *               this hash they agree on canonicalization, which is the cleanest convergence proof there
 *               is — it needs no key resolution, no signature verification, no identity layer.
 *
 *   SECONDARY — decision agreement, for portable-resolvable bundles only. Cross-impl decision divergence
 *               is usually a claim/key-resolution CONVENTION difference (self-describing `cci:<hex>` vs
 *               resolvable `did:demos:*`), not a spec gap — so it is contextualized, not graded.
 *
 * THE CONTRACT
 * ------------
 *   hash      = the §10.4.1 / R5-1 canonical bundle signed-scope hash, i.e.
 *               sha256(JCS(bundle WITHOUT `signatures` and WITHOUT `anchoredByRole`)), hex.
 *               `signatures` is the §10.4.1 exclusion; `anchoredByRole` is the R5-1 exclusion (it is
 *               per-copy, so excluding it is what makes the buyer-anchored and seller-anchored copies
 *               of a two-sided session hash EQUAL). Compute this over the bundle as given — do NOT add
 *               or normalize fields beyond JCS canonicalization.
 *
 *   decision  = the impl's §7.5.1 verdict for the bundle. Each impl has its own native enum
 *               (pathos-dacs-ref: accept | reject | indeterminate; others may use pass | fail | …).
 *               The harness normalizes "verified vs not" for cross-comparison; it does NOT require a
 *               shared enum. The §7.5.1 do-not-collapse rule applies: an unresolvable signer key should
 *               yield an `indeterminate`-class verdict, NOT a hard reject.
 *
 * An adapter MUST be a thin shim over the impl's own verifier + canonical-hasher. It must NOT
 * re-implement either; the whole point is to compare the REAL impls, not the harness's idea of them.
 *
 * To add an impl: implement this interface (see ./adapters/external-template.ts for a worked stub),
 * then register it in ./harness.mts.
 */

/** A DACS AttestationBundle, as parsed JSON. Kept as an open record so each adapter can narrow it. */
export type Bundle = Record<string, unknown>;

/** The result an adapter returns for a single bundle. */
export interface ConvergenceResult {
  /** The impl's §7.5.1 verdict (impl-native enum). `"error"` if the adapter could not run. */
  decision: string;
  /** The §10.4.1 / R5-1 canonical bundle signed-scope hash (hex). Empty string if it could not be computed. */
  hash: string;
  /** Optional human-readable note when decision/hash could not be produced. */
  error?: string;
}

export interface ConvergenceAdapter {
  /** Stable, human-readable impl name shown in the report (e.g. "pathos-dacs-ref"). */
  name: string;
  /**
   * Run the impl's verifier + canonical-hasher on one bundle.
   * MUST NOT throw — catch internally and return `{ decision: "error", hash: "", error }`.
   */
  verify(bundle: Bundle): ConvergenceResult;
}
