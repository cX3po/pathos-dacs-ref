/**
 * ConvergenceAdapter — dacs-verify (mj-deving's INDEPENDENT third-party verifier).
 *
 * A thin shim over the VENDORED real dacs-verify (`../vendor/dacs-verify`, commit 10aefa7f, verbatim —
 * see vendor/dacs-verify/SOURCE.md). It re-implements NOTHING: it imports the actual `bundleHash` and
 * `verifyBundle` so the harness compares the REAL independent impl against pathos-dacs-ref. That is the
 * whole point — a second, clean-room implementation is what turns the Trust Wall's self-report into a
 * genuine cross-impl convergence proof.
 *
 *   hash     = dacs-verify's `bundleHash`  — sha256(JCS(bundle minus signatures + anchoredByRole)),
 *              the same §10.4.1 / R5-1 signed-scope hash our contract specifies.
 *   decision = dacs-verify's `verifyBundle(bundle, resolveKey)` — its own native §7.5.1 enum
 *              (pass | fail | indeterminate | error). The harness normalizes "verified vs not".
 *
 * HONESTY: the corpus signers are placeholder DIDs (did:demos:buyer/seller) with no real keys, so the
 * resolver returns null (genuinely unresolvable). dacs-verify then yields its own `indeterminate` per
 * the §7.5.1 do-not-collapse rule. We do NOT fabricate keys — a forced pass would be a FALSE
 * convergence, which is exactly what the Trust Wall exists to prevent.
 */
import { bundleHash, verifyBundle } from '../vendor/dacs-verify/src/dacs5/bundle.ts';
import type { Bundle, ConvergenceAdapter, ConvergenceResult } from '../adapter.js';

/** Honest resolver: placeholder-DID corpus signers have no real key → null (unresolvable). */
const resolveKey = (_party: unknown): null => null;

export const dacsVerifyAdapter: ConvergenceAdapter = {
  name: 'dacs-verify',
  verify(bundle: Bundle): ConvergenceResult {
    const out: ConvergenceResult = { decision: 'error', hash: '', error: '' };
    try {
      out.hash = bundleHash(bundle as never);
    } catch (e) {
      out.error = 'hash:' + (e as Error).message;
    }
    try {
      out.decision = verifyBundle(bundle as never, resolveKey as never);
    } catch (e) {
      out.error = (out.error ? out.error + '; ' : '') + 'decision:' + (e as Error).message;
    }
    return out;
  },
};

export default dacsVerifyAdapter;
