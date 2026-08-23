/**
 * ConvergenceAdapter — dacs-sdk (DACS-Agent-commerce/dacs-sdk, an INDEPENDENT third-party impl).
 *
 * A thin shim over the VENDORED real dacs-sdk canonical hasher (`../vendor/dacs-sdk`, commit 44d8ff2,
 * verbatim — see vendor/dacs-sdk/SOURCE.md). It re-implements NOTHING: it imports the actual
 * `contentHash` so the harness compares dacs-sdk's REAL canonicalization against pathos-dacs-ref and
 * dacs-verify. A third independent impl on the PRIMARY hash is what turns a two-impl agreement into a
 * three-way convergence proof.
 *
 *   hash     = dacs-sdk's `contentHash` over the §10.4.1 signed scope (bundle minus `signatures` and
 *              `anchoredByRole`) — the same R5-1 canonical bundle signed-scope hash our contract
 *              specifies, KEY-FREE (no key resolution, no signature verification).
 *   decision = NOT wired. dacs-sdk's §7.5.1 verifier is a 14-file dependency tree; the PRIMARY hash is
 *              the cleanest convergence proof, and the corpus is `did:demos:*` (non-portable), so the
 *              harness does not decision-compare it anyway. Wiring the full verifier is a clean follow-up.
 */
import { contentHash } from '../vendor/dacs-sdk/canonical/hash.ts';
import type { Bundle, ConvergenceAdapter, ConvergenceResult } from '../adapter.js';

export const dacsSdkAdapter: ConvergenceAdapter = {
  name: 'dacs-sdk',
  verify(bundle: Bundle): ConvergenceResult {
    // `n/a` (not `error`): the adapter runs successfully for the PRIMARY metric; it simply does not
    // compute a §7.5.1 decision. Non-portable corpus ⇒ decision is not compared, so this never grades.
    const out: ConvergenceResult = { decision: 'n/a', hash: '', error: '' };
    try {
      const scope = { ...(bundle as Record<string, unknown>) };
      delete scope['anchoredByRole']; // contentHash strips `signatures` itself (§10.4.1 signed scope)
      out.hash = contentHash(scope);
    } catch (e) {
      out.decision = 'error';
      out.error = 'hash:' + (e as Error).message;
    }
    return out;
  },
};

export default dacsSdkAdapter;
