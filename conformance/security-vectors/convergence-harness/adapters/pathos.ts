/**
 * ConvergenceAdapter — pathos-dacs-ref (PATH-OS reference implementation).
 *
 * A thin shim over the in-repo verifier + canonical-hasher. It re-implements NOTHING: the harness
 * compares the REAL pathos-dacs-ref impl, exactly as the CLI and the conformance suite use it.
 *
 *   decision = verifyBundleV1(bundle).decision        (native enum: accept | reject | indeterminate)
 *   hash     = bundleSignedScopeHashV1(bundle)         (§10.4.1 / R5-1 canonical signed-scope hash)
 *
 * `bundleSignedScopeHashV1` strips `signatures` (§10.4.1) and `anchoredByRole` (R5-1) itself, so it is
 * safe — and correct — to pass either the full bundle or a signature-less one. We pass the bundle minus
 * `signatures` to make the §10.4.1 exclusion explicit at the call site; the function applies the rest.
 */
import { verifyBundleV1 } from '../../../../src/lib/verify-bundle-v1.js';
import { bundleSignedScopeHashV1 } from '../../../../src/lib/bundle-signed-scope-v1.js';
import type { Bundle, ConvergenceAdapter, ConvergenceResult } from '../adapter.js';

export const pathosAdapter: ConvergenceAdapter = {
  name: 'pathos-dacs-ref',
  verify(bundle: Bundle): ConvergenceResult {
    const out: ConvergenceResult = { decision: 'error', hash: '', error: '' };
    try {
      const { signatures: _omitSigs, ...unsigned } = bundle as { signatures?: unknown };
      void _omitSigs; // §10.4.1 — signatures are never in the signed scope
      try {
        out.hash = bundleSignedScopeHashV1(unsigned);
      } catch (e) {
        out.error = 'hash:' + (e as Error).message;
      }
      out.decision = verifyBundleV1(bundle as never).decision;
    } catch (e) {
      out.error = (e as Error).message;
    }
    return out;
  },
};

export default pathosAdapter;
