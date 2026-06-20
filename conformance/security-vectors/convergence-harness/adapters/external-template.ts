/**
 * ConvergenceAdapter — TEMPLATE for an external/independent DACS implementation.
 *
 * This is a STUB, not a working adapter. It exists to show how a third implementation (for example a
 * dacs-verify, a DNO verifier, or any clean-room impl) plugs into the convergence harness. Copy this
 * file, rename it (e.g. `adapters/my-impl.ts`), wire it to YOUR verifier + canonical-hasher, and
 * register it in `../harness.mts`.
 *
 * There is intentionally NO real third-party code here — no SDK, no clone, no vendored verifier. The
 * point of the harness is to compare independent impls against each other; each impl owns its own
 * adapter and imports its own code.
 *
 * WHAT TO IMPLEMENT
 * -----------------
 *   hash      = your impl's §10.4.1 / R5-1 canonical bundle signed-scope hash:
 *               sha256(JCS(bundle WITHOUT `signatures` and WITHOUT `anchoredByRole`)), hex.
 *               This is the PRIMARY convergence metric and is key-free — if your hash matches another
 *               impl's hash for the same bundle, you have proven canonicalization convergence.
 *
 *   decision  = your impl's §7.5.1 verdict, in your own native enum. The harness normalizes
 *               "verified vs not" for comparison; you do NOT need to match anyone else's enum. Keep the
 *               §7.5.1 do-not-collapse rule: an unresolvable signer key is an `indeterminate`-class
 *               verdict, not a hard reject.
 *
 * The adapter MUST be a thin shim over your real verifier + hasher, and MUST NOT throw — catch
 * internally and return `{ decision: "error", hash: "", error }`.
 */
import type { Bundle, ConvergenceAdapter, ConvergenceResult } from '../adapter.js';

export const externalTemplateAdapter: ConvergenceAdapter = {
  // Rename to your impl's stable name; this is what appears in the report's columns.
  name: 'external-template',

  verify(bundle: Bundle): ConvergenceResult {
    const out: ConvergenceResult = { decision: 'error', hash: '', error: 'template adapter — not wired to a real impl' };

    // ── STEP 1: canonical bundle hash (PRIMARY metric — key-free) ─────────────────────────────────
    // Replace this with a call to YOUR canonical-hasher. It MUST hash the bundle with `signatures` and
    // `anchoredByRole` removed, JCS-canonicalized, sha256, hex. Example shape:
    //
    //   const { signatures, anchoredByRole, ...scope } = bundle as Record<string, unknown>;
    //   out.hash = myImpl.canonicalBundleHash(scope);   // sha256(JCS(scope)) hex
    //
    // (If your hasher strips those fields itself, you can pass the whole bundle.)

    // ── STEP 2: §7.5.1 verdict (SECONDARY metric — decision agreement) ────────────────────────────
    // Replace this with a call to YOUR verifier. It returns your native decision enum. Example shape:
    //
    //   out.decision = myImpl.verifyBundle(bundle);      // e.g. "pass" | "fail" | "indeterminate"
    //
    // Decision comparison only happens for portable-resolvable bundles (see harness.mts), so a `did:*`
    // fixture that needs your native identity resolver will simply not be decision-compared — its hash
    // still converges.

    void bundle; // remove once STEP 1/2 are implemented
    return out;
  },
};

export default externalTemplateAdapter;
