/**
 * DACS-2 VerifyResult INTEGRITY — threat-matrix GAP #17 (VerifyResult replay) + #6 (method
 * substitution) + #7 (recipe poisoning). Filed as DACS-Standard#158; offered as a 0.2 roadmap
 * candidate vector (RB invited "pick things off the roadmap to start implementing", 2026-06-22).
 *
 * THREATS:
 *   #17 replay   — a genuine VerifyResult produced for one session/claim is RE-LIFTED into another.
 *                  Defense: the result is bound to (jobId, claim, recipe); a consumer presented a
 *                  result whose jobId/claim ≠ the session/claim under verification MUST reject it.
 *   #6 method-substitution — the asserted `recipe` (method@version) differs from the recipe the
 *                  verifier was actually run under (the pinned/expected recipe). MUST reject.
 *   #7 recipe-poisoning   — the recipe id is right but the VERSION differs from the pinned version
 *                  (an attacker swaps a weaker recipe version). MUST reject on version mismatch.
 *
 * Behaviour-keyed, NOT section-number-keyed: the spec modular-restructure (v0.2) renumbers sections,
 * so this validator asserts VerifyResult BINDING behaviour + the §7.5.1 4-value decision invariant,
 * which survive renumbering. Pure, offline, deterministic, dep-free.
 *
 * Decision (§7.5.1, do-not-collapse): accept (bound + decision present) · reject (binding broken —
 * replay/substitution/poisoning) · indeterminate (a binding input the consumer needs is absent —
 * never silently accept) · error (the VerifyResult is malformed — verifier-side, retryable, never reject).
 *
 * SCOPE (state this honestly — Codex review): this checks the CONTEXT BINDING of a presented
 * VerifyResult ("is this the right result for THIS session+claim+pinned-recipe?"). It does NOT verify
 * a self-signature (the v0.1 VerifyResult is not self-signed — producer authenticity rests on the
 * enclosing signed AttestationBundle/CompositeVerificationRecord), and it does NOT prove the recipe was
 * actually run. `accept` means "correctly bound", NOT "the party passed vetting" — the result's own
 * §7.5.1 `decision` is interpreted separately by the relying party.
 *
 * Canonicalization: `scheme` is matched case-insensitively (registry token). `claim.identifier` and the
 * recipe id are matched NFC-EXACT (case-SENSITIVE) — case-insensitivity is scheme/registry-specific, so
 * a generic validator must not fold it (LEIs happen to be uppercase; folding could mask a real mismatch).
 */

/** Mirror of the producer's VerifyResult binding surface (src/types/verify-result.ts). */
export interface VerifyResultLike {
  v?: string;
  jobId?: unknown;
  claim?: { scheme?: unknown; identifier?: unknown } | unknown;
  recipe?: unknown; // "id@version"
  decision?: unknown; // pass | fail | indeterminate | error
}

/** What the consumer KNOWS for this verification (the session it is validating against). */
export interface ExpectedContext {
  jobId: string;
  claim: { scheme: string; identifier: string };
  /** The recipe the verifier was run under / the consumer pinned: "id@version". */
  pinnedRecipe: string;
}

export interface Check { id: string; ok: boolean | null; detail: string }
export interface IntegrityVerdict { decision: 'accept' | 'reject' | 'indeterminate' | 'error'; checks: Check[] }

const DECISIONS = new Set(['pass', 'fail', 'indeterminate', 'error']);
const lc = (s: string) => s.normalize('NFC').toLowerCase();   // scheme (case-insensitive registry token)
const nfc = (s: string) => s.normalize('NFC');                 // identifier / recipe id (case-SENSITIVE)

/** Split "id@version" into [id, version]; version '' if absent (→ a binding gap, not a crash). */
function splitRecipe(r: string): [string, string] {
  const at = r.lastIndexOf('@');
  return at < 0 ? [r, ''] : [r.slice(0, at), r.slice(at + 1)];
}

export function verifyResultIntegrity(result: VerifyResultLike, expected: ExpectedContext): IntegrityVerdict {
  const checks: Check[] = [];
  const add = (id: string, ok: boolean | null, detail: string) => { checks.push({ id, ok, detail }); };
  const err = (d: string): IntegrityVerdict => ({ decision: 'error', checks: [{ id: 'schema', ok: false, detail: `${d} (verifier-side, retryable — never reject)` }] });

  // ── schema gate → error (a malformed result is never a reject) ──
  if (!result || typeof result !== 'object') return err('VerifyResult missing/not an object');
  if (typeof result.jobId !== 'string' || result.jobId.length === 0) return err('VerifyResult.jobId missing/empty');
  if (typeof result.recipe !== 'string' || result.recipe.length === 0) return err('VerifyResult.recipe missing/empty');
  const claim = result.claim as { scheme?: unknown; identifier?: unknown } | undefined;
  if (!claim || typeof claim !== 'object' || typeof claim.scheme !== 'string' || typeof claim.identifier !== 'string') return err('VerifyResult.claim missing scheme/identifier');
  if (typeof result.decision !== 'string' || !DECISIONS.has(result.decision)) return err(`VerifyResult.decision not one of pass|fail|indeterminate|error (got ${JSON.stringify(result.decision)})`);

  // 1. jobId binding (replay #17): the result MUST be for THIS session.
  add('1-jobid-binding', result.jobId === expected.jobId,
    result.jobId === expected.jobId ? `bound to session jobId ${expected.jobId}` : `jobId ${JSON.stringify(result.jobId)} ≠ session ${expected.jobId} — VerifyResult re-lifted from another session (replay)`);

  // 2. claim binding (replay #17): the result MUST be for the claim under verification.
  const claimOk = lc(claim.scheme as string) === lc(expected.claim.scheme) && nfc(claim.identifier as string) === nfc(expected.claim.identifier);
  add('2-claim-binding', claimOk,
    claimOk ? `bound to claim ${expected.claim.scheme}:${expected.claim.identifier}` : `claim ${claim.scheme}:${claim.identifier} ≠ verified claim ${expected.claim.scheme}:${expected.claim.identifier} — result mis-bound (replay)`);

  // 3. method/recipe + version pinning (#6 method-substitution, #7 recipe-poisoning).
  const [rid, rver] = splitRecipe(result.recipe);
  const [eid, ever] = splitRecipe(expected.pinnedRecipe);
  if (ever === '' || rver === '') {
    // an unversioned pinned/asserted recipe = the consumer cannot pin a version → indeterminate, never accept.
    add('3-recipe-version', null, `recipe version absent (asserted "${result.recipe}", pinned "${expected.pinnedRecipe}") — cannot pin version, undecidable`);
  } else {
    const idOk = nfc(rid) === nfc(eid);
    const verOk = rver === ever;
    add('3-recipe-method', idOk, idOk ? `method/recipe id "${rid}" matches pinned` : `recipe id "${rid}" ≠ pinned "${eid}" — method substitution`);
    add('4-recipe-version', verOk, verOk ? `recipe version "${rver}" matches pinned` : `recipe version "${rver}" ≠ pinned "${ever}" — recipe-version poisoning`);
  }

  const anyFail = checks.some((k) => k.ok === false);
  const anyIndet = checks.some((k) => k.ok === null);
  const decision = anyFail ? 'reject' : anyIndet ? 'indeterminate' : 'accept';
  return { decision, checks };
}
