/**
 * Conformance vectors for DACS-2 VerifyResult INTEGRITY — GAP #17/#6/#7 (DACS-Standard#158).
 * Replay (jobId/claim re-lift), method substitution, recipe-version poisoning. Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifyResultIntegrity, type VerifyResultLike, type ExpectedContext } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const CTX: ExpectedContext = { jobId: 'job-7f3a', claim: { scheme: 'lei', identifier: '506700GE1G29325QX363' }, pinnedRecipe: 'gleif-cbp@1' };
const good: VerifyResultLike = { v: 'dacs-2-verify-result:0.1', jobId: 'job-7f3a', claim: { scheme: 'lei', identifier: '506700GE1G29325QX363' }, recipe: 'gleif-cbp@1', decision: 'pass' };
const c = (o: Partial<VerifyResultLike>): VerifyResultLike => ({ ...good, ...o });

type Case = { name: string; gap: string; expected: 'accept' | 'reject' | 'indeterminate' | 'error'; result: VerifyResultLike; ctx?: ExpectedContext };
const cases: Case[] = [
  { name: 'valid-bound-result', gap: '-', expected: 'accept', result: good },
  // a correctly-bound result carrying a NON-pass decision is still integrity-valid (we never conflate
  // the result's §7.5.1 decision with its binding — accept means "bound", not "passed").
  { name: 'valid-bound-indeterminate-decision', gap: '-', expected: 'accept', result: c({ decision: 'indeterminate' }) },
  // #17 replay: a genuine result from another session re-lifted into this one
  { name: 'replay-wrong-jobid', gap: '#17', expected: 'reject', result: c({ jobId: 'job-OTHER' }) },
  // #17 replay: result bound to a different claim than the one under verification
  { name: 'replay-mismatched-claim', gap: '#17', expected: 'reject', result: c({ claim: { scheme: 'lei', identifier: '999999OTHERLEI0000000' } }) },
  // #6 method substitution: asserted recipe id ≠ the pinned/run recipe
  { name: 'method-substitution', gap: '#6', expected: 'reject', result: c({ recipe: 'self-attest@1' }) },
  // #7 recipe poisoning: right id, swapped (weaker) version
  { name: 'recipe-version-poisoning', gap: '#7', expected: 'reject', result: c({ recipe: 'gleif-cbp@0' }) },
  // unversioned pinned recipe → cannot pin a version → indeterminate, never silent accept
  { name: 'unversioned-recipe-indeterminate', gap: '#7', expected: 'indeterminate', result: c({ recipe: 'gleif-cbp' }), ctx: { ...CTX, pinnedRecipe: 'gleif-cbp' } },
  // hostile edge: empty version after the delimiter ("id@") → version absent → indeterminate (Codex)
  { name: 'empty-version-indeterminate', gap: '#7', expected: 'indeterminate', result: c({ recipe: 'gleif-cbp@' }) },
  // hostile edge: double delimiter ("id@1@evil") → lastIndexOf('@') makes id="gleif-cbp@1" ≠ pinned id → reject (Codex)
  { name: 'double-delimiter-recipe', gap: '#6', expected: 'reject', result: c({ recipe: 'gleif-cbp@1@evil' }) },
  // malformed → error (verifier-side, never reject): decision not in the §7.5.1 set
  { name: 'malformed-decision-error', gap: '-', expected: 'error', result: c({ decision: 'ok' as unknown as string }) },
  // malformed → error: jobId missing
  { name: 'missing-jobid-error', gap: '-', expected: 'error', result: c({ jobId: undefined }) },
];

const vectors = cases.map((c) => ({ name: c.name, gap: c.gap, expected: c.expected, context: c.ctx ?? CTX, result: c.result }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/verify-result-integrity-v0.1.json`, JSON.stringify({
  set: 'verify-result-integrity-v0.1', spec: 'DACS-2 VerifyResult binding (behaviour-keyed) — GAP #17/#6/#7 (DACS-Standard#158)',
  note: 'Behaviour-keyed not §-number-keyed (spec restructure renumbers sections at v0.2). accept=bound; reject=replay/substitution/poisoning; indeterminate=unpinnable; error=malformed.',
  scope: 'Validates CONTEXT BINDING of a presented VerifyResult (right result for this session+claim+pinned-recipe). Does NOT verify a self-signature (v0.1 VerifyResult is not self-signed — producer authenticity rests on the enclosing signed bundle) and does NOT prove the recipe was run. accept = "correctly bound", not "party passed vetting". scheme matched case-insensitively; claim.identifier + recipe id matched NFC-exact (case-insensitivity is scheme/registry-specific).',
  hash: setHash, count: vectors.length, vectors,
}, null, 2));

let pass = 0;
console.log('\n=== DACS-2 VerifyResult-integrity conformance vectors v0.1 (GAP #17/#6/#7) ===');
for (const tc of cases) {
  const v = verifyResultIntegrity(tc.result, tc.ctx ?? CTX);
  const ok = v.decision === tc.expected;
  pass += ok ? 1 : 0;
  const why = v.checks.filter((k) => k.ok === false).map((k) => k.id).join(',') || v.checks.filter((k) => k.ok === null).map((k) => k.id).join(',');
  console.log(`  [${ok ? '✓' : '✗'}] ${tc.name.padEnd(36)} ${tc.gap.padEnd(4)} exp=${tc.expected.padEnd(13)} got=${v.decision.padEnd(13)}${why ? ' :' + why : ''}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/verify-result-integrity-v0.1.json`);
if (pass !== cases.length) process.exit(1);
