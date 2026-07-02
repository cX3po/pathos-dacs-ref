/**
 * vet-cross-run.mts — DACS-2 GLEIF vet-vector cross-run (PATH-OS Labs ref-impl).
 *
 * Drives a §7.5.1 GLEIF vet-vector corpus through THIS impl's deterministic classifier
 * (src/lib/gleif-classify.ts) and reports, per case, whether our decision matches the vector's
 * expected §7.5.1 four-value decision (pass | fail | indeterminate | error).
 *
 * Built to be READY for the vet-control vector port (DACS-Standard #170 / #146): when mj-deving's
 * port lands, point this at that corpus —
 *     npx tsx conformance/vet-drift/vet-cross-run.mts <path-to-their-vectors.json>
 * — and we get an immediate convergence read, including the arm @xm33 asked us to cover.
 *
 * HARD RULE (xm33, #170): the run FAILS (exit 1) if the `indeterminate` / unresolvable arm is not
 * exercised — a suite that only covers clean pass/fail is not a do-not-collapse conformance run.
 * Also fails on ANY decision mismatch. Deterministic, zero-network.
 */
import { readFileSync } from 'node:fs';
import { classifyFetchStatus, classifyRegistrationStatus } from '../../src/lib/gleif-classify.js';
import type { VerifyDecision } from '../../src/types/verify-result.js';

// A fetch-level decision can be a §7.5.1 verdict OR `null` = "no fetch-level verdict, proceed to
// the registration-status cases" (a legitimate, asserted outcome — e.g. HTTP 200).
type FetchDecision = VerifyDecision | null;
type Expected = { decision: FetchDecision };
type FetchCase = { id: string; responseStatus: number; hasErrors: boolean; errorDetail?: string; expected: Expected };
type StatusCase = { id: string; registrationStatus?: string; entityName?: string; expected: { decision: VerifyDecision } };
type Corpus = { recipe?: string; dacsStage?: string; fetchCases?: FetchCase[]; statusCases?: StatusCase[] };

const path = process.argv[2] ?? new URL('./recipe-vectors.json', import.meta.url).pathname;
const corpus = JSON.parse(readFileSync(path, 'utf8')) as Corpus;

type Row = { id: string; kind: 'fetch' | 'status'; expected: string; got: string; ok: boolean };
const rows: Row[] = [];

for (const c of corpus.fetchCases ?? []) {
  const res = classifyFetchStatus(c.responseStatus, c.hasErrors, c.errorDetail);
  // `null` result ↔ expected `null` (proceed) is a MATCH; otherwise compare the §7.5.1 decision.
  const got = res === null ? 'proceed' : res.decision;
  const expected = c.expected.decision === null ? 'proceed' : c.expected.decision;
  rows.push({ id: c.id, kind: 'fetch', expected, got, ok: got === expected });
}
for (const c of corpus.statusCases ?? []) {
  const res = classifyRegistrationStatus(c.registrationStatus, c.entityName);
  rows.push({ id: c.id, kind: 'status', expected: c.expected.decision, got: res.decision, ok: res.decision === c.expected.decision });
}

const dist: Record<string, number> = {};
for (const r of rows) dist[r.got] = (dist[r.got] ?? 0) + 1;
const mismatches = rows.filter((r) => !r.ok);
const indeterminateExercised = rows.some((r) => r.expected === 'indeterminate') && rows.some((r) => r.got === 'indeterminate');

console.log(`vet cross-run — recipe=${corpus.recipe ?? '?'} stage=${corpus.dacsStage ?? '?'} corpus=${path}`);
console.log(`  cases: ${rows.length}  |  decision distribution: ${JSON.stringify(dist)}`);
console.log(`  indeterminate arm exercised: ${indeterminateExercised ? 'YES' : 'NO'}`);
for (const r of mismatches) {
  console.log(`  ✗ ${r.kind}/${r.id}: expected ${r.expected}, got ${r.got}`);
}
if (mismatches.length === 0) console.log(`  ✓ all ${rows.length} cases converge with expected §7.5.1 decisions`);

const fail: string[] = [];
if (mismatches.length) fail.push(`${mismatches.length} decision mismatch(es)`);
if (!indeterminateExercised) fail.push('indeterminate/unresolvable arm NOT exercised (xm33 #170: do-not-collapse requires it)');
if (fail.length) {
  console.error(`\nCROSS-RUN FAILED: ${fail.join('; ')}`);
  process.exit(1);
}
console.log(`\n✓ cross-run clean — all arms exercised (incl. indeterminate), zero divergence.`);
