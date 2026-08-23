/**
 * control-gate-cross-run.mts — DACS-Standard #170 vet-control cross-run (PATH-OS Labs ref-impl).
 *
 * Drives the golden control-gate vector set (authored by mj-deving's dacs-verify, merged via #213)
 * through THIS impl's independent control gate (src/lib/control-gate.ts) and reports, per case,
 * whether our §7.5.1 four-value decision matches the set's `expected`. Emits a CROSS-RUN.md run file
 * for scripts/diff_vector_runs.py.
 *
 *   npx tsx conformance/vet-drift/control-gate-cross-run.mts <control-gate-vectors.json> [--emit run.json]
 *
 * Exit 0 iff every case converges (decision, and `throws` where the vector pins it). Non-zero on any
 * divergence — a divergence is a real finding about our impl or the set, and belongs on #170.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { classifyControlGate, type ControlGateInput, type Decision } from '../../src/lib/control-gate.js';

const require = createRequire(import.meta.url);
const IMPL = `pathos-dacs-ref@${(require('../../package.json').version as string) ?? '0.0.0'}`;

type Expected = Decision | { decision: Decision; throws?: boolean };
type Case = { id: string; input: ControlGateInput; expected: Expected };
type Fixture = { now: number; cases: Case[]; source?: string; status?: string };

const path = process.argv[2];
if (!path) { console.error('usage: control-gate-cross-run.mts <vectors.json> [--emit run.json]'); process.exit(2); }
const fx = JSON.parse(readFileSync(path, 'utf8')) as Fixture;

const expDecision = (e: Expected): Decision => (typeof e === 'string' ? e : e.decision);
const expThrows = (e: Expected): boolean | undefined => (typeof e === 'string' ? undefined : e.throws);

type Row = { name: string; expected: Decision; got: Decision; expThrows?: boolean; gotThrew: boolean; ok: boolean; reason: string };
const rows: Row[] = [];
for (const c of fx.cases) {
  const r = classifyControlGate(c.input, fx.now);
  const ed = expDecision(c.expected);
  const et = expThrows(c.expected);
  const ok = r.decision === ed && (et === undefined || r.threw === et);
  rows.push({ name: c.id, expected: ed, got: r.decision, expThrows: et, gotThrew: r.threw, ok, reason: r.reason });
}

const converged = rows.every((r) => r.ok);
for (const r of rows) {
  const t = r.expThrows === undefined ? '' : ` throws exp=${r.expThrows}/got=${r.gotThrew}`;
  console.log(`${r.ok ? '✓' : '✗'} ${r.name}: expected=${r.expected} got=${r.got}${t}${r.ok ? '' : `  ⟵ ${r.reason}`}`);
}
console.log(`\n${converged ? 'cross-run CONVERGED' : 'cross-run DIVERGED'} — ${rows.filter((r) => r.ok).length}/${rows.length} cases (${IMPL})`);

const emitIdx = process.argv.indexOf('--emit');
if (emitIdx !== -1 && process.argv[emitIdx + 1]) {
  const run = { set: 'control-gate-vectors', impl: IMPL, results: rows.map((r) => ({ name: r.name, verdict: r.got })) };
  writeFileSync(process.argv[emitIdx + 1], JSON.stringify(run, null, 2));
  console.log(`emitted run file → ${process.argv[emitIdx + 1]}`);
}

process.exit(converged ? 0 : 1);
