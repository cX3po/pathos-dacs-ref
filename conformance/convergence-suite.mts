/**
 * convergence-suite.mts — the aggregate DACS convergence gate.
 *
 * Runs EVERY independent cross-run + the multi-impl canonical-hash harness in one pass and
 * aggregates the verdicts, so a golden-vector change or a canonicalization drift anywhere in the
 * ecosystem is caught continuously (CI: .github/workflows/convergence.yml) instead of by an ad-hoc
 * manual read. Each sub-run stays the source of truth for its own convergence (it exits non-zero on
 * an UNdocumented divergence; documented spec-ambiguity divergences exit 0 and are surfaced in its
 * own output) — this runner just fans out, collects exit codes, and fails the suite if any sub-run
 * diverges.
 *
 *   npx tsx conformance/convergence-suite.mts          # run all, human summary
 *   npx tsx conformance/convergence-suite.mts --json   # machine summary for CI annotations
 *
 * Exit 0 iff every sub-run converged (documented divergences allowed); non-zero otherwise.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const GOLDEN = join(HERE, 'vet-drift', 'golden', 'control-gate-vectors.json');

/** Each entry drives one independent cross-run. `args` is appended after the script path. */
const SUITE: Array<{ id: string; script: string; args?: string[]; note: string }> = [
  { id: 'control-gate (#170)', script: 'conformance/vet-drift/control-gate-cross-run.mts', args: [GOLDEN],
    note: 'DACS-1 §6.3.2 step-6 control gate vs the vendored #170 golden' },
  { id: 'sealed-envelope SE-8 (#218)', script: 'conformance/vet-drift/se8-role-cross-run.mts',
    note: 'DACS-3 §8.4.3 sealed-envelope role assignment vs the #218 golden' },
  { id: 'settlement-evidence (#28)', script: 'conformance/vet-drift/settlement-evidence-cross-run.mts',
    note: 'DACS-4 §9.7 SettlementEvidence vs dacs-sdk #28 case set' },
  { id: 'bundle-consistency (#30)', script: 'conformance/vet-drift/bundle-consistency-cross-run.mts',
    note: 'DACS-5 §10.4.3 two-sided verdict vs dacs-sdk #30 case set' },
  { id: 'canonical-hash 3-way', script: 'conformance/security-vectors/convergence-harness/harness.mts',
    note: 'multi-impl §10.4.1/R5-1 canonical bundle-hash agreement (pathos / dacs-verify / dacs-sdk)' },
];

const jsonMode = process.argv.includes('--json');
type Result = { id: string; ok: boolean; code: number; tail: string; note: string; failKind?: string };
const results: Result[] = [];

for (const s of SUITE) {
  const r = spawnSync('npx', ['tsx', s.script, ...(s.args ?? [])], {
    cwd: REPO, encoding: 'utf8', timeout: 180_000,
  });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`.trimEnd();
  const tail = out.split('\n').slice(-2).join(' ⏎ ').slice(0, 300);
  // A sub-run signals convergence with exit 0 (documented divergences allowed); anything else fails.
  const ok = r.status === 0;
  // Distinguish "never ran / killed" from "ran and diverged" so a CI failure is diagnosable
  // (Codex note): a spawn error (ENOENT) or a signal-kill (timeout) is NOT a convergence result.
  const failKind = ok ? undefined
    : r.error ? `did-not-run: ${r.error.message}`
    : r.signal ? `killed: ${r.signal}${r.signal === 'SIGTERM' ? ' (likely 180s timeout)' : ''}`
    : `diverged: exit ${r.status}`;
  results.push({ id: s.id, ok, code: r.status ?? -1, tail, note: s.note, ...(failKind ? { failKind } : {}) });
}

const passed = results.filter((r) => r.ok).length;
const allConverged = results.every((r) => r.ok);

if (jsonMode) {
  console.log(JSON.stringify({ suite: 'dacs-convergence', passed, total: results.length, converged: allConverged, results }, null, 2));
} else {
  console.log('DACS convergence suite — independent cross-runs + canonical-hash harness\n');
  for (const r of results) {
    console.log(`${r.ok ? '✓' : '✗'} ${r.id.padEnd(30)} ${r.ok ? 'CONVERGED' : (r.failKind ?? `DIVERGED (exit ${r.code})`)}`);
    console.log(`    ${r.note}`);
    console.log(`    ↳ ${r.tail}`);
  }
  console.log(`\n${allConverged ? '✅ ALL CONVERGED' : '❌ DIVERGENCE'} — ${passed}/${results.length} sub-runs (pathos-dacs-ref convergence suite)`);
}

process.exit(allConverged ? 0 : 1);
