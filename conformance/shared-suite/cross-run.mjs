#!/usr/bin/env node
/**
 * conformance/shared-suite/cross-run.mjs — DACS Shared Conformance Suite runner.
 *
 * Runs the seed corpus (`./seed-corpus.mjs`) through every registered adapter via
 * `crossRun()` (`./adapter-contract.mjs`) and prints an agreement matrix + spec-questions.
 * Default registration (this file, run directly) is the reference adapter ALONE — this is
 * the real, non-demo run. See `./demo-divergent-adapter.mjs` for a second invocation that
 * additionally registers a deliberately-wrong stub adapter to prove the disagreement path.
 *
 * Self-contained: Node >= 18, zero npm dependencies, no network, no imports outside
 * conformance/ (partner-kit + shared-suite).
 *
 * Usage:
 *   node cross-run.mjs                    agreement matrix, human-readable
 *   node cross-run.mjs --spec-questions   only the disagreements (upstream-filing format)
 *   node cross-run.mjs --json             machine-readable report
 *
 * Exit: 0 = no SPEC-QUESTION rows (ABSTAIN is expected/fine) · 1 = >=1 SPEC-QUESTION.
 */
import { crossRun } from './adapter-contract.mjs';
import { loadSeedCorpus } from './seed-corpus.mjs';
import { referenceAdapter } from './reference-adapter.mjs';

const F4_NOTE =
  'F4 / bundle-verify: ABSTAIN — no adapter in this run exports verifyBundle, and the ' +
  'current seed corpus carries ZERO bundle-verify vectors (the referenced-artifact-' +
  'authorization / dacs-sdk#38 vectors named in ADAPTER.md\'s "Seed corpus" section are ' +
  'aspirational — not yet shipped). See the F4 header note in reference-adapter.mjs for why ' +
  'DACS-5 §10.4 full-bundle verification is intentionally not wired zero-dep here.';

/**
 * Run `adapters` against `corpus` (defaults to the full seed corpus) and return a plain,
 * JSON-serialisable report. Exported so `demo-divergent-adapter.mjs` can reuse it with its
 * own adapter list instead of duplicating the loading/formatting logic.
 */
export function run(adapters, corpus = loadSeedCorpus()) {
  const { vectors, outOfScope, sourceFiles } = corpus;
  const { matrix, specQuestions } = crossRun(adapters, vectors);
  return { adapters: adapters.map((a) => a.name), sourceFiles, matrix, specQuestions, outOfScope };
}

/** Per-family PASS/SPEC-QUESTION/ABSTAIN counts. */
export function summarizeByFamily(report) {
  const bySection = {};
  for (const row of report.matrix) {
    bySection[row.family] ??= { total: 0, pass: 0, specQuestion: 0, abstain: 0 };
    bySection[row.family].total++;
    if (row.verdict === 'PASS') bySection[row.family].pass++;
    else if (row.verdict === 'SPEC-QUESTION') bySection[row.family].specQuestion++;
    else bySection[row.family].abstain++;
  }
  return bySection;
}

export function printHuman(report, { specQuestionsOnly = false, title = 'DACS Shared Conformance Suite — cross-run' } = {}) {
  const w = (s) => process.stdout.write(s);
  w(`# ${title}\n`);
  w(`# adapters registered: ${report.adapters.join(', ')}\n`);
  w(`# seed corpus: ${report.sourceFiles.partnerKit}, ${report.sourceFiles.sig6}\n`);
  w('# NON-NORMATIVE. Agreement is interop evidence; disagreement is a spec question filed\n');
  w('# upstream — never a verdict on any implementation. See ADAPTER.md.\n\n');

  if (specQuestionsOnly) {
    if (report.specQuestions.length === 0) {
      w('No SPEC-QUESTION rows — every executed vector is either PASS or ABSTAIN.\n\n');
    }
    for (const row of report.specQuestions) {
      w(`SPEC-QUESTION  ${row.id}  [${row.family} / ${row.fnName}]\n`);
      w(`  ${row.description}\n`);
      w(`  expected: ${row.expected}\n`);
      for (const [name, r] of Object.entries(row.perAdapter)) {
        w(`    ${name}: ${r.status === 'ABSTAIN' ? 'ABSTAIN' : `${r.outcome} (${r.status})`}\n`);
      }
      w('\n');
    }
  } else {
    const bySection = summarizeByFamily(report);
    for (const [family, s] of Object.entries(bySection)) {
      const mark = s.specQuestion > 0 ? '?' : s.pass === s.total - s.abstain && s.pass > 0 ? '✓' : s.pass === 0 && s.abstain === s.total ? '-' : '?';
      w(`  ${mark} ${family}: ${s.pass} PASS, ${s.specQuestion} SPEC-QUESTION, ${s.abstain} ABSTAIN (of ${s.total})\n`);
    }
    w(`\n${F4_NOTE}\n`);

    if (report.outOfScope.length > 0) {
      w(`\n${report.outOfScope.length} seed vector(s) out of v0 adapter-interface scope (documented, not silently dropped):\n`);
      for (const o of report.outOfScope) w(`  - ${o.id} [${o.section}]: ${o.reason}\n`);
    }

    if (report.specQuestions.length > 0) {
      w(`\n${report.specQuestions.length} SPEC-QUESTION row(s) — rerun with --spec-questions for the upstream-filing view.\n`);
    }
    const totalExecuted = report.matrix.length;
    const totalPass = report.matrix.filter((r) => r.verdict === 'PASS').length;
    w(`\n${totalPass}/${totalExecuted} executed vectors PASS · ${report.specQuestions.length} SPEC-QUESTION · ${report.matrix.filter((r) => r.verdict === 'ABSTAIN').length} fully-ABSTAIN.\n`);
  }
}

export function printJson(report) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

async function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes('--json');
  const specQuestionsOnly = args.includes('--spec-questions');
  const unknown = args.filter((a) => !['--json', '--spec-questions'].includes(a));
  if (unknown.length) {
    process.stderr.write(`usage: node cross-run.mjs [--json] [--spec-questions] (unknown: ${unknown.join(' ')})\n`);
    return 2;
  }

  const adapters = [referenceAdapter()];
  const report = run(adapters);

  if (wantJson) printJson(report);
  else printHuman(report, { specQuestionsOnly });

  return report.specQuestions.length > 0 ? 1 : 0;
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  process.exitCode = await main();
}
