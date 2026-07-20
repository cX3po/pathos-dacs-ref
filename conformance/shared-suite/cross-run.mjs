#!/usr/bin/env node
/** DACS shared-suite runner. The adapter boundary is JSONL subprocess protocol v1. */
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crossRun } from './adapter-contract.mjs';
import { startAdapterProcess } from './adapter-process-client.mjs';
import { loadSeedCorpus } from './seed-corpus.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const F4_NOTE =
  'F4 / bundle-verify: ASPIRATIONAL — the pinned sources declare zero F4 vectors, and the ' +
  'reference adapter does not advertise verifyBundle. No F4 row is executed or counted as ' +
  'a pass; F4 becomes a candidate family only when authoritative vectors and two adapters exist.';

export async function run(adapters, corpus = loadSeedCorpus(), options = {}) {
  const { vectors, outOfScope, sourceFiles, sourceCounts } = corpus;
  const { matrix, specQuestions } = await crossRun(adapters, vectors, options);
  return {
    protocol: 'dacs-adapter/1',
    adapters: adapters.map((adapter) => adapter.metadata ?? { name: adapter.name }),
    sourceFiles,
    sourceCounts,
    matrix,
    specQuestions,
    outOfScope,
  };
}

export function summarizeByFamily(report) {
  const byFamily = {};
  for (const row of report.matrix) {
    byFamily[row.family] ??= {
      total: 0, selfCheck: 0, interopAgree: 0, vectorMismatch: 0,
      implementationDivergence: 0, abstain: 0, specQuestion: 0,
    };
    const summary = byFamily[row.family];
    summary.total++;
    const key = {
      'SELF-CHECK': 'selfCheck',
      'INTEROP-AGREE': 'interopAgree',
      'VECTOR-MISMATCH': 'vectorMismatch',
      'IMPLEMENTATION-DIVERGENCE': 'implementationDivergence',
      ABSTAIN: 'abstain',
    }[row.status];
    summary[key]++;
    if (row.triage === 'SPEC-QUESTION') summary.specQuestion++;
  }
  return byFamily;
}

export function printHuman(report, { specQuestionsOnly = false, title = 'DACS Shared Conformance Suite — cross-run' } = {}) {
  const write = (value) => process.stdout.write(value);
  write(`# ${title}\n`);
  write(`# protocol: ${report.protocol}\n`);
  for (const adapter of report.adapters) {
    write(`# adapter: ${adapter.name} ${adapter.version ?? '?'} · ${adapter.repository ?? '?'} @ ${adapter.revision ?? '?'}\n`);
  }
  write(`# pinned sources: ${report.sourceFiles.partnerKit}, ${report.sourceFiles.sig6}\n`);
  write('# NON-NORMATIVE tooling. SELF-CHECK is not cross-implementation evidence; passing is not certification.\n\n');

  if (specQuestionsOnly) {
    if (report.specQuestions.length === 0) {
      write('No triaged SPEC-QUESTION rows. Mismatches and divergences require explicit triage.\n');
    }
    for (const row of report.specQuestions) {
      write(`SPEC-QUESTION  ${row.id}  [${row.status}]\n`);
      for (const [name, result] of Object.entries(row.perAdapter)) {
        write(`  ${name}: ${result.status === 'ABSTAIN' ? 'ABSTAIN' : `${result.outcome} (${result.status})`}\n`);
      }
    }
    return;
  }

  for (const [family, summary] of Object.entries(summarizeByFamily(report))) {
    write(`  ${family}: ${summary.interopAgree} INTEROP-AGREE, ${summary.selfCheck} SELF-CHECK, ` +
      `${summary.vectorMismatch} VECTOR-MISMATCH, ${summary.implementationDivergence} IMPLEMENTATION-DIVERGENCE, ` +
      `${summary.abstain} ABSTAIN (of ${summary.total})\n`);
  }
  write(`\n${F4_NOTE}\n`);
  if (report.outOfScope.length) {
    write(`\n${report.outOfScope.length} declared partner-kit vector(s) not executed by this interface:\n`);
    for (const item of report.outOfScope) write(`  - ${item.id} [${item.section}]: ${item.reason}\n`);
  }
  const counts = Object.fromEntries(
    ['SELF-CHECK', 'INTEROP-AGREE', 'VECTOR-MISMATCH', 'IMPLEMENTATION-DIVERGENCE', 'ABSTAIN']
      .map((status) => [status, report.matrix.filter((row) => row.status === status).length])
  );
  write(`\nExecuted assertions: ${report.matrix.length} · ${counts['SELF-CHECK']} SELF-CHECK · ` +
    `${counts['INTEROP-AGREE']} INTEROP-AGREE · ${counts['VECTOR-MISMATCH']} VECTOR-MISMATCH · ` +
    `${counts['IMPLEMENTATION-DIVERGENCE']} IMPLEMENTATION-DIVERGENCE · ${counts.ABSTAIN} fully ABSTAIN · ` +
    `${report.specQuestions.length} triaged SPEC-QUESTION.\n`);
}

export function printJson(report) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

async function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes('--json');
  const specQuestionsOnly = args.includes('--spec-questions');
  const triaged = new Set();
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--triage-spec-question') {
      if (!args[index + 1]) throw new Error('--triage-spec-question requires a vector id');
      triaged.add(args[++index]);
    } else if (!['--json', '--spec-questions'].includes(args[index])) {
      throw new Error(`unknown argument: ${args[index]}`);
    }
  }

  const adapter = await startAdapterProcess(process.execPath, [path.join(HERE, 'reference-adapter-process.mjs')], { cwd: HERE });
  try {
    const report = await run([adapter], loadSeedCorpus(), { triagedSpecQuestions: triaged });
    if (wantJson) printJson(report);
    else printHuman(report, { specQuestionsOnly });
    const unresolved = report.matrix.filter((row) =>
      row.status === 'VECTOR-MISMATCH' || row.status === 'IMPLEMENTATION-DIVERGENCE');
    return unresolved.length ? 1 : 0;
  } finally {
    await adapter.close();
  }
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try { process.exitCode = await main(); }
  catch (error) {
    process.stderr.write(`shared-suite runner error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }
}
