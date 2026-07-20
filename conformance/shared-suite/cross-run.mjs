#!/usr/bin/env node
/** DACS shared-suite runner. The adapter boundary is JSONL subprocess protocol v1. */
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crossRun } from './adapter-contract.mjs';
import { startAdapterProcess } from './adapter-process-client.mjs';
import { launchAdapters, parseAdapterArgs } from './adapter-registry.mjs';
import { loadSeedCorpus } from './seed-corpus.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const F4_NOTE =
  'F4 / bundle-verify: ASPIRATIONAL — the pinned sources declare zero F4 vectors, and the ' +
  'reference adapter does not advertise verifyBundle. No F4 row is executed or counted as ' +
  'a pass; F4 becomes a candidate family only when authoritative vectors and two adapters exist.';

export async function run(adapters, corpus = loadSeedCorpus(), options = {}) {
  const { vectors, outOfScope, sourceFiles, sourceCounts } = corpus;
  const { matrix, specQuestions, runs, duplicateReportedNames } = await crossRun(adapters, vectors, options);
  return {
    protocol: 'dacs-adapter/1',
    // Pair each adapter's self-reported metadata with its runner-assigned runId (Blocker 1) so
    // the report distinguishes runner-tracked identity from self-reported name.
    adapters: adapters.map((adapter, index) => ({
      runId: runs?.[index]?.runId ?? `run-${index}`,
      ...(adapter.metadata ?? { name: adapter.name }),
    })),
    duplicateReportedNames: duplicateReportedNames ?? [],
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
    write(`# adapter: [${adapter.runId ?? '?'}] ${adapter.name} ${adapter.version ?? '?'} · ${adapter.repository ?? '?'} @ ${adapter.revision ?? '?'}\n`);
  }
  if (report.duplicateReportedNames?.length) {
    write(`# WARNING: duplicate self-reported adapter name(s): ${report.duplicateReportedNames.join(', ')} — ` +
      `results are tracked by runner-assigned runId, so no false INTEROP-AGREE can result, but check adapter registration.\n`);
  }
  write(`# pinned sources: ${report.sourceFiles.partnerKit}, ${report.sourceFiles.sig6}\n`);
  write('# NON-NORMATIVE tooling. SELF-CHECK is not cross-implementation evidence; passing is not certification.\n\n');

  if (specQuestionsOnly) {
    if (report.specQuestions.length === 0) {
      write('No triaged SPEC-QUESTION rows. Mismatches and divergences require explicit triage.\n');
    }
    for (const row of report.specQuestions) {
      write(`SPEC-QUESTION  ${row.id}  [${row.status}]\n`);
      // perAdapter is keyed by runner-assigned runId (Blocker 1); the self-reported name is a
      // display label carried on each entry.
      for (const [runId, result] of Object.entries(row.perAdapter)) {
        write(`  ${runId} (${result.name}): ${result.status === 'ABSTAIN' ? 'ABSTAIN' : `${result.outcome} (${result.status})`}\n`);
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

  // Blocker 3: pull adapter-registration flags (--adapter / --adapter-provenance / --config /
  // --adapter-timeout-ms / --adapter-max-output-bytes) out first; `rest` is everything else.
  const { specs, rest } = parseAdapterArgs(args, { readFileSync });

  const wantJson = rest.includes('--json');
  const specQuestionsOnly = rest.includes('--spec-questions');
  const triaged = new Set();
  for (let index = 0; index < rest.length; index++) {
    if (rest[index] === '--triage-spec-question') {
      if (!rest[index + 1]) throw new Error('--triage-spec-question requires a vector id');
      triaged.add(rest[++index]);
    } else if (!['--json', '--spec-questions'].includes(rest[index])) {
      throw new Error(`unknown argument: ${rest[index]}`);
    }
  }

  // Default (no --adapter/--config): run the single PATH-OS reference adapter exactly as before
  // — the WG-visible invariant is "43 SELF-CHECK, 0 INTEROP-AGREE" for that run.
  let adapters;
  let unavailable = [];
  if (specs.length === 0) {
    adapters = [await startAdapterProcess(process.execPath, [path.join(HERE, 'reference-adapter-process.mjs')], { cwd: HERE })];
  } else {
    const launched = await launchAdapters(specs, { defaultCwd: HERE });
    adapters = launched.adapters;
    unavailable = launched.unavailable;
  }

  try {
    const report = await run(adapters, loadSeedCorpus(), { triagedSpecQuestions: triaged });
    if (unavailable.length) {
      report.unavailableAdapters = unavailable;
      if (!wantJson) {
        for (const { spec, reason } of unavailable) {
          process.stderr.write(`# UNAVAILABLE adapter (fail-closed): ${spec.command.join(' ')} — ${reason}\n`);
        }
      }
    }
    if (wantJson) printJson(report);
    else printHuman(report, { specQuestionsOnly });
    const unresolved = report.matrix.filter((row) =>
      row.status === 'VECTOR-MISMATCH' || row.status === 'IMPLEMENTATION-DIVERGENCE');
    return unresolved.length ? 1 : 0;
  } finally {
    await Promise.all(adapters.map((adapter) => adapter.close?.()));
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
