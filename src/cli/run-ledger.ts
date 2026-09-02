#!/usr/bin/env tsx

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { openRunLedger, reconcile, type ReconcileReport } from '../live/run-ledger.js';

interface Output {
  write(chunk: string): unknown;
}

function linesFor(dir: string, report: ReconcileReport): string[] {
  const lines = [
    `Run ledger: ${dir}`,
    `Journals: ${report.journals.length}`,
  ];
  for (const journal of report.journals) {
    lines.push(`  ${journal.chainIdentity} / ${journal.wallet} (generation ${journal.generation})`);
    const stages = Object.entries(journal.byStage);
    lines.push(`    stages: ${stages.length === 0 ? 'none' : stages.map(([stage, count]) => `${stage}=${count}`).join(', ')}`);
    for (const record of journal.unresolved) {
      lines.push(`    unresolved: ${record.writeId} stage=${record.stage} nonce=${record.nonce}${record.txRef ? ` txRef=${record.txRef}` : ''}`);
    }
  }
  lines.push(`Settlement outcomes: ${report.settlements.outcomes}`);
  lines.push(`Open settlement intents: ${report.settlements.openIntents.length}`);
  for (const hash of report.settlements.openIntents) lines.push(`  ${hash}`);
  return lines;
}

export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  stdout: Output = process.stdout,
): Promise<number> {
  const command = argv[0];
  if (command !== 'status' && command !== 'reconcile') {
    stdout.write('Usage: npm run run-ledger -- <status|reconcile>\n');
    return 2;
  }
  const { dir } = openRunLedger(env);
  const report = reconcile(dir);
  stdout.write(`${linesFor(dir, report).join('\n')}\n`);
  if (command === 'status') return 0;
  const hasUnresolvedWrites = report.journals.some((journal) => journal.unresolved.length > 0);
  return hasUnresolvedWrites || report.settlements.openIntents.length > 0 ? 3 : 0;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (error: unknown) => {
      process.stderr.write(`run-ledger: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
