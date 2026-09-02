import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  createFsDemosWriteJournal,
  createFsSettlementLog,
} from '../../src/live/run-ledger.js';

const action = process.argv[2];
const dir = process.argv[3];
const key = { chainIdentity: 'chain-1', wallet: 'wallet-1' };

if (!action || !dir) throw new Error('child action and ledger directory are required');
const childAction = action;
const ledgerDir = dir;

async function waitForStart(): Promise<void> {
  process.stdout.write('READY\n');
  const gate = join(ledgerDir, `.start-${childAction}`);
  while (!existsSync(gate)) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

if (childAction === 'claim') {
  await waitForStart();
  const result = await createFsSettlementLog({ dir: ledgerDir }).claimIntent('rail:job:0');
  writeFileSync(join(ledgerDir, `.result-${childAction}-${process.pid}`), result);
} else if (childAction === 'reclaim') {
  await waitForStart();
  try {
    const lease = await createFsDemosWriteJournal({
      dir: ledgerDir,
      lockStaleMs: 50,
      lockTimeoutMs: 150,
    }).acquire(key);
    writeFileSync(join(ledgerDir, `.result-${childAction}-${process.pid}`), 'acquired');
    await new Promise((resolve) => setTimeout(resolve, 250));
    await lease.release();
  } catch (error) {
    writeFileSync(
      join(ledgerDir, `.result-${childAction}-${process.pid}`),
      `rejected:${error instanceof Error ? error.message : String(error)}`,
    );
  }
} else if (childAction === 'hold') {
  const lease = await createFsDemosWriteJournal({ dir: ledgerDir }).acquire(key);
  process.stdout.write('READY\n');
  await new Promise((resolve) => setTimeout(resolve, 200));
  await lease.release();
} else {
  throw new Error(`unknown child action ${childAction}`);
}
