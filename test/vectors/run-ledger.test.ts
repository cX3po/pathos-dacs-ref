import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import type { DemosWriteJournalRecord, SettleResult } from '../../src/adapters/dacs/sdk-journal-types.js';
import { main } from '../../src/cli/run-ledger.js';
import {
  createFsDemosWriteJournal,
  createFsSettlementLog,
  createIdempotencyStore,
  reconcile,
  resolveRunLedgerDir,
} from '../../src/live/run-ledger.js';

function temporaryLedger(t: { after(fn: () => void): void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'pathos-run-ledger-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function record(
  generation: number,
  writeId = 'write-1',
  stage: DemosWriteJournalRecord['stage'] = 'prepared',
): DemosWriteJournalRecord {
  return {
    writeId,
    generation,
    kind: 'mutable',
    operation: 'create',
    stage,
    logicalName: `logical-${writeId}`,
    programName: `program-${writeId}`,
    owner: 'wallet-1',
    nativeAddress: `native-${writeId}`,
    valueHash: `value-${writeId}`,
    nonce: generation,
    updatedAt: Date.now(),
    ...(stage === 'prepared' ? {} : {
      txRef: `tx-${writeId}`,
      signedTransaction: `signed-secret-${writeId}`,
      signedTransactionHash: `signed-hash-${writeId}`,
    }),
  };
}

const key = { chainIdentity: 'chain-1', wallet: 'wallet-1' };

function settle(txHash: string, ok = true): SettleResult {
  return { ok, txHash, chainId: 'chain-1', payer: 'payer-1', payee: 'payee-1' };
}

test('run ledger directory refuses a path inside a git working tree', (t) => {
  const root = temporaryLedger(t);
  writeFileSync(join(root, '.git'), 'gitdir: elsewhere\n');
  const nested = join(root, 'nested', 'ledger');
  assert.throws(
    () => resolveRunLedgerDir({ DACS_RUN_LEDGER_DIR: nested }),
    /inside git working tree.*outside the checkout/,
  );
});

test('run ledger directory defaults under the OS home directory', () => {
  assert.equal(
    resolveRunLedgerDir({}),
    join(homedir(), '.pathos-dacs-ref', 'run-ledger'),
  );
});

test('generation fence rejects the earlier lease after a second acquire', async (t) => {
  const dir = temporaryLedger(t);
  const journal = createFsDemosWriteJournal({ dir });
  const first = await journal.acquire(key);
  await first.put(record(first.generation));
  await first.release();

  const second = await journal.acquire(key);
  assert.equal(second.generation, first.generation + 1);
  await assert.rejects(first.assertCurrent(), /fence 1 was released/);
  await assert.rejects(first.put(record(first.generation, 'stale')), /fence 1 was released/);
  assert.equal(second.snapshot.records.length, 1);
  await second.release();
});

test('snapshot replacement is atomic and corrupt snapshot reads name the file', async (t) => {
  const dir = temporaryLedger(t);
  const journal = createFsDemosWriteJournal({ dir });
  const lease = await journal.acquire(key);
  await lease.put(record(lease.generation));
  await lease.release();
  const walletDir = join(dir, 'journal', key.chainIdentity, key.wallet);
  assert.deepEqual(readdirSync(walletDir).sort(), ['snapshot.json']);

  const snapshotPath = join(walletDir, 'snapshot.json');
  writeFileSync(snapshotPath, '{not-json');
  await assert.rejects(
    journal.acquire(key),
    (error: unknown) => error instanceof Error && error.message.includes(snapshotPath) && /invalid JSON/.test(error.message),
  );
  assert.equal(readdirSync(walletDir).includes('snapshot.json'), true);
});

function writeLock(dir: string, owner: { token: string; pid: number; hostname: string; createdAt: number }): void {
  const walletDir = join(dir, 'journal', key.chainIdentity, key.wallet);
  mkdirSync(walletDir, { recursive: true });
  writeFileSync(join(walletDir, 'lock.json'), JSON.stringify(owner));
}

test('dead local pid lock is reclaimed', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'dead', pid: 999999, hostname: hostname(), createdAt: Date.now() });
  const lease = await createFsDemosWriteJournal({ dir, lockTimeoutMs: 100 }).acquire(key);
  assert.equal(lease.generation, 1);
  await lease.release();
});

test('foreign-hostname lock is never stolen and times out', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'foreign', pid: 999999, hostname: 'foreign.invalid', createdAt: 0 });
  const journal = createFsDemosWriteJournal({ dir, lockStaleMs: 1, lockTimeoutMs: 25 });
  await assert.rejects(journal.acquire(key), /timed out acquiring Demos wallet journal/);
});

test('live local pid lock waits and then times out', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'live', pid: process.pid, hostname: hostname(), createdAt: Date.now() });
  const journal = createFsDemosWriteJournal({ dir, lockStaleMs: 1, lockTimeoutMs: 25 });
  const started = Date.now();
  await assert.rejects(journal.acquire(key), /timed out acquiring Demos wallet journal/);
  assert.ok(Date.now() - started >= 20);
});

test('recorded settlement outcome is returned without resubmitting', async (t) => {
  const dir = temporaryLedger(t);
  const store = createIdempotencyStore(createFsSettlementLog({ dir }));
  let submits = 0;
  const submit = async (): Promise<SettleResult> => settle(`tx-${++submits}`);
  assert.equal((await store.once('rail:job:0', submit)).txHash, 'tx-1');
  assert.equal((await store.once('rail:job:0', submit)).txHash, 'tx-1');
  assert.equal(submits, 1);
});

test('unresolved settlement intent without reconcile fails closed with SDK text', async (t) => {
  const dir = temporaryLedger(t);
  const log = createFsSettlementLog({ dir });
  assert.equal(await log.claimIntent('rail:job:0'), 'claimed');
  const store = createIdempotencyStore(log);
  await assert.rejects(
    store.once('rail:job:0', async () => settle('must-not-submit')),
    /settlement rail:job:0 has an unresolved or in-flight prior attempt and no reconcile capability; refusing to resubmit \(double-pay risk\)/,
  );
});

test('reconcile adopts a definitive prior settlement without submitting', async (t) => {
  const dir = temporaryLedger(t);
  const log = createFsSettlementLog({ dir });
  await log.claimIntent('rail:job:0');
  let submits = 0;
  const result = await createIdempotencyStore(log).once(
    'rail:job:0',
    async () => { submits += 1; return settle('new'); },
    async () => settle('reconciled'),
  );
  assert.equal(result.txHash, 'reconciled');
  assert.equal(submits, 0);
  assert.equal((await log.getOutcome('rail:job:0'))?.txHash, 'reconciled');
});

test('no-transaction settlement result releases intent and permits a new submit', async (t) => {
  const dir = temporaryLedger(t);
  const store = createIdempotencyStore(createFsSettlementLog({ dir }));
  let submits = 0;
  const first = await store.once('rail:job:0', async () => {
    submits += 1;
    return settle('', false);
  });
  assert.equal(first.txHash, '');
  const second = await store.once('rail:job:0', async () => {
    submits += 1;
    return settle('tx-retry');
  });
  assert.equal(second.txHash, 'tx-retry');
  assert.equal(submits, 2);
});

test('two independent settlement logs yield exactly one atomic intent claim', async (t) => {
  const dir = temporaryLedger(t);
  const first = createFsSettlementLog({ dir });
  const second = createFsSettlementLog({ dir });
  const claims = await Promise.all([
    first.claimIntent('rail:job:0'),
    second.claimIntent('rail:job:0'),
  ]);
  assert.equal(claims.filter((claim) => claim === 'claimed').length, 1);
  assert.equal(claims.filter((claim) => claim === 'held').length, 1);
});

test('reconcile counts stages and omits signed transactions and proofs', async (t) => {
  const dir = temporaryLedger(t);
  const journal = createFsDemosWriteJournal({ dir });
  const lease = await journal.acquire(key);
  await lease.put(record(lease.generation, 'pending', 'prepared'));
  await lease.put(record(lease.generation, 'failed', 'canonical-failed'));
  await lease.release();
  const settlement = createFsSettlementLog({ dir });
  await settlement.putOutcome('rail:done:0', settle('tx-done'));
  await settlement.claimIntent('rail:open:0');

  const report = reconcile(dir);
  assert.equal(report.journals.length, 1);
  assert.deepEqual(report.journals[0]?.byStage, { prepared: 1, 'canonical-failed': 1 });
  assert.deepEqual(report.journals[0]?.unresolved, [{ writeId: 'pending', stage: 'prepared', nonce: 1 }]);
  assert.equal(report.settlements.outcomes, 1);
  assert.deepEqual(report.settlements.openIntents, [
    createHash('sha256').update('rail:open:0').digest('hex'),
  ]);
  const rendered = JSON.stringify(report);
  assert.equal(rendered.includes('signedTransaction'), false);
  assert.equal(rendered.includes('finalityProof'), false);
  assert.equal(rendered.includes('signed-secret'), false);
});

test('CLI status exits 0 and reconcile exits 3 for an open intent', async (t) => {
  const dir = temporaryLedger(t);
  await createFsSettlementLog({ dir }).claimIntent('rail:open:0');
  const env = { DACS_RUN_LEDGER_DIR: dir };
  let statusOutput = '';
  const status = await main(['status'], env, { write: (chunk) => { statusOutput += chunk; } });
  assert.equal(status, 0);
  assert.match(statusOutput, new RegExp(`Run ledger: ${dir}`));
  assert.match(statusOutput, /Open settlement intents: 1/);

  let reconcileOutput = '';
  const reconcileExit = await main(['reconcile'], env, { write: (chunk) => { reconcileOutput += chunk; } });
  assert.equal(reconcileExit, 3);
  assert.match(reconcileOutput, /Open settlement intents: 1/);
});
