import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { homedir, hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import type { DemosWriteJournalKey, DemosWriteJournalRecord, SettleResult } from '../../src/adapters/dacs/sdk-journal-types.js';
import { main } from '../../src/cli/run-ledger.js';
import {
  createFsDemosWriteJournal,
  createFsSettlementLog,
  createIdempotencyStore,
  openRunLedger,
  reconcile,
  resolveRunLedgerDir,
} from '../../src/live/run-ledger.js';

const childHelper = fileURLToPath(new URL('../helpers/run-ledger-child.ts', import.meta.url));
const key = { chainIdentity: 'chain-1', wallet: 'wallet-1' };

function temporaryLedger(t: { after(fn: () => void): void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'pathos-run-ledger-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function keyDigest(value: DemosWriteJournalKey): string {
  return createHash('sha256')
    .update(value.chainIdentity)
    .update('\0')
    .update(value.wallet)
    .digest('hex');
}

function walletDir(dir: string, value: DemosWriteJournalKey = key): string {
  return join(dir, 'journal', keyDigest(value));
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

function settle(txHash: string, ok = true): SettleResult {
  return { ok, txHash, chainId: 'chain-1', payer: 'payer-1', payee: 'payee-1' };
}

interface RunningChild {
  child: ChildProcessWithoutNullStreams;
  complete: Promise<void>;
}

function startChild(action: string, dir: string): RunningChild {
  const childEnv = { ...process.env };
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, ['--import', 'tsx', childHelper, action, dir], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: childEnv,
  });
  let stderr = '';
  child.stdout.resume();
  child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
  const complete = new Promise<void>((resolveComplete, rejectComplete) => {
    child.once('error', rejectComplete);
    child.once('close', (code) => {
      if (code === 0) resolveComplete();
      else rejectComplete(new Error(`run-ledger child exited ${String(code)}: ${stderr}`));
    });
  });
  return { child, complete };
}

async function runBarrierChildren(action: string, dir: string): Promise<string[]> {
  const children = [startChild(action, dir), startChild(action, dir)];
  // Let both OS processes reach the filesystem gate before releasing them.
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 500));
  writeFileSync(join(dir, `.start-${action}`), 'start\n');
  await Promise.all(children.map(({ complete }) => complete));
  return children.map(({ child }) =>
    readFileSync(join(dir, `.result-${action}-${String(child.pid)}`), 'utf8'));
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

test('run ledger refuses a symlink into the checkout before writing stores', (t) => {
  const root = temporaryLedger(t);
  const link = join(root, 'checkout-link');
  const targetName = `.run-ledger-symlink-${process.pid}`;
  const target = join(process.cwd(), targetName);
  symlinkSync(process.cwd(), link, 'dir');
  t.after(() => rmSync(target, { recursive: true, force: true }));
  assert.throws(
    () => openRunLedger({ DACS_RUN_LEDGER_DIR: join(link, targetName) }),
    /inside git working tree.*outside the checkout/,
  );
  assert.equal(existsSync(join(target, 'journal')), false);
  assert.equal(existsSync(join(target, 'settlement')), false);
});

test('run ledger directory defaults under the OS home directory', () => {
  assert.equal(
    resolveRunLedgerDir({}),
    join(homedir(), '.pathos-dacs-ref', 'run-ledger'),
  );
});

test('journal hashes traversal-shaped identities instead of using path segments', async (t) => {
  const dir = temporaryLedger(t);
  const unusualKey = { chainIdentity: '..', wallet: '/' };
  const lease = await createFsDemosWriteJournal({ dir }).acquire(unusualKey);
  assert.equal(lease.snapshot.chainIdentity, '..');
  assert.equal(lease.snapshot.wallet, '/');
  assert.deepEqual(readdirSync(join(dir, 'journal')), [keyDigest(unusualKey)]);
  await lease.release();
});

test('journal refuses a planted symlink at the hashed wallet directory', async (t) => {
  const dir = temporaryLedger(t);
  const outside = temporaryLedger(t);
  createFsDemosWriteJournal({ dir });
  symlinkSync(outside, walletDir(dir), 'dir');
  await assert.rejects(
    createFsDemosWriteJournal({ dir }).acquire(key),
    /resolves outside/,
  );
  assert.deepEqual(readdirSync(outside), []);
});

test('on-disk lock token fences put and release preserves the newer owner', async (t) => {
  const dir = temporaryLedger(t);
  const journal = createFsDemosWriteJournal({ dir });
  const lease = await journal.acquire(key);
  const lockPath = join(walletDir(dir), 'lock.json');
  const newer = { token: 'newer-token', pid: process.pid, hostname: hostname(), createdAt: Date.now() };
  writeFileSync(lockPath, JSON.stringify(newer));
  await assert.rejects(lease.put(record(lease.generation)), /no longer current/);
  assert.equal(lease.snapshot.records.length, 0);
  await lease.release();
  assert.equal(JSON.parse(readFileSync(lockPath, 'utf8')).token, newer.token);
});

test('on-disk snapshot generation fences assertCurrent', async (t) => {
  const dir = temporaryLedger(t);
  const lease = await createFsDemosWriteJournal({ dir }).acquire(key);
  const snapshotPath = join(walletDir(dir), 'snapshot.json');
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as { generation: number };
  snapshot.generation += 1;
  writeFileSync(snapshotPath, JSON.stringify(snapshot));
  await assert.rejects(lease.assertCurrent(), /no longer current/);
  await lease.release();
});

test('snapshot replacement is atomic and corrupt snapshot reads name the file', async (t) => {
  const dir = temporaryLedger(t);
  const journal = createFsDemosWriteJournal({ dir });
  const lease = await journal.acquire(key);
  await lease.put(record(lease.generation));
  await lease.release();
  assert.deepEqual(readdirSync(walletDir(dir)).sort(), ['snapshot.json']);

  const snapshotPath = join(walletDir(dir), 'snapshot.json');
  writeFileSync(snapshotPath, '{not-json');
  await assert.rejects(
    journal.acquire(key),
    (error: unknown) => error instanceof Error && error.message.includes(snapshotPath) && /invalid JSON/.test(error.message),
  );
  assert.equal(readdirSync(walletDir(dir)).includes('snapshot.json'), true);
});

function writeLock(dir: string, owner: { token: string; pid: number; hostname: string; createdAt: number }): void {
  mkdirSync(walletDir(dir), { recursive: true });
  writeFileSync(join(walletDir(dir), 'lock.json'), JSON.stringify(owner));
}

test('dead local pid lock is reclaimed', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'dead', pid: 999999, hostname: hostname(), createdAt: Date.now() });
  const lease = await createFsDemosWriteJournal({ dir, lockStaleMs: 50, lockTimeoutMs: 100 }).acquire(key);
  assert.equal(lease.generation, 1);
  await lease.release();
});

test('two child acquirers race to reclaim a dead lock and exactly one wins', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'dead', pid: 999999, hostname: hostname(), createdAt: Date.now() });
  const outputs = await runBarrierChildren('reclaim', dir);
  assert.equal(outputs.filter((output) => output === 'acquired').length, 1, JSON.stringify(outputs));
  assert.equal(outputs.filter((output) => output.includes('rejected:timed out acquiring')).length, 1, JSON.stringify(outputs));
});

test('an old empty crash lock is reclaimed within one acquire attempt', async (t) => {
  const dir = temporaryLedger(t);
  mkdirSync(walletDir(dir), { recursive: true });
  const lockPath = join(walletDir(dir), 'lock.json');
  writeFileSync(lockPath, '');
  utimesSync(lockPath, new Date(0), new Date(0));
  const lease = await createFsDemosWriteJournal({
    dir,
    lockStaleMs: 5,
    lockTimeoutMs: 50,
  }).acquire(key);
  assert.equal(lease.generation, 1);
  await lease.release();
});

test('foreign-hostname lock is never stolen and times out', async (t) => {
  const dir = temporaryLedger(t);
  writeLock(dir, { token: 'foreign', pid: 999999, hostname: 'foreign.invalid', createdAt: 0 });
  const journal = createFsDemosWriteJournal({ dir, lockStaleMs: 1, lockTimeoutMs: 25 });
  await assert.rejects(journal.acquire(key), /timed out acquiring Demos wallet journal/);
});

test('a real child process live-pid lock waits and then times out', async (t) => {
  const dir = temporaryLedger(t);
  const holder = startChild('hold', dir);
  const lockPath = join(walletDir(dir), 'lock.json');
  const childPid = holder.child.pid;
  for (let attempts = 0; attempts < 100; attempts += 1) {
    try {
      if (JSON.parse(readFileSync(lockPath, 'utf8')).pid === childPid) break;
    } catch {
      // The child has not finished publishing its lock yet.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  assert.equal(JSON.parse(readFileSync(lockPath, 'utf8')).pid, childPid);
  const journal = createFsDemosWriteJournal({ dir, lockStaleMs: 1, lockTimeoutMs: 50 });
  const started = Date.now();
  await assert.rejects(journal.acquire(key), /timed out acquiring Demos wallet journal/);
  assert.ok(Date.now() - started >= 40);
  await holder.complete;
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

test('once success clears its intent and clean CLI reconcile exits 0', async (t) => {
  const dir = temporaryLedger(t);
  const store = createIdempotencyStore(createFsSettlementLog({ dir }));
  await store.once('rail:job:0', async () => settle('tx-1'));
  assert.deepEqual(reconcile(dir).settlements.openIntents, []);
  let output = '';
  const exit = await main(['reconcile'], { DACS_RUN_LEDGER_DIR: dir }, {
    write: (chunk) => { output += chunk; },
  });
  assert.equal(exit, 0);
  assert.match(output, /Open settlement intents: 0/);
});

test('reconcile omits a crash-window intent when a valid outcome exists', async (t) => {
  const dir = temporaryLedger(t);
  const log = createFsSettlementLog({ dir });
  await log.putOutcome('rail:job:0', settle('tx-1'));
  assert.equal(await log.claimIntent('rail:job:0'), 'claimed');
  assert.deepEqual(reconcile(dir).settlements.openIntents, []);
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
  assert.deepEqual(reconcile(dir).settlements.openIntents, []);
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

test('two child processes yield exactly one O_EXCL intent claim', async (t) => {
  const dir = temporaryLedger(t);
  const outputs = await runBarrierChildren('claim', dir);
  assert.equal(outputs.filter((output) => output === 'claimed').length, 1, JSON.stringify(outputs));
  assert.equal(outputs.filter((output) => output === 'held').length, 1, JSON.stringify(outputs));
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

test('CLI usage exits 2', async (t) => {
  const dir = temporaryLedger(t);
  let output = '';
  const exit = await main(['unknown'], { DACS_RUN_LEDGER_DIR: dir }, {
    write: (chunk) => { output += chunk; },
  });
  assert.equal(exit, 2);
  assert.match(output, /^Usage:/);
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

test('CLI reconcile exits 3 for an unresolved journal write', async (t) => {
  const dir = temporaryLedger(t);
  const lease = await createFsDemosWriteJournal({ dir }).acquire(key);
  await lease.put(record(lease.generation));
  await lease.release();
  const exit = await main(['reconcile'], { DACS_RUN_LEDGER_DIR: dir }, { write: () => undefined });
  assert.equal(exit, 3);
});
