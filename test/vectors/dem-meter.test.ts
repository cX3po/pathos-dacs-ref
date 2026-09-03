import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';

import {
  createDemMeter,
  type MeterEntry,
  type MeterRow,
} from '../../src/adapters/demos/dem-meter.js';
import { settlePayDemCore, type DemosNativeClient } from '../../src/adapters/dacs/pay-dem.js';
import { createProofLedger, type ReceiptEntry } from '../../src/adapters/demos/proof-ledger.js';
import type { DemosHandle } from '../../src/demos/connection.js';
import type { FetchResult } from '../../src/demos/storage.js';
import { jcsHashHex } from '../../src/jcs.js';
import { runDemMeterCli } from '../../src/live/dem-meter.mjs';

const A = `cci:${'a'.repeat(64)}`;
const B = `cci:${'b'.repeat(64)}`;
const RECEIPT = 'c'.repeat(64);
const T0 = '2026-09-02T10:00:00.000Z';
const T1 = '2026-09-02T11:00:00.000Z';

function temporaryMeter(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'dem-meter-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'meter.jsonl');
  return { path, meter: createDemMeter({ path, now: () => T0, agent: 'seat-one' }) };
}

test('record/read round trip writes JCS rows linked by hashes', (t) => {
  const { path, meter } = temporaryMeter(t);
  const first = meter.record({ kind: 'seat-call', os: '7', receiptHash: RECEIPT });
  const second = meter.record({ agent: A, kind: 'tool-call', dem: '1.25', at: T1, ref: 'tool:x' });
  assert.equal(second.os, '1250000000');
  assert.equal(second.prevRowHash, first.rowHash);
  assert.deepEqual(meter.read(), [first, second]);
  for (const line of readFileSync(path, 'utf8').trimEnd().split('\n')) {
    assert.equal(JSON.stringify(JSON.parse(line)), line);
  }
});

test('fresh meter creates its initial sidecar before any record', (t) => {
  const { path } = temporaryMeter(t);
  assert.deepEqual(JSON.parse(readFileSync(`${path}.head`, 'utf8')), {
    rowCount: 0,
    meterHead: null,
  });
  assert.equal(existsSync(path), false);
});

test('read detects an edited line', (t) => {
  const { path, meter } = temporaryMeter(t);
  meter.record({ kind: 'seat-call', os: '7' });
  const text = readFileSync(path, 'utf8').replace('"os":"7"', '"os":"8"');
  writeFileSync(path, text);
  assert.throws(() => meter.read(), /chain is broken/);
});

test('read detects reordered rows, suffix truncation, blank lines, and mixed-case stored CCI', async (t) => {
  await t.test('reorder', (t) => {
    const { path, meter } = temporaryMeter(t);
    meter.record({ kind: 'seat-call', os: '7' });
    meter.record({ kind: 'tool-call', os: '8' });
    const lines = readFileSync(path, 'utf8').trimEnd().split('\n');
    writeFileSync(path, `${lines.reverse().join('\n')}\n`);
    assert.throws(() => meter.read(), /chain is broken/);
  });
  await t.test('suffix truncation', (t) => {
    const { path, meter } = temporaryMeter(t);
    meter.record({ kind: 'seat-call', os: '7' });
    meter.record({ kind: 'tool-call', os: '8' });
    const first = readFileSync(path, 'utf8').split('\n')[0];
    writeFileSync(path, `${first}\n`);
    assert.throws(() => meter.read(), (error: unknown) =>
      (error as { code?: string }).code === 'head-mismatch');
  });
  await t.test('missing head after first append', (t) => {
    const { path, meter } = temporaryMeter(t);
    meter.record({ kind: 'seat-call', os: '7' });
    rmSync(`${path}.head`);
    for (const operation of [() => meter.read(), () => meter.record({ kind: 'tool-call', os: '8' })]) {
      assert.throws(operation, (error: unknown) =>
        (error as { code?: string }).code === 'head-missing');
    }
    assert.deepEqual(meter.repair(), { repaired: 'uncommitted-tail', removedRows: 1 });
    assert.equal(readFileSync(path).length, 0);
    assert.deepEqual(JSON.parse(readFileSync(`${path}.head`, 'utf8')), {
      rowCount: 0,
      meterHead: null,
    });
    const next = meter.record({ kind: 'tool-call', os: '8' });
    assert.equal(next.prevRowHash, undefined);
    assert.deepEqual(meter.read(), [next]);
  });
  await t.test('blank line', (t) => {
    const { path, meter } = temporaryMeter(t);
    meter.record({ kind: 'seat-call', os: '7' });
    appendFileSync(path, '\n');
    assert.throws(() => meter.read(), /blank/);
  });
  await t.test('stored mixed-case CCI', (t) => {
    const { path, meter } = temporaryMeter(t);
    const row = meter.record({ agent: `cci:${'A'.repeat(64)}`, kind: 'seat-call', os: '7' });
    assert.equal(row.agent, A);
    const text = readFileSync(path, 'utf8').replace(`"agent":"${A}"`, `"agent":"cci:${'A'.repeat(64)}"`);
    writeFileSync(path, text);
    assert.throws(() => meter.read(), /lowercase hexadecimal/);
  });
});

test('partial tail fails closed, blocks record, and repair restores the guarded prefix', (t) => {
  const { path, meter } = temporaryMeter(t);
  const first = meter.record({ kind: 'seat-call', os: '7' });
  appendFileSync(path, '{"agent"');
  for (const operation of [() => meter.read(), () => meter.record({ kind: 'tool-call', os: '8' })]) {
    assert.throws(operation, (error: unknown) => (error as { code?: string }).code === 'partial-tail');
  }
  assert.deepEqual(meter.repair(), { rowCount: 1, meterHead: first.rowHash });
  assert.deepEqual(meter.read(), [first]);
  assert.equal(meter.record({ kind: 'tool-call', os: '8' }).prevRowHash, first.rowHash);
});

test('repair rolls back a complete uncommitted tail to the committed head', (t) => {
  const { path, meter } = temporaryMeter(t);
  const first = meter.record({ kind: 'seat-call', os: '7' });
  const committedHead = readFileSync(`${path}.head`);
  meter.record({ kind: 'tool-call', os: '8' });
  writeFileSync(`${path}.head`, committedHead);

  for (const operation of [() => meter.read(), () => meter.record({ kind: 'anchor', os: '9' })]) {
    assert.throws(operation, (error: unknown) => (error as { code?: string }).code === 'head-mismatch');
  }
  assert.deepEqual(meter.repair(), { repaired: 'uncommitted-tail', removedRows: 1 });
  assert.deepEqual(meter.read(), [first]);
  assert.equal(readFileSync(path, 'utf8').trimEnd().split('\n').length, 1);

  const next = meter.record({ kind: 'anchor', os: '9' });
  assert.equal(next.prevRowHash, first.rowHash);
  assert.deepEqual(meter.read(), [first, next]);
});

test('repair refuses a complete tail when the committed prefix does not match the head', (t) => {
  const { path, meter } = temporaryMeter(t);
  meter.record({ kind: 'seat-call', os: '7' });
  const second = meter.record({ kind: 'tool-call', os: '8' });
  writeFileSync(`${path}.head`, JSON.stringify({ rowCount: 1, meterHead: second.rowHash }));
  assert.throws(() => meter.repair(),
    (error: unknown) => (error as { code?: string }).code === 'meter-invalid');
});

test('repair initializes a missing head for an empty or absent log', async (t) => {
  await t.test('absent log', (t) => {
    const { path, meter } = temporaryMeter(t);
    rmSync(`${path}.head`);
    assert.deepEqual(meter.repair(), { rowCount: 0, meterHead: null });
    assert.deepEqual(JSON.parse(readFileSync(`${path}.head`, 'utf8')), {
      rowCount: 0, meterHead: null,
    });
  });
  await t.test('empty log', (t) => {
    const { path, meter } = temporaryMeter(t);
    writeFileSync(path, '');
    rmSync(`${path}.head`);
    assert.deepEqual(meter.repair(), { rowCount: 0, meterHead: null });
    assert.deepEqual(JSON.parse(readFileSync(`${path}.head`, 'utf8')), {
      rowCount: 0, meterHead: null,
    });
  });
});

test('meter lock recovers an old owner record', (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, JSON.stringify({
    pid: process.pid, createdAt: Date.now() - 30_001, token: 'old-owner',
  }));
  assert.deepEqual(meter.read(), []);
  assert.equal(existsSync(`${path}.lock`), false);
});

test('meter lock recovers an aged empty crash lock by mtime', (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, '');
  const old = new Date(Date.now() - 30_001);
  utimesSync(`${path}.lock`, old, old);
  assert.deepEqual(meter.read(), []);
  assert.equal(existsSync(`${path}.lock`), false);
});

test('meter lock bounds future owner clock skew', (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, JSON.stringify({
    pid: process.pid, createdAt: Date.now() + 60_000, token: 'future-owner',
  }));
  assert.deepEqual(meter.read(), []);
  assert.equal(existsSync(`${path}.lock`), false);
});

test('meter lock treats EPERM while probing a pid as live', (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, JSON.stringify({
    pid: process.pid + 1, createdAt: Date.now(), token: 'other-user-owner',
  }));
  const originalKill = process.kill;
  process.kill = (() => {
    const error = new Error('not permitted') as NodeJS.ErrnoException;
    error.code = 'EPERM';
    throw error;
  }) as typeof process.kill;
  try {
    assert.throws(() => meter.read(),
      (error: unknown) => (error as { code?: string }).code === 'meter-busy');
  } finally {
    process.kill = originalKill;
  }
  assert.equal((JSON.parse(readFileSync(`${path}.lock`, 'utf8')) as { token: string }).token,
    'other-user-owner');
});

test('two processes racing stale-lock reclaim serialize their records', async (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, '');
  const old = new Date(Date.now() - 30_001);
  utimesSync(`${path}.lock`, old, old);
  const source = [
    "const { createDemMeter } = await import('./src/adapters/demos/dem-meter.ts');",
    'const meter = createDemMeter({ path: process.argv[1], agent: process.argv[2],',
    "  now: () => '2026-09-02T10:00:00.000Z' });",
    "meter.record({ kind: 'seat-call', os: '1' });",
  ].join('\n');
  const run = (agent: string) => new Promise<{ code: number | null; error?: NodeJS.ErrnoException }>((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', source, path, agent], {
      cwd: process.cwd(), stdio: 'ignore',
    });
    child.once('error', (error) => resolve({ code: null, error }));
    child.once('close', (code) => resolve({ code }));
  });
  const results = await Promise.all([run('seat-one'), run('seat-two')]);
  if (results.some((result) => result.error?.code === 'EPERM')) {
    t.skip('sandbox forbids child-process creation from node:test');
    return;
  }
  assert.deepEqual(results.map((result) => result.code), [0, 0]);
  assert.equal(meter.read().length, 2);
});

test('meter lock keeps a live foreign owner and fails with meter-busy', (t) => {
  const { path, meter } = temporaryMeter(t);
  writeFileSync(`${path}.lock`, JSON.stringify({
    pid: process.pid, createdAt: Date.now(), token: 'live-owner',
  }));
  assert.throws(() => meter.read(),
    (error: unknown) => (error as { code?: string }).code === 'meter-busy');
  assert.equal((JSON.parse(readFileSync(`${path}.lock`, 'utf8')) as { token: string }).token, 'live-owner');
});

test('meter release never removes a replacement owner lock', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'dem-meter-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'meter.jsonl');
  const meter = createDemMeter({
    path,
    agent: 'seat-one',
    now: () => {
      writeFileSync(`${path}.lock`, JSON.stringify({
        pid: process.pid, createdAt: Date.now(), token: 'replacement-owner',
      }));
      return T0;
    },
  });
  meter.record({ kind: 'seat-call', os: '7' });
  assert.equal(
    (JSON.parse(readFileSync(`${path}.lock`, 'utf8')) as { token: string }).token,
    'replacement-owner',
  );
});

test('record rejects every malformed input rule', async (t) => {
  const { meter } = temporaryMeter(t);
  const invalid: Array<[string, unknown]> = [
    ['negative OS', { agent: 'seat', kind: 'tool-call', os: '-1' }],
    ['non-integer OS', { agent: 'seat', kind: 'tool-call', os: '1.5' }],
    ['non-canonical OS', { agent: 'seat', kind: 'tool-call', os: '01' }],
    ['bad DEM', { agent: 'seat', kind: 'tool-call', dem: '1.0' }],
    ['negative DEM', { agent: 'seat', kind: 'tool-call', dem: '-1' }],
    ['both units', { agent: 'seat', kind: 'tool-call', os: '1', dem: '1' }],
    ['no units', { agent: 'seat', kind: 'tool-call' }],
    ['hash', { agent: 'seat', kind: 'tool-call', os: '1', receiptHash: 'ABC' }],
    ['kind', { agent: 'seat', kind: 'other', os: '1' }],
    ['seat', { agent: 'Seat One', kind: 'tool-call', os: '1' }],
    ['claim', { agent: 'cci:short', kind: 'tool-call', os: '1' }],
    ['timestamp', { agent: 'seat', kind: 'tool-call', os: '1', at: '2026-09-02' }],
  ];
  for (const [name, entry] of invalid) {
    await t.test(name, () => assert.throws(() => meter.record(entry as MeterEntry)));
  }
});

test('summaries use exact integer totals beyond 2^53', (t) => {
  const { meter } = temporaryMeter(t);
  meter.record({ agent: A, kind: 'seat-call', os: '9007199254740993', at: T0 });
  meter.record({ agent: A, kind: 'tool-call', dem: '0.000000007', at: T1 });
  meter.record({ agent: B, kind: 'tool-call', os: '5', at: T1 });
  const all = meter.summarize();
  assert.equal(all.rowCount, 3);
  assert.equal(all.totalOs, '9007199254741005');
  assert.equal(all.totalDem, '9007199.254741005');
  assert.deepEqual(all.byAgent[A], { count: 2, os: '9007199254741000', dem: '9007199.254741' });
  assert.deepEqual(all.byKind['tool-call'], { count: 2, os: '12', dem: '0.000000012' });
  assert.equal(meter.summarize({ since: T1, until: '2026-09-02T12:00:00.000Z' }).rowCount, 2);
});

test('invoice shape and content hash are deterministic', (t) => {
  const { meter } = temporaryMeter(t);
  meter.record({ agent: A, kind: 'anchor', os: '1000000000', at: T0, receiptHash: RECEIPT });
  meter.record({ agent: A, kind: 'anchor', os: '2', at: T1, receiptHash: RECEIPT });
  const opts = { from: A, to: B, issuer: A, payer: B, since: T0, until: '2026-09-03T00:00:00.000Z' };
  const invoice = meter.invoice(opts);
  assert.deepEqual(invoice.lines, [{ kind: 'anchor', count: 2, os: '1000000002', dem: '1.000000002' }]);
  assert.equal(invoice.totalOs, '1000000002');
  assert.deepEqual(invoice.meteredReceiptHashes, [RECEIPT]);
  assert.equal(invoice.notice,
    'unsigned internal accounting; not a DACS artifact, not settlement proof, not a payment request');
  const { contentHash, ...unsigned } = invoice;
  assert.equal(contentHash, jcsHashHex(unsigned));
  assert.deepEqual(meter.invoice(opts), invoice);
});

async function proofHarness(meter?: { record(entry: MeterEntry): MeterRow; agent: string }) {
  const owner = `0x${'1'.repeat(64)}`;
  const stored = new Map<string, FetchResult>();
  const handle = {
    address: owner,
    rpc: 'offline:',
    demos: { async getAddressNonce() { return 0; } },
  } as unknown as DemosHandle;
  const fetchAnchoredImpl = async (_rpc: string, address: string) => stored.get(address) ?? null;
  const broadcastImpl = async (_handle: DemosHandle, raw: unknown) => {
    const payload = raw as { storageAddress: string; data: unknown };
    stored.set(payload.storageAddress, {
      storageAddress: payload.storageAddress, owner, data: payload.data, sizeBytes: 1, createdAt: T0,
    });
    return { txHash: 'anchor-tx' };
  };
  return createProofLedger({
    handle, rpc: 'offline:', ledgerName: 'meter-hook', fetchAnchoredImpl, broadcastImpl, meter,
  });
}

const proofEntry: ReceiptEntry = {
  kind: 'test', ref: 'r', contentHash: 'd'.repeat(64), at: T0,
};

test('proof-ledger append records one anchor only when a meter is present', async () => {
  const recorded: MeterEntry[] = [];
  const fake = { agent: A, record(entry: MeterEntry) { recorded.push(entry); return {} as MeterRow; } };
  await (await proofHarness(fake)).append(proofEntry);
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0]?.kind, 'anchor');
  assert.match(String(recorded[0]?.os), /^\d+$/);
  assert.match(String(recorded[0]?.ref), /^stor-/);
  await (await proofHarness()).append(proofEntry);
  assert.equal(recorded.length, 1);
});

test('proof-ledger isolates a throwing meter after success and advances its in-memory head', async () => {
  const ledger = await proofHarness({
    agent: A,
    record() { throw new Error('sensitive implementation detail'); },
  });
  const first = await ledger.append(proofEntry);
  assert.equal(first.txHash, 'anchor-tx');
  assert.deepEqual(first.meterError, { code: 'meter-failed', message: 'DEM meter record failed' });
  const second = await ledger.append({ ...proofEntry, ref: 'r2' });
  assert.equal(second.entryCount, 2);
  assert.equal(second.txHash, 'anchor-tx');
  assert.deepEqual(second.meterError, { code: 'meter-failed', message: 'DEM meter record failed' });
});

test('proof-ledger hook writes one well-formed row through a real DEM meter with its configured agent', async (t) => {
  const { meter } = temporaryMeter(t);
  const result = await (await proofHarness({ record: meter.record, agent: A })).append(proofEntry);
  assert.equal(result.txHash, 'anchor-tx');
  assert.equal(result.meterError, undefined);
  const rows = meter.read();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.agent, A);
  assert.equal(rows[0]?.kind, 'anchor');
  assert.match(rows[0]?.os ?? '', /^\d+$/);
});

test('pay-dem settlement records one finalized transfer', async () => {
  const recorded: MeterEntry[] = [];
  const client: DemosNativeClient = {
    address: 'payer',
    async transfer() { return { ok: true, hash: 'tx-hash', state: 'included', blockNumber: 1 }; },
  };
  const result = await settlePayDemCore({
    recipient: 'payee', amountDemCanonical: '1.25', currency: 'DEM', jobId: 'job', phaseIndex: 0,
  }, client, {
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: T0 }; },
    meter: { record(entry) { recorded.push(entry); return {} as MeterRow; } },
  });
  assert.equal(result.ok, true);
  assert.deepEqual(recorded, [{ agent: 'payer', kind: 'transfer', os: '1250000000', ref: 'tx-hash' }]);
});

test('pay-dem isolates a throwing meter after an included transfer', async () => {
  const client: DemosNativeClient = {
    address: 'payer',
    async transfer() { return { ok: true, hash: 'tx-hash', state: 'included', blockNumber: 1 }; },
  };
  const result = await settlePayDemCore({
    recipient: 'payee', amountDemCanonical: '1.25', currency: 'DEM', jobId: 'job', phaseIndex: 0,
  }, client, {
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: T0 }; },
    meter: { record() { throw new Error('sensitive implementation detail'); } },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.txHash, 'tx-hash');
  assert.deepEqual(result.meterError, { code: 'meter-failed', message: 'DEM meter record failed' });
});

test('pay-dem hook writes one well-formed row through a real DEM meter with the buyer agent', async (t) => {
  const { meter } = temporaryMeter(t);
  const client: DemosNativeClient = {
    address: A,
    async transfer() { return { ok: true, hash: 'tx-hash', state: 'included', blockNumber: 1 }; },
  };
  const result = await settlePayDemCore({
    recipient: 'payee', amountDemCanonical: '1.25', currency: 'DEM', jobId: 'job', phaseIndex: 0,
  }, client, {
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: T0 }; },
    meter: { record: meter.record },
  });
  assert.equal(result.ok, true);
  const rows = meter.read();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.agent, A);
  assert.equal(rows[0]?.kind, 'transfer');
  assert.equal(rows[0]?.os, '1250000000');
});

test('DEM meter CLI summary works in process and as a spawned command', (t) => {
  const { path, meter } = temporaryMeter(t);
  meter.record({ kind: 'verify-call', os: '9' });
  const direct = runDemMeterCli(['--summary', '--path', path], {});
  assert.equal((direct as { totalOs: string }).totalOs, '9');
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, [
    '--import', 'tsx', 'src/live/dem-meter.mts', '--summary', '--path', path,
  ], { cwd: process.cwd(), encoding: 'utf8', env });
  if ((run.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('sandbox forbids child-process creation from node:test');
    return;
  }
  assert.equal(run.status, 0, run.stderr);
  assert.equal((JSON.parse(run.stdout) as { totalOs: string }).totalOs, '9');
});

test('DEM meter CLI verify, invoice, and repair success and fail closed without disclosure', (t) => {
  const env: NodeJS.ProcessEnv = { ...process.env, DEM_METER_TEST_SECRET: 'meter-secret-sentinel' };
  delete env.NODE_TEST_CONTEXT;
  const spawn = (args: string[]) => spawnSync(process.execPath, [
    '--import', 'tsx', 'src/live/dem-meter.mts', ...args,
  ], { cwd: process.cwd(), encoding: 'utf8', env });
  const assertPrivateFailure = (run: ReturnType<typeof spawnSync>, path: string) => {
    assert.equal(run.status, 1);
    const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    assert.doesNotMatch(output, new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.doesNotMatch(output, /meter-secret-sentinel/);
    assert.deepEqual(JSON.parse(String(run.stderr)), { ok: false, error: 'DEM meter command failed' });
  };

  const valid = temporaryMeter(t);
  valid.meter.record({ agent: A, kind: 'anchor', os: '9', receiptHash: RECEIPT });
  const verify = spawn(['--verify', '--path', valid.path]);
  if ((verify.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('sandbox forbids child-process creation from node:test');
    return;
  }
  assert.equal(verify.status, 0);
  assert.deepEqual(JSON.parse(verify.stdout), {
    ok: true, rowCount: 1, meterHead: valid.meter.read()[0]?.rowHash,
  });
  const invoice = spawn([
    '--invoice', '--path', valid.path, '--from', A, '--to', B,
    '--since', T0, '--until', '2026-09-03T00:00:00.000Z',
  ]);
  assert.equal(invoice.status, 0);
  const invoiceJson = JSON.parse(invoice.stdout) as { notice: string; meteredReceiptHashes: string[] };
  assert.match(invoiceJson.notice, /^unsigned internal accounting/);
  assert.deepEqual(invoiceJson.meteredReceiptHashes, [RECEIPT]);

  const lines = readFileSync(valid.path, 'utf8').trimEnd().split('\n');
  writeFileSync(valid.path, lines.length > 1 ? `${lines[0]}\n` : '');
  assertPrivateFailure(spawn(['--verify', '--path', valid.path]), valid.path);
  assertPrivateFailure(spawn(['--invoice', '--path', valid.path]), valid.path);

  const repairable = temporaryMeter(t);
  const row = repairable.meter.record({ kind: 'tool-call', os: '4' });
  appendFileSync(repairable.path, '{"partial"');
  const repaired = spawn(['--repair', '--path', repairable.path]);
  assert.equal(repaired.status, 0);
  assert.deepEqual(JSON.parse(repaired.stdout), { rowCount: 1, meterHead: row.rowHash });
  assert.deepEqual(repairable.meter.read(), [row]);
});
