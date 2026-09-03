import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

test('read detects an edited line', (t) => {
  const { path, meter } = temporaryMeter(t);
  meter.record({ kind: 'seat-call', os: '7' });
  const text = readFileSync(path, 'utf8').replace('"os":"7"', '"os":"8"');
  writeFileSync(path, text);
  assert.throws(() => meter.read(), /chain is broken/);
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
  assert.deepEqual(invoice.receiptRefs, [RECEIPT]);
  const { contentHash, ...unsigned } = invoice;
  assert.equal(contentHash, jcsHashHex(unsigned));
  assert.deepEqual(meter.invoice(opts), invoice);
});

async function proofHarness(meter?: { record(entry: MeterEntry): MeterRow }) {
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
  const fake = { record(entry: MeterEntry) { recorded.push(entry); return {} as MeterRow; } };
  await (await proofHarness(fake)).append(proofEntry);
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0]?.kind, 'anchor');
  assert.match(String(recorded[0]?.os), /^\d+$/);
  assert.match(String(recorded[0]?.ref), /^stor-/);
  await (await proofHarness()).append(proofEntry);
  assert.equal(recorded.length, 1);
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
  assert.deepEqual(recorded, [{ kind: 'transfer', os: '1250000000', ref: 'tx-hash' }]);
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
