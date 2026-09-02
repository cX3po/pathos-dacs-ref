import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  BroadcastFailedError,
  BroadcastTimeoutError,
} from '@kynesyslabs/demosdk/websdk';

import {
  demToOs,
  osToDem,
  settlePayDemCore,
  type DemosNativeClient,
  type DemosTransferResult,
} from '../../src/adapters/dacs/pay-dem.js';
import {
  createDemosNativeClient,
  parseBroadcastWaitResult,
  settlePayDem,
  type DemosSdkFunctions,
} from '../../src/adapters/dacs/pay-dem-demosdk.js';
import type { DemosHandle } from '../../src/demos/connection.js';
import {
  createPayDemJsonlJournal,
  resolvePayDemJournalPath,
} from '../../src/live/pay-dem-journal.js';

const PAYER = 'payer-address';
const PAYEE = 'payee-address';

function clientWith(result: DemosTransferResult): DemosNativeClient {
  return {
    address: PAYER,
    async transfer() {
      return result;
    },
  };
}

function params(overrides: Partial<Parameters<typeof settlePayDemCore>[0]> = {}) {
  return {
    recipient: PAYEE,
    amountDemCanonical: '1.25',
    currency: 'DEM',
    jobId: 'job-1',
    phaseIndex: 3,
    network: 'demos-devnet',
    ...overrides,
  };
}

test('demToOs and osToDem round-trip canonical DEM amounts', () => {
  for (const amount of ['0.000000001', '0.1', '1', '1.25', '9007199.123456789']) {
    assert.equal(osToDem(demToOs(amount)), amount);
  }
});

test('demToOs rejects ten fractional digits', () => {
  assert.throws(() => demToOs('1.1234567890'), /fractional digits/);
});

test('demToOs rejects zero', () => {
  assert.throws(() => demToOs('0'), /invalid canonical|greater than zero/);
});

test('demToOs rejects a negative amount', () => {
  assert.throws(() => demToOs('-1'), /invalid canonical/);
});

test('demToOs rejects non-numeric text', () => {
  assert.throws(() => demToOs('abc'), /invalid canonical/);
});

test('demToOs rejects non-canonical decimal spellings', () => {
  for (const amount of ['1.', '.5', '1e9', '01', '1.0']) {
    assert.throws(() => demToOs(amount), /invalid canonical/, amount);
  }
});

test('broadcast parser accepts only included status and its numeric block witness', () => {
  assert.deepEqual(
    parseBroadcastWaitResult({ status: { state: 'included', blockNumber: 42 } }, 'signed-hash'),
    { ok: true, hash: 'signed-hash', state: 'included', blockNumber: 42 },
  );
  const missingStatus = parseBroadcastWaitResult({}, 'signed-hash');
  assert.equal(missingStatus.ok, false);
  assert.equal(missingStatus.state, undefined);
  const missingState = parseBroadcastWaitResult({ status: { blockNumber: 42 } }, 'signed-hash');
  assert.equal(missingState.ok, false);
  assert.equal(missingState.state, undefined);
  const failed = parseBroadcastWaitResult({ status: { state: 'failed', blockNumber: 1 } }, 'signed-hash');
  assert.equal(failed.ok, false);
  assert.equal(failed.state, 'failed');
});

test('broadcast parser ignores block numbers outside status and non-number status values', () => {
  const misleading = {
    blockNumber: 99,
    broadcast: { data: { blockNumber: 98 }, response: { blockNumber: 97 } },
    status: { state: 'included', blockNumber: '42' },
  };
  const parsed = parseBroadcastWaitResult(misleading, 'signed-hash');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.blockNumber, undefined);
});

test('broadcast parser preserves signed-hash identity and rejects a payload mismatch', () => {
  const result = parseBroadcastWaitResult({
    broadcast: { response: { hash: 'different-hash' } },
    status: { state: 'included', blockNumber: 42 },
  }, 'signed-hash');
  assert.deepEqual(result, {
    ok: false,
    hash: 'signed-hash',
    message: 'pay-dem broadcast hash mismatch',
  });
});

const stubHandle = {
  address: PAYER,
  demos: {} as DemosHandle['demos'],
  rpc: 'stub://no-network',
} satisfies DemosHandle;

function sdkWith(overrides: Partial<DemosSdkFunctions> = {}): DemosSdkFunctions {
  return {
    async pay() { return { unsigned: true }; },
    async sign() { return { hash: 'signed-hash', content: { nonce: 7 } }; },
    async confirm() { return { validity: true }; },
    async broadcastAndWait() { return { status: { state: 'included', blockNumber: 42 } }; },
    ...overrides,
  };
}

test('demosdk wiring journals signed identity before confirmation and broadcast', async () => {
  const calls: string[] = [];
  const sdk = sdkWith({
    async pay() { calls.push('pay'); return {}; },
    async sign() { calls.push('sign'); return { hash: 'signed-hash', content: { nonce: 7 } }; },
    async confirm() { calls.push('confirm'); return {}; },
    async broadcastAndWait() {
      calls.push('broadcastAndWait');
      return { status: { state: 'included', blockNumber: 42 } };
    },
  });
  const client = createDemosNativeClient(stubHandle, {
    sdk,
    async journalPreparedTransfer(prepared) {
      calls.push(`journal:${prepared.txHash}:${prepared.nonce}`);
    },
  });
  const result = await client.transfer({ to: PAYEE, amountOs: 5n });
  assert.deepEqual(calls, ['pay', 'sign', 'journal:signed-hash:7', 'confirm', 'broadcastAndWait']);
  assert.deepEqual(result, { ok: true, hash: 'signed-hash', state: 'included', blockNumber: 42 });
});

test('settlePayDem journals one signed preparation carrying core recovery context', async () => {
  const records: unknown[] = [];
  const result = await settlePayDem({
    buyer: stubHandle,
    sellerAddress: PAYEE,
    amountDemCanonical: '1.25',
    amountOs: 1_250_000_000n,
    jobId: 'job-1',
    phaseIndex: 3,
    network: 'demos-devnet',
    sdk: sdkWith(),
    async journal(prepared) { records.push(prepared); },
  });
  assert.equal(result.ok, true);
  assert.equal(records.length, 1);
  assert.deepEqual(records[0], {
    txHash: 'signed-hash',
    nonce: 7,
    payer: PAYER,
    payee: PAYEE,
    amountOs: '1250000000',
    network: 'demos-devnet',
    recovery: {
      railId: 'pay-dem',
      jobId: 'job-1',
      phaseIndex: 3,
      settlementKey: 'pay-dem:job-1:3',
      network: 'demos-devnet',
      payer: PAYER,
      payee: PAYEE,
      amountOs: '1250000000',
    },
  });
});

test('demosdk wiring converts pay, sign, confirm, and broadcast failures to closed results', async (t) => {
  const failures: Array<{ name: string; override: Partial<DemosSdkFunctions>; expectedHash: string }> = [
    { name: 'pay', override: { async pay() { throw new Error('pay failed'); } }, expectedHash: '' },
    { name: 'sign', override: { async sign() { throw new Error('sign failed'); } }, expectedHash: '' },
    { name: 'confirm', override: { async confirm() { throw new Error('confirm failed'); } }, expectedHash: 'signed-hash' },
    {
      name: 'broadcast',
      override: {
        async broadcastAndWait() {
          throw new BroadcastFailedError({ txHash: 'signed-hash', cause: new Error('offline') });
        },
      },
      expectedHash: 'signed-hash',
    },
  ];
  for (const failure of failures) {
    await t.test(failure.name, async () => {
      const result = await createDemosNativeClient(stubHandle, { sdk: sdkWith(failure.override) })
        .transfer({ to: PAYEE, amountOs: 1n });
      assert.equal(result.ok, false);
      assert.equal(result.hash, failure.expectedHash);
      assert.equal(result.state, undefined);
    });
  }
});

test('a broadcast timeout remains failed while retaining signed hash and last-seen state', async () => {
  const sdk = sdkWith({
    async broadcastAndWait() {
      throw new BroadcastTimeoutError({
        txHash: 'signed-hash',
        lastSeenState: 'pending',
        elapsedMs: 1,
      });
    },
  });
  const result = await createDemosNativeClient(stubHandle, { sdk })
    .transfer({ to: PAYEE, amountOs: 1n });
  assert.equal(result.ok, false);
  assert.equal(result.hash, 'signed-hash');
  assert.equal(result.state, 'pending');
  assert.match(result.message ?? '', /timed out/i);
});

test('core rejects a currency other than DEM before transfer', async () => {
  let called = false;
  const client: DemosNativeClient = {
    address: PAYER,
    async transfer() { called = true; return { ok: true, hash: 'h', state: 'included', blockNumber: 1 }; },
  };
  await assert.rejects(settlePayDemCore(params({ currency: 'USD' }), client), /unsupported currency/);
  assert.equal(called, false);
});

test('exact included state with block witness returns success evidence', async () => {
  const outcome = await settlePayDemCore(
    params(),
    clientWith({ ok: true, hash: 'hash-123', state: 'included', blockNumber: 42 }),
  );
  assert.equal(outcome.ok, true);
  if (!outcome.ok) return;
  assert.equal(outcome.txHash, 'hash-123');
  assert.equal(outcome.blockNumber, 42);
  assert.deepEqual(outcome.finality, { model: 'bft-final' });
  assert.equal(outcome.evidence.paymentAmount.amount, '1.25');
  assert.equal(outcome.evidence.paymentAmount.currency, 'DEM');
  assert.equal(outcome.evidence.paymentTxRefs[0]?.txHash, 'demos:hash-123');
});

test('alternate pre-inclusion state fails without evidence', async () => {
  const outcome = await settlePayDemCore(
    params(),
    clientWith({ ok: true, hash: 'h', state: ['con', 'firmed'].join(''), blockNumber: 7 }),
  );
  assert.deepEqual(outcome, { ok: false, reason: 'pay-dem did not observe included state (state=confirmed)' });
  assert.equal('evidence' in outcome, false);
});

test('alternate post-inclusion alias fails without evidence', async () => {
  const outcome = await settlePayDemCore(
    params(),
    clientWith({ ok: true, hash: 'h', state: ['final', 'ized'].join(''), blockNumber: 7 }),
  );
  assert.equal(outcome.ok, false);
  assert.equal('evidence' in outcome, false);
});

test('missing state fails without evidence', async () => {
  const outcome = await settlePayDemCore(params(), clientWith({ ok: true, hash: 'h', blockNumber: 7 }));
  assert.equal(outcome.ok, false);
  assert.equal('evidence' in outcome, false);
});

test('missing block number fails without evidence', async () => {
  const outcome = await settlePayDemCore(params(), clientWith({ ok: true, hash: 'h', state: 'included' }));
  assert.equal(outcome.ok, false);
  assert.equal('evidence' in outcome, false);
});

test('client failure returns failure without evidence', async () => {
  const outcome = await settlePayDemCore(
    params(),
    clientWith({ ok: false, hash: '', message: 'rejected' }),
  );
  assert.deepEqual(outcome, { ok: false, reason: 'rejected' });
  assert.equal('evidence' in outcome, false);
});

test('recovery context is journaled exactly before transfer', async () => {
  const calls: string[] = [];
  let transferredRecovery: unknown;
  const client: DemosNativeClient = {
    address: PAYER,
    async transfer(input) {
      calls.push('transfer');
      transferredRecovery = input.recovery;
      return { ok: true, hash: 'h', state: 'included', blockNumber: 8 };
    },
  };
  let journaled: unknown;
  const outcome = await settlePayDemCore(params(), client, {
    async journalPreparedTransfer(prepared) {
      calls.push('journal');
      journaled = prepared;
    },
  });
  const expected = {
    railId: 'pay-dem',
    jobId: 'job-1',
    phaseIndex: 3,
    settlementKey: 'pay-dem:job-1:3',
    network: 'demos-devnet',
    payer: PAYER,
    payee: PAYEE,
    amountOs: '1250000000',
  };
  assert.equal(outcome.ok, true);
  assert.deepEqual(calls, ['journal', 'transfer']);
  assert.deepEqual(journaled, expected);
  assert.deepEqual(transferredRecovery, expected);
  assert.equal(Object.isFrozen(journaled), true);
});

test('mutable params cannot change recipient or amount after settlement starts', async () => {
  let releaseJournal!: () => void;
  const journalGate = new Promise<void>((resolve) => { releaseJournal = resolve; });
  const mutable = params();
  let received: { to: string; amountOs: bigint; recovery?: unknown } | undefined;
  const client: DemosNativeClient = {
    address: PAYER,
    async transfer(input) {
      received = input;
      return { ok: true, hash: 'h', state: 'included', blockNumber: 9 };
    },
  };
  const pending = settlePayDemCore(mutable, client, {
    async journalPreparedTransfer() { await journalGate; },
  });
  mutable.recipient = 'mutated-payee';
  mutable.amountDemCanonical = '99';
  releaseJournal();
  const outcome = await pending;
  assert.equal(outcome.ok, true);
  assert.equal(received?.to, PAYEE);
  assert.equal(received?.amountOs, 1_250_000_000n);
  if (outcome.ok) assert.equal(outcome.evidence.paymentAmount.amount, '1.25');
});

test('evidence amount and currency exactly describe the moved OS', async () => {
  const outcome = await settlePayDemCore(
    params({ amountDemCanonical: '12.345678901', amountOs: 12_345_678_901n }),
    clientWith({ ok: true, hash: 'h', state: 'included', blockNumber: 10 }),
  );
  assert.equal(outcome.ok, true);
  if (!outcome.ok) return;
  assert.equal(outcome.evidence.paymentAmount.amount, osToDem(outcome.amountOs));
  assert.equal(outcome.evidence.paymentAmount.currency, 'DEM');
});

test('JSONL journal appends exactly one line per signed preparation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'pay-dem-journal-test-'));
  const path = join(directory, 'prepared.jsonl');
  try {
    const journal = createPayDemJsonlJournal(path);
    const prepared = {
      txHash: 'signed-hash',
      nonce: 7,
      payer: PAYER,
      payee: PAYEE,
      amountOs: '5',
      network: 'demos-devnet',
    };
    await journal(prepared);
    await journal({ ...prepared, txHash: 'signed-hash-2', nonce: 8 });
    const lines = (await readFile(path, 'utf8')).trimEnd().split('\n');
    assert.equal(lines.length, 2);
    assert.deepEqual(lines.map((line) => JSON.parse(line)), [
      prepared,
      { ...prepared, txHash: 'signed-hash-2', nonce: 8 },
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('JSONL journal refuses a path inside the checkout', () => {
  assert.throws(
    () => resolvePayDemJournalPath(join(process.cwd(), 'pay-dem-journal.jsonl')),
    /outside a Git working tree/,
  );
});

test('pure core has no demosdk import and gateway uses demosdk wiring with a journal', () => {
  const root = process.cwd();
  assert.equal(existsSync(join(root, 'src/live/pay-dem.ts')), false);
  const gateway = readFileSync(join(root, 'src/live/organ-gateway.mts'), 'utf8');
  assert.match(gateway, /import\('\.\.\/adapters\/dacs\/pay-dem-demosdk\.js'\)/);
  assert.match(gateway, /journal:\s*createPayDemJsonlJournal/);
  const core = readFileSync(join(root, 'src/adapters/dacs/pay-dem.ts'), 'utf8');
  assert.doesNotMatch(core, /@kynesyslabs\/demosdk/);

  const sourceFiles = (directory: string): string[] => readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => entry.isDirectory()
      ? sourceFiles(join(directory, entry.name))
      : /\.[cm]?ts$/.test(entry.name) ? [join(directory, entry.name)] : []);
  const aliases = `${['con', 'firmed'].join('')}|${['final', 'ized'].join('')}`;
  const aliasStateCheck = new RegExp(
    `(?:state|status)[^\\n]{0,80}\\b(?:${aliases})\\b|\\b(?:${aliases})\\b[^\\n]{0,80}(?:state|status)`,
    'i',
  );
  const offenders = sourceFiles(join(root, 'src')).flatMap((file) =>
    readFileSync(file, 'utf8').split('\n')
      .map((line, index) => ({ file, line: index + 1, text: line }))
      .filter(({ text }) => !/^\s*(?:\/\/|\/\*|\*)/.test(text) && aliasStateCheck.test(text)));
  assert.deepEqual(offenders, []);
});
