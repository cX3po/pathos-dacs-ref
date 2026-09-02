import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  demToOs,
  osToDem,
  settlePayDemCore,
  type DemosNativeClient,
  type DemosTransferResult,
} from '../../src/adapters/dacs/pay-dem.js';

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

test('legacy source is gone and gateway imports the adapter with no finality aliases in src', () => {
  const root = process.cwd();
  assert.equal(existsSync(join(root, 'src/live/pay-dem.ts')), false);
  const gateway = readFileSync(join(root, 'src/live/organ-gateway.mts'), 'utf8');
  assert.match(gateway, /import\('\.\.\/adapters\/dacs\/pay-dem\.js'\)/);

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
