import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { settlePayDemCore } from '../../src/adapters/dacs/pay-dem.js';
import { createDemosNativeClient, settlePayDem, type DemosSdkFunctions } from '../../src/adapters/dacs/pay-dem-demosdk.js';
import type { DemosHandle } from '../../src/demos/connection.js';
import {
  authorizeTransfer,
  loadPayPolicy,
  parsePayPolicy,
  spentTodayFromJournal,
  utcDateOrThrow,
  type PayPolicy,
} from '../../src/live/pay-policy.js';
import {
  acquirePayDemJournalLock,
  createPayDemOutcomeJournal,
  payKillSwitchPresent,
  readPayDemJournalOrEmpty,
} from '../../src/live/pay-dem-journal.js';
import { createPayDemAuthorizationGate } from '../../src/live/pay-dem-authorization.js';

const policyJson = {
  network: 'testnet',
  rpcHosts: ['demosnode.discus.sh'],
  perTransactionCapDem: '5',
  dailyCapDem: '25',
  killSwitchFile: '/tmp/PAY_KILL',
} as const;

const policy: PayPolicy = parsePayPolicy(policyJson);

test('parsePayPolicy accepts the exact policy shape', () => {
  assert.deepEqual(policy, policyJson);
});

test('parsePayPolicy rejects each invalid or missing field and unknown fields', () => {
  const { dailyCapDem, ...rest } = policyJson;
  const cases: Array<[string, unknown, RegExp]> = [
    ['object', null, /JSON object/],
    ['network', { ...policyJson, network: 'mainnet' }, /network.*testnet/],
    ['rpcHosts empty', { ...policyJson, rpcHosts: [] }, /rpcHosts.*non-empty/],
    ['rpcHosts member', { ...policyJson, rpcHosts: ['https://demosnode.discus.sh'] }, /hostname/],
    ['perTransactionCapDem', { ...policyJson, perTransactionCapDem: '5.0' }, /perTransactionCapDem.*canonical/],
    ['dailyCapDem', { ...policyJson, dailyCapDem: '0' }, /dailyCapDem.*canonical/],
    ['killSwitchFile', { ...policyJson, killSwitchFile: '' }, /killSwitchFile.*non-empty/],
    ['missing', rest, /missing required field: dailyCapDem/],
    ['unknown', { ...policyJson, permissive: true }, /unknown field.*permissive/],
  ];
  for (const [name, input, expected] of cases) {
    assert.throws(() => parsePayPolicy(input), expected, name);
  }
});

test('loadPayPolicy blocks when DACS_PAY_POLICY is absent and parses injected file text', () => {
  assert.deepEqual(loadPayPolicy({}, () => assert.fail('reader must not run')), {
    verdict: 'BLOCK',
    reason: 'no policy configured',
  });
  let pathRead = '';
  assert.deepEqual(loadPayPolicy({ DACS_PAY_POLICY: '/policy.json' }, (path) => {
    pathRead = path;
    return JSON.stringify(policyJson);
  }), policyJson);
  assert.equal(pathRead, '/policy.json');
});

const authorizationInput = {
  amountOs: 1_000_000_000n,
  rpcUrl: 'https://demosnode.discus.sh/',
  spentTodayOs: 0n,
  killSwitchPresent: false,
  nowIso: '2026-09-02T12:00:00.000Z',
};

function blockedRule(result: ReturnType<typeof authorizeTransfer>): string | undefined {
  return result.verdict === 'BLOCK' ? result.rule : undefined;
}

test('authorizeTransfer applies kill-switch, network, per-transaction, and daily rules in order', () => {
  assert.equal(blockedRule(authorizeTransfer(policy, {
    ...authorizationInput,
    killSwitchPresent: true,
    rpcUrl: 'https://wrong.example/',
    amountOs: 99_000_000_000n,
  })), 'kill-switch');
  assert.equal(blockedRule(authorizeTransfer(policy, {
    ...authorizationInput,
    rpcUrl: 'https://wrong.example/',
    amountOs: 99_000_000_000n,
  })), 'network');
  assert.equal(blockedRule(authorizeTransfer(policy, {
    ...authorizationInput,
    amountOs: 5_000_000_001n,
    spentTodayOs: 25_000_000_000n,
  })), 'per-transaction-cap');
  assert.equal(blockedRule(authorizeTransfer(policy, {
    ...authorizationInput,
    spentTodayOs: 24_000_000_001n,
  })), 'daily-cap');
});

test('authorizeTransfer permits equal cap boundaries and blocks one OS over', () => {
  assert.deepEqual(authorizeTransfer(policy, {
    ...authorizationInput,
    amountOs: 5_000_000_000n,
    spentTodayOs: 20_000_000_000n,
  }), { verdict: 'PROCEED', nowIso: authorizationInput.nowIso });
  assert.equal(authorizeTransfer(policy, {
    ...authorizationInput,
    amountOs: 5_000_000_001n,
  }).verdict, 'BLOCK');
  assert.equal(authorizeTransfer(policy, {
    ...authorizationInput,
    spentTodayOs: 24_000_000_001n,
  }).verdict, 'BLOCK');
});

test('spentTodayFromJournal counts same-UTC-day broadcast outcomes only', () => {
  const entries = [
    { timestamp: '2026-09-02T00:00:00.000Z', amountOs: '10', outcome: 'included' },
    { timestamp: '2026-09-02T23:59:59.999Z', amountOs: '20', outcome: 'failed' },
    { timestamp: '2026-09-01T23:59:59.999Z', amountOs: '40', outcome: 'included' },
    { timestamp: '2026-09-02T12:00:00.000Z', amountOs: '80', outcome: 'aborted-before-broadcast' },
    { timestamp: '2026-09-02T12:00:00.000Z', amountOs: '160', outcome: 'pre-broadcast-abort' },
    { timestamp: '2026-09-02T12:00:00.000Z', amountOs: '30', outcome: 'broadcast-attempted' },
    { txHash: 'legacy-preparation', amountOs: '160' },
  ];
  assert.equal(spentTodayFromJournal(entries, '2026-09-02T17:00:00-04:00'), 60n);
});

test('spentTodayFromJournal fails closed on malformed outcomes and timezone-less timestamps', () => {
  assert.throws(() => spentTodayFromJournal(
    [{ timestamp: '2026-09-02T00:00:00.000Z', amountOs: '10', outcome: '' }],
    '2026-09-02T12:00:00.000Z'), /non-empty string/);
  assert.throws(() => spentTodayFromJournal(
    [{ timestamp: '2026-09-02T23:30:00', amountOs: '10', outcome: 'included' }],
    '2026-09-02T12:00:00.000Z'), /timezone/);
  assert.throws(() => utcDateOrThrow('2026-09-02T12:00:00'), /timezone/);
  assert.throws(() => spentTodayFromJournal([], '2026-09-02T12:00:00'), /timezone/);
});

test('journal and kill-switch helpers rethrow EACCES instead of treating it as absent', () => {
  const denied = Object.assign(new Error('denied'), { code: 'EACCES' });
  assert.throws(() => readPayDemJournalOrEmpty('/journal', () => { throw denied; }), /denied/);
  assert.throws(() => payKillSwitchPresent('/kill', () => { throw denied; }), /denied/);
});

test('payment journal lock excludes a concurrent local authorization', () => {
  const directory = mkdtempSync(join(tmpdir(), 'pay-policy-lock-'));
  const path = join(directory, 'journal.jsonl');
  try {
    const first = acquirePayDemJournalLock(path);
    assert.throws(() => acquirePayDemJournalLock(path), /already held/);
    first.release();
    acquirePayDemJournalLock(path).release();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function testAuthorizationGate(overrides: Partial<Parameters<typeof createPayDemAuthorizationGate>[0]> = {}) {
  return createPayDemAuthorizationGate({
    policy,
    journalPath: '/outside-worktree/journal.jsonl',
    acquireLock: () => ({ release() {} }),
    readJournal: () => [],
    killSwitchPresent: () => false,
    resolveKillSwitchPath: (path) => path,
    durableOutcomeJournal: async () => {},
    nowIso: () => authorizationInput.nowIso,
    ...overrides,
  });
}

test('lock-held authorization returns the distinct journal-lock rule', async () => {
  const gate = testAuthorizationGate({
    acquireLock() { throw new Error('payment journal lock is already held'); },
  });
  const result = await gate.authorize({ amountOs: 1n, rpcUrl: authorizationInput.rpcUrl });
  assert.equal(result.verdict, 'BLOCK');
  if (result.verdict === 'BLOCK') {
    assert.equal(result.rule, 'journal-lock');
    assert.match(result.reason, /journal lock.*already held/i);
  }
});

test('a throwing release clears the in-process lease', async () => {
  let acquisitions = 0;
  const gate = testAuthorizationGate({
    acquireLock: () => {
      acquisitions += 1;
      return acquisitions === 1
        ? { release() { throw new Error('release failed'); } }
        : { release() {} };
    },
  });
  const first = await gate.authorize({ amountOs: 1n, rpcUrl: authorizationInput.rpcUrl });
  assert.equal(first.verdict, 'PROCEED');
  await assert.rejects(gate.journalOutcome({
    timestamp: authorizationInput.nowIso,
    amountOs: '1',
    outcome: 'broadcast-attempted',
  }), /release failed/);
  const second = await gate.authorize({ amountOs: 1n, rpcUrl: authorizationInput.rpcUrl });
  assert.equal(second.verdict, 'PROCEED');
  assert.equal(acquisitions, 2);
});

test('outcome journal rejects a timezone-less timestamp', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'pay-policy-outcome-'));
  try {
    const journal = createPayDemOutcomeJournal(join(directory, 'journal.jsonl'));
    await assert.rejects(journal({
      timestamp: '2026-09-02T12:00:00', amountOs: '1', outcome: 'broadcast-attempted',
    }), /timezone/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

const coreParams = {
  recipient: 'payee',
  amountDemCanonical: '1',
  amountOs: 1_000_000_000n,
  currency: 'DEM',
  jobId: 'policy-job',
  phaseIndex: 3,
  network: 'demos-testnet',
  rpcUrl: 'https://demosnode.discus.sh/',
};

test('core BLOCK returns abort recovery context before journaling or transfer', async () => {
  const calls: string[] = [];
  const result = await settlePayDemCore(coreParams, {
    address: 'payer',
    async transfer() {
      calls.push('transfer');
      return { ok: true, hash: 'never', state: 'included', blockNumber: 1 };
    },
  }, {
    async authorizeTransfer(ctx) {
      calls.push(`authorize:${ctx.amountOs}:${ctx.rpcUrl}`);
      return { verdict: 'BLOCK', rule: 'daily-cap', reason: 'daily cap reached' };
    },
    async journalPreparedTransfer() { calls.push('journal'); },
  });
  assert.deepEqual(calls, ['authorize:1000000000:https://demosnode.discus.sh/']);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.deepEqual(result.recovery?.abort, { rule: 'daily-cap', reason: 'daily cap reached' });
});

test('settlePayDem BLOCK invokes neither SDK pay nor sign', async () => {
  const calls: string[] = [];
  const sdk: DemosSdkFunctions = {
    async pay() { calls.push('pay'); return {}; },
    async sign() { calls.push('sign'); return {}; },
    async confirm() { calls.push('confirm'); return {}; },
    async broadcastAndWait() { calls.push('broadcast'); return {}; },
  };
  const handle = { address: 'payer', rpc: 'https://demosnode.discus.sh/', demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const result = await settlePayDem({
    buyer: handle,
    sellerAddress: 'payee',
    amountDemCanonical: '1',
    jobId: 'policy-job',
    phaseIndex: 3,
    sdk,
    async authorizeTransfer() { return { verdict: 'BLOCK', rule: 'kill-switch', reason: 'stopped' }; },
  });
  assert.equal(result.ok, false);
  assert.deepEqual(calls, []);
});

test('core without authorization hook fails closed before journaling or transfer', async () => {
  const calls: string[] = [];
  const result = await settlePayDemCore(coreParams, {
    address: 'payer',
    async transfer() {
      calls.push('transfer');
      return { ok: true, hash: 'hash', state: 'included', blockNumber: 1 };
    },
  }, {
    async journalPreparedTransfer() { calls.push('journal'); },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.reason, 'payment policy authorization is unavailable');
  assert.deepEqual(result.recovery?.abort, {
    rule: 'network',
    reason: 'payment policy authorization is unavailable',
  });
  assert.deepEqual(calls, []);
});

test('non-PROCEED authorization result invokes neither SDK pay nor sign', async () => {
  const calls: string[] = [];
  const handle = { address: 'payer', rpc: 'https://demosnode.discus.sh/', demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const result = await settlePayDem({
    buyer: handle,
    sellerAddress: 'payee',
    amountDemCanonical: '1',
    jobId: 'policy-job',
    phaseIndex: 3,
    sdk: {
      async pay() { calls.push('pay'); return {}; },
      async sign() { calls.push('sign'); return {}; },
      async confirm() { calls.push('confirm'); return {}; },
      async broadcastAndWait() { calls.push('broadcast'); return {}; },
    },
    async authorizeTransfer() { return { verdict: 'ALLOW' } as never; },
  });
  assert.equal(result.ok, false);
  assert.deepEqual(calls, []);
});

test('PROCEED without nowIso is refused before SDK pay or sign', async () => {
  const calls: string[] = [];
  const handle = { address: 'payer', rpc: authorizationInput.rpcUrl, demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const result = await settlePayDem({
    buyer: handle,
    sellerAddress: 'payee',
    amountDemCanonical: '1',
    jobId: 'missing-authorization-clock',
    phaseIndex: 3,
    sdk: {
      async pay() { calls.push('pay'); return {}; },
      async sign() { calls.push('sign'); return {}; },
      async confirm() { calls.push('confirm'); return {}; },
      async broadcastAndWait() { calls.push('broadcast'); return {}; },
    },
    async authorizeTransfer() { return { verdict: 'PROCEED' } as never; },
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'payment policy authorization is unavailable');
  assert.deepEqual(calls, []);
});

test('UTC day change after authorization blocks before broadcast', async () => {
  const calls: string[] = [];
  const authorizationNowIso = new Date(Date.now() - 86_400_000).toISOString();
  const handle = { address: 'payer', rpc: authorizationInput.rpcUrl, demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const result = await settlePayDem({
    buyer: handle,
    sellerAddress: 'payee',
    amountDemCanonical: '1',
    jobId: 'expired-authorization-clock',
    phaseIndex: 3,
    sdk: {
      async pay() { calls.push('pay'); return {}; },
      async sign() { calls.push('sign'); return { hash: 'h', content: { nonce: 1 } }; },
      async confirm() { calls.push('confirm'); return {}; },
      async broadcastAndWait() { calls.push('broadcast'); return {}; },
    },
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: authorizationNowIso }; },
    async journalTransferOutcome(outcome) { calls.push(`journal:${outcome.outcome}`); },
  });
  assert.equal(result.ok, false);
  assert.deepEqual(calls, ['pay', 'sign', 'confirm', 'journal:aborted-before-broadcast']);
});

test('abort journaling releases the lease when authorization timestamp validation throws', async () => {
  let released = false;
  const outcomes: string[] = [];
  const gate = testAuthorizationGate({
    acquireLock: () => ({ release() { released = true; } }),
    durableOutcomeJournal: async (outcome) => { outcomes.push('outcome' in outcome ? outcome.outcome : outcome.resolution); },
  });
  const authorization = await gate.authorize({ amountOs: 1n, rpcUrl: authorizationInput.rpcUrl });
  assert.equal(authorization.verdict, 'PROCEED');
  const handle = { address: 'payer', rpc: authorizationInput.rpcUrl, demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const result = await createDemosNativeClient(handle, {
    sdk: {
      async pay() { assert.fail('pay must not run'); },
      async sign() { assert.fail('sign must not run'); },
      async confirm() { assert.fail('confirm must not run'); },
      async broadcastAndWait() { assert.fail('broadcast must not run'); },
    },
    journalTransferOutcome: gate.journalOutcome,
  }).transfer({ to: 'payee', amountOs: 1n, authorizationNowIso: 'invalid' });
  assert.equal(result.ok, false);
  assert.equal(released, true);
  assert.deepEqual(outcomes, ['aborted-before-broadcast']);
});

test('broadcast-attempted is journaled before broadcast and a rejected count prevents send', async () => {
  const handle = { address: 'payer', rpc: 'https://demosnode.discus.sh/', demos: {} as DemosHandle['demos'] } satisfies DemosHandle;
  const makeSdk = (calls: string[]): DemosSdkFunctions => ({
    async pay() { calls.push('pay'); return {}; },
    async sign() { calls.push('sign'); return { hash: 'h', content: { nonce: 1 } }; },
    async confirm() { calls.push('confirm'); return {}; },
    async broadcastAndWait() { calls.push('broadcast'); return { status: { state: 'included', blockNumber: 1 } }; },
  });

  const successfulCalls: string[] = [];
  const successful = await settlePayDem({
    buyer: handle, sellerAddress: 'payee', amountDemCanonical: '1', jobId: 'j1', phaseIndex: 3,
    sdk: makeSdk(successfulCalls),
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: new Date().toISOString() }; },
    async journalTransferOutcome(outcome) { successfulCalls.push(`journal:${outcome.outcome}`); },
  });
  assert.equal(successful.ok, true);
  assert.deepEqual(successfulCalls, ['pay', 'sign', 'confirm', 'journal:broadcast-attempted', 'broadcast']);

  const rejectedCalls: string[] = [];
  const rejected = await settlePayDem({
    buyer: handle, sellerAddress: 'payee', amountDemCanonical: '1', jobId: 'j2', phaseIndex: 3,
    sdk: makeSdk(rejectedCalls),
    async authorizeTransfer() { return { verdict: 'PROCEED', nowIso: new Date().toISOString() }; },
    async journalTransferOutcome(outcome) {
      rejectedCalls.push(`journal:${outcome.outcome}`);
      if (outcome.outcome === 'broadcast-attempted') throw new Error('disk full');
    },
  });
  assert.equal(rejected.ok, false);
  assert.deepEqual(rejectedCalls, ['pay', 'sign', 'confirm', 'journal:broadcast-attempted', 'journal:aborted-before-broadcast']);
});

test('live gateway preflight blocks before connection when DACS_PAY_POLICY is absent', () => {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, LIVE: '1', DACS_PAY_POLICY: '' };
  delete childEnv.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/organ-gateway.mts'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: childEnv,
  });
  assert.equal(run.status, 2, run.stderr);
  assert.match(readFileSync('src/live/organ-gateway.mts', 'utf8'), /exitPayPolicyBlocked\(loadedPayPolicy\.reason\)/);
  assert.doesNotMatch(`${run.stdout}${run.stderr}`, /DEMOS_MNEMONIC/);
});

function runLiveWithPolicy(overrides: Partial<PayPolicy>, journalPath: string) {
  const directory = mkdtempSync(join(tmpdir(), 'pay-policy-test-'));
  const policyPath = join(directory, 'policy.json');
  writeFileSync(policyPath, JSON.stringify({ ...policyJson, ...overrides }));
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    LIVE: '1',
    DEMOS_RPC: 'https://demosnode.discus.sh/',
    DACS_PAY_POLICY: policyPath,
    DACS_PAYDEM_JOURNAL: journalPath,
  };
  delete childEnv.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/organ-gateway.mts'], {
    cwd: process.cwd(), encoding: 'utf8', env: childEnv,
  });
  rmSync(directory, { recursive: true, force: true });
  return run;
}

test('disallowed DEMOS_RPC exits 2 before connectLive', () => {
  const journalPath = join(tmpdir(), `pay-policy-${process.pid}-rpc.jsonl`);
  const directory = mkdtempSync(join(tmpdir(), 'pay-policy-rpc-'));
  const policyPath = join(directory, 'policy.json');
  writeFileSync(policyPath, JSON.stringify(policyJson));
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    LIVE: '1',
    DEMOS_RPC: 'https://disallowed.example/',
    DACS_PAY_POLICY: policyPath,
    DACS_PAYDEM_JOURNAL: journalPath,
  };
  delete childEnv.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/organ-gateway.mts'], {
    cwd: process.cwd(), encoding: 'utf8', env: childEnv,
  });
  rmSync(directory, { recursive: true, force: true });
  assert.equal(run.status, 2, run.stderr);
  assert.match(run.stderr, /RPC host.*not allowed/);
  assert.doesNotMatch(`${run.stdout}${run.stderr}`, /DEMOS_MNEMONIC/);
});

test('journal EACCES and kill-switch EACCES block during pre-connect policy evaluation', () => {
  const journalDenied = runLiveWithPolicy({}, '/proc/1/mem');
  assert.equal(journalDenied.status, 2, journalDenied.stderr);
  assert.match(journalDenied.stderr, /EACCES|permission denied/i);

  const journalPath = join(tmpdir(), `pay-policy-${process.pid}-kill.jsonl`);
  const killDenied = runLiveWithPolicy({ killSwitchFile: '/root/no-such-dir/PAY_KILL' }, journalPath);
  assert.equal(killDenied.status, 2, killDenied.stderr);
  assert.match(killDenied.stderr, /EACCES|permission denied/i);
});

test('a kill switch that appears after authorization blocks the pre-broadcast path and releases the lease', async () => {
  let killSwitch = false;
  let released = 0;
  const written: string[] = [];
  const gate = testAuthorizationGate({
    acquireLock: () => ({ release() { released += 1; } }),
    killSwitchPresent: () => killSwitch,
    durableOutcomeJournal: async (outcome) => { written.push('outcome' in outcome ? outcome.outcome : outcome.resolution); },
  });
  const authorization = await gate.authorize({ amountOs: 1n, rpcUrl: authorizationInput.rpcUrl });
  assert.equal(authorization.verdict, 'PROCEED');
  if (authorization.verdict !== 'PROCEED') return;
  killSwitch = true;
  await assert.rejects(
    gate.journalOutcome({ timestamp: authorization.nowIso, amountOs: '1', outcome: 'broadcast-attempted' }),
    /kill switch is present/,
  );
  assert.deepEqual(written, []);
  assert.equal(released, 1);
  await assert.rejects(gate.beforeBroadcast({ authorizationNowIso: authorization.nowIso }), /kill switch is present/);
});
