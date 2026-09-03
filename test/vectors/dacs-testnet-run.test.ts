import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createLiveAdapterWiring,
  createLiveDependencies,
  createLiveSettlementDependency,
  createNodeReceiptProvider,
  DacsTestnetRefusal,
  main,
  parameterHash,
  rollupColdVerifications,
  runDacsTestnetSession,
  type ColdVerdict,
  type CoreReceiptProvider,
  type DacsTestnetConfig,
  type DacsTestnetDependencies,
  type LiveSettlementSeams,
} from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';
import type { AnchorReceipt } from '../../src/types/bundle.js';

const config: DacsTestnetConfig = { jobId: 'unit-job', mode: 'dry-run', organ: 'nws_alerts', query: 'fixture-query', priceDem: '1', spendCapDem: 50, rpc: 'https://example.invalid' };
test('orchestration executes in exact fail-closed order', async () => {
  const calls: string[] = [];
  const deps = createDryRunDependencies(config);
  const names: Array<[keyof DacsTestnetDependencies, string]> = [
    ['capabilityPreflight', 'preflight'], ['publishListing', 'listing'], ['vetListing', 'vet'], ['emitAgreement', 'agreement'],
    ['verifyAgreement', 'agreement-cold'], ['settlePayment', 'payment'], ['deliver', 'delivery'], ['finalize', 'finalization'], ['verifyBundle', 'bundle-cold'],
  ];
  for (const [method, name] of names) {
    const original = (deps as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>)[method]!.bind(deps);
    (deps as unknown as Record<string, unknown>)[method] = async (...args: unknown[]) => { calls.push(name); return original(...args); };
  }
  const result = await runDacsTestnetSession(config, deps);
  assert.deepEqual(calls, ['preflight', 'listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold']);
  assert.equal(result.rollup, 'PASS');
  assert.deepEqual(result.phases.map(({ index, kind }) => [index, kind]), [[0, 'negotiate-fixed-price'], [1, 'commit-agreement'], [2, 'pay-dem'], [3, 'deliver-storage-program']]);
});

test('every failing stage stops all subsequent work', async () => {
  const stages = ['preflight', 'listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold'] as const;
  const full = ['preflight', 'listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold'];
  for (const stage of stages) {
    const variants = stage === 'vet' || stage === 'agreement-cold' || stage === 'bundle-cold' ? ['throw', 'fail', 'indeterminate'] as const : ['throw'] as const;
    for (const variant of variants) {
      const calls: string[] = [];
      const deps = createDryRunDependencies(config);
      const method = ({ preflight: 'capabilityPreflight', listing: 'publishListing', vet: 'vetListing', agreement: 'emitAgreement',
        'agreement-cold': 'verifyAgreement', payment: 'settlePayment', delivery: 'deliver', finalization: 'finalize', 'bundle-cold': 'verifyBundle' } as const)[stage];
      for (const [candidate, name] of Object.entries({ capabilityPreflight: 'preflight', publishListing: 'listing', vetListing: 'vet', emitAgreement: 'agreement',
        verifyAgreement: 'agreement-cold', settlePayment: 'payment', deliver: 'delivery', finalize: 'finalization', verifyBundle: 'bundle-cold' })) {
        const original = (deps as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>)[candidate]!.bind(deps);
        (deps as unknown as Record<string, unknown>)[candidate] = async (...args: unknown[]) => { calls.push(name); return original(...args); };
      }
      (deps as unknown as Record<string, unknown>)[method] = async () => {
        calls.push(stage);
        if (variant !== 'throw') return { outcome: variant, detail: 'sentinel verdict' };
        throw new Error('dependency sentinel');
      };
      const result = await runDacsTestnetSession(config, deps);
      assert.deepEqual(calls, full.slice(0, full.indexOf(stage) + 1), `${stage}/${variant}`);
      assert.notEqual(result.rollup, 'PASS', `${stage}/${variant}`);
    }
  }
});

test('cold-verifier rollup covers every fail/indeterminate combination', () => {
  const outcomes = ['pass', 'fail', 'indeterminate'] as const;
  for (const a of outcomes) for (const b of outcomes) {
    const actual = rollupColdVerifications({ outcome: a, detail: a }, { outcome: b, detail: b });
    const expected = a === 'fail' || b === 'fail' ? 'FAIL' : a === 'indeterminate' || b === 'indeterminate' ? 'INDETERMINATE' : 'PASS';
    assert.equal(actual, expected, `${a}/${b}`);
  }
});

test('result JSON and error handling do not expose secret or environment values', async () => {
  const sentinel = 'twelve-secret-words-never-appear';
  const secretConfig = { ...config, query: sentinel, rpc: sentinel };
  const deps = createDryRunDependencies(secretConfig);
  deps.publishListing = async () => { throw new Error(sentinel); };
  const result = await runDacsTestnetSession(secretConfig, deps);
  const encoded = JSON.stringify(result);
  assert.doesNotMatch(encoded, /mnemonic|private.?key|fixture.?seed/i);
  assert.ok(!encoded.includes(sentinel));
});

test('LIVE receipt capability is checked before any environment read', async () => {
  const run = { ...config, mode: 'live' as const };
  for (const provider of [
    { describe: () => ({ kind: 'core-5.1-receipts' as const, provesFinality: false, source: 'liar' }), async fetch() {
      return { state: 'finalized' } as AnchorReceipt;
    } },
    { describe() { throw new Error('describe failed'); }, async fetch() { return { outcome: 'indeterminate' as const, detail: 'unused' }; } },
  ]) {
    let reads = 0;
    const env = new Proxy({}, { get() { reads++; return undefined; } }) as NodeJS.ProcessEnv;
    await assert.rejects(createLiveAdapterWiring(run, env, provider),
      (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'capability');
    assert.equal(reads, 0);
  }
});

test('createLiveDependencies refuses the repository node observer as a capability', async () => {
  const run = { ...config, mode: 'live' as const };
  const env = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(run) };
  await assert.rejects(createLiveDependencies(run, env, createNodeReceiptProvider(run), {
    loadPolicy: async () => ({ network: 'testnet', rpcHosts: ['example.invalid'], perTransactionCapDem: '10', dailyCapDem: '20', killSwitchFile: '/tmp/no-kill' }),
    resolveJournalPath: async () => '/tmp/dacs-node-observer-test.jsonl',
  }), (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'capability');
});

test('createLiveSettlementDependency preserves the gateway pay-dem call order', async () => {
  const run = { ...config, mode: 'live' as const };
  const calls: string[] = [];
  const envTarget: NodeJS.ProcessEnv = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(run) };
  const env = new Proxy(envTarget, { get(target, key, receiver) { if (typeof key === 'string' && key.startsWith('GATEWAY_')) calls.push(`env:${key}`); return Reflect.get(target, key, receiver); } });
  const handle = { address: 'wallet', rpc: run.rpc, demos: {} } as never;
  const anchor = { logicalAddress: 'payment', nativeAddress: 'native-payment', transactionRef: { kind: 'demos', value: 'tx' }, writer: `cci:${'11'.repeat(32)}`, nonce: '1' };
  const provider: CoreReceiptProvider = { describe: () => ({ kind: 'core-5.1-receipts', provesFinality: true, source: 'test' }), async fetch() { return { outcome: 'indeterminate', detail: 'unused' }; } };
  const gate = { authorize: async () => ({ verdict: 'PROCEED' as const, nowIso: new Date().toISOString() }), journalOutcome: async () => {}, beforeBroadcast: async () => {} };
  const seams: Partial<LiveSettlementSeams> = {
    loadPolicy: async () => { calls.push('policy'); return { network: 'testnet', rpcHosts: ['example.invalid'], perTransactionCapDem: '10', dailyCapDem: '20', killSwitchFile: '/tmp/no-kill' }; },
    resolveJournalPath: async () => { calls.push('journal-path'); return '/tmp/pay.jsonl'; },
    connect: async (_config, _env, receipt) => { calls.push('capability'); receipt.describe(); calls.push('credentials'); return {
      handles: { buyer: handle, seller: handle }, signers: { buyer: { claim: anchor.writer, sign: async () => new Uint8Array([1]) }, seller: { claim: anchor.writer, sign: async () => new Uint8Array([1]) }, orchestrator: { claim: anchor.writer, sign: async () => new Uint8Array([1]) } },
      anchor: async () => { calls.push('anchor'); return anchor; }, fetchAnchored: async () => ({}),
    }; },
    readJournal: async () => { calls.push('journal-read'); return []; }, killSwitchPresent: async () => { calls.push('kill-switch'); return false; },
    authorizeTransfer: async () => { calls.push('authorizeTransfer'); return { verdict: 'PROCEED', nowIso: new Date().toISOString() }; },
    createOutcomeJournal: async () => { calls.push('outcome-journal'); return async () => {}; },
    createJournal: async () => { calls.push('payment-journal'); return async () => {}; },
    createAuthorizationGate: async () => { calls.push('authorization-gate'); return gate; },
    balance: async () => { calls.push('balance'); return 100; },
    preflight: async (input) => { calls.push(`preflight-margin:${input.balanceMarginDem}`); return { verdict: 'PROCEED', estCostDem: 9, reasons: [] }; },
    settle: (async (input) => { calls.push(input.beforeBroadcast === gate.beforeBroadcast ? 'settle-beforeBroadcast' : 'settle-missing-beforeBroadcast'); return {
      ok: true, amountOs: 1_000_000_000n, txHash: 'hash', chainId: 'demos', payer: 'buyer', payee: 'seller', blockNumber: 1, finality: { model: 'bft-final' }, finalityObservedAt: 1,
      evidence: { evidenceVersion: '1', jobId: run.jobId, phase: 'pay-dem', phaseIndex: 2, outcome: 'success', paymentTxRefs: [{ rail: 'pay-dem', txHash: 'demos:hash', kind: 'payment' }], paymentAmount: { amount: '1', currency: 'DEM' }, settlementFinality: { model: 'bft-final', finalityObservedAt: 1 }, observedAt: 1 },
    }; }) as LiveSettlementSeams['settle'],
  };
  const live = await createLiveSettlementDependency(run, env, provider, seams);
  await live.settlePayment({} as never, run);
  assert.deepEqual(calls, ['policy', 'journal-path', 'env:GATEWAY_DRYRUN_HASH', 'env:GATEWAY_LIVE_APPROVED', 'capability', 'credentials',
    'journal-read', 'kill-switch', 'authorizeTransfer', 'outcome-journal', 'payment-journal', 'authorization-gate', 'balance', 'preflight-margin:2',
    'settle-beforeBroadcast', 'anchor']);
  assert.ok(calls.indexOf('env:GATEWAY_DRYRUN_HASH') < calls.indexOf('balance'));
  assert.ok(calls.indexOf('journal-path') < calls.indexOf('credentials'));
});

test('LIVE dry-run hash mismatch refuses before the balance query', async () => {
  const run = { ...config, mode: 'live' as const };
  let balanceCalls = 0;
  await assert.rejects(createLiveSettlementDependency(run, {
    GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: 'mismatch',
  }, createNodeReceiptProvider(run), {
    loadPolicy: async () => ({ network: 'testnet', rpcHosts: ['example.invalid'], perTransactionCapDem: '10', dailyCapDem: '20', killSwitchFile: '/tmp/no-kill' }),
    resolveJournalPath: async () => '/tmp/pay.jsonl',
    balance: async () => { balanceCalls++; return 100; },
  }), (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'spend');
  assert.equal(balanceCalls, 0);
});

test('in-process main dry-run stdout is wholly deterministic', async () => {
  const capture = async () => {
    const writes: string[] = [];
    const original = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => { writes.push(String(chunk)); return true; }) as typeof process.stdout.write;
    try { assert.equal(await main(['--dry-run', '--job-id', 'fixture-job', '--json'], {}), 0); }
    finally { process.stdout.write = original; }
    const json = writes.flatMap((chunk) => chunk.split('\n')).find((line) => line.startsWith('{"jobId"'));
    assert.ok(json);
    return JSON.parse(json) as unknown;
  };
  assert.deepEqual(await capture(), await capture());
});

function spawn(args: string[], extraEnv: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/live/dacs-testnet-run.mts', ...args], {
    cwd: process.cwd(), encoding: 'utf8', env: { PATH: process.env.PATH, ...extraEnv }, timeout: 30_000,
  });
}

test('dry-run CLI is deterministic, passes both cold checks, and emits no key material', (t) => {
  const first = spawn(['--dry-run', '--job-id', 'fixture-job', '--json']);
  if (first.error && (first.error as NodeJS.ErrnoException).code === 'EPERM') { t.skip('sandbox refuses nested process creation'); return; }
  const second = spawn(['--dry-run', '--job-id', 'fixture-job', '--json']);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.ok(first.stdout.trim(), `first stdout empty; stderr=${first.stderr}`);
  assert.ok(second.stdout.trim(), `second stdout empty; stderr=${second.stderr}`);
  const a = JSON.parse(first.stdout.trim()), b = JSON.parse(second.stdout.trim());
  assert.deepEqual(a, b);
  assert.equal(a.verification.agreement.outcome, 'pass');
  assert.equal(a.verification.bundle.outcome, 'pass');
  assert.equal(a.rollup, 'PASS');
  assert.doesNotMatch(first.stdout, /mnemonic|seed|private.?key/i);
});

test('LIVE without operator approval exits 2 and never prints environment values', (t) => {
  const sentinel = 'ENV-VALUE-MUST-NOT-APPEAR';
  const result = spawn(['--job-id', 'live-refusal', '--json'], { LIVE: '1', DEMOS_MNEMONIC: sentinel, DEMOS_SELLER_MNEMONIC: sentinel, GATEWAY_DRYRUN_HASH: sentinel });
  if (result.error && (result.error as NodeJS.ErrnoException).code === 'EPERM') { t.skip('sandbox refuses nested process creation'); return; }
  assert.equal(result.status, 2);
  assert.ok(!`${result.stdout}${result.stderr}`.includes(sentinel));
});
