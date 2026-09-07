import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DacsTestnetRefusal,
  createLiveAdapterWiring,
  main,
  parameterHash,
  runDacsTestnetSession,
  type ColdVerdict,
  type DacsTestnetConfig,
} from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';
import type { AnchorReceipt } from '../../src/types/bundle.js';

const config = (overrides: Partial<DacsTestnetConfig> = {}): DacsTestnetConfig => ({
  jobId: 'fixture-job', mode: 'dry-run', organ: 'nws_alerts', query: '35.2271,-80.8431',
  priceDem: '1', spendCapDem: 50, rpc: 'https://demosnode.discus.sh/', ...overrides,
});

test('real dry-run entry point is wholly deterministic', async () => {
  const firstConfig = config();
  const secondConfig = config();
  const first = await runDacsTestnetSession(firstConfig, createDryRunDependencies(firstConfig));
  const second = await runDacsTestnetSession(secondConfig, createDryRunDependencies(secondConfig));
  assert.deepEqual(first, second);
  assert.equal(first.rollup, 'PASS');
});

test('dependency mode mismatch is a capability refusal', async () => {
  const run = config({ mode: 'live' });
  await assert.rejects(runDacsTestnetSession(run, createDryRunDependencies(run)),
    (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'capability');
});

test('policy and spend refusals from settlement propagate out of the library', async () => {
  for (const reason of ['policy', 'spend'] as const) {
    const run = config({ jobId: `${reason}-refusal` });
    const deps = createDryRunDependencies(run);
    deps.settlePayment = async () => { throw new DacsTestnetRefusal(reason, 'sentinel must remain private'); };
    await assert.rejects(runDacsTestnetSession(run, deps),
      (error: unknown) => error instanceof DacsTestnetRefusal && error.code === reason);
  }
});

test('policy and spend settlement refusals map to CLI exit 2', async () => {
  for (const reason of ['policy', 'spend'] as const) {
    const stderr: string[] = [];
    const stdout: string[] = [];
    const originalErr = process.stderr.write.bind(process.stderr);
    const originalOut = process.stdout.write.bind(process.stdout);
    process.stderr.write = ((chunk: string | Uint8Array) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write;
    process.stdout.write = ((chunk: string | Uint8Array) => { stdout.push(String(chunk)); return true; }) as typeof process.stdout.write;
    try {
      const exit = await main(['--dry-run', '--json'], {}, (run) => {
        const deps = createDryRunDependencies(run);
        deps.settlePayment = async () => { throw new DacsTestnetRefusal(reason, 'private sentinel'); };
        return deps;
      });
      assert.equal(exit, 2);
    } finally {
      process.stderr.write = originalErr;
      process.stdout.write = originalOut;
    }
    assert.equal(stdout.join(''), '');
    assert.match(stderr.join(''), new RegExp(`"reason":"${reason}"`));
    assert.ok(!stderr.join('').includes('private sentinel'));
  }
});

test('preflight is enveloped, redacted, and still propagates typed refusals', async () => {
  const run = config();
  const failedDeps = createDryRunDependencies(run);
  failedDeps.capabilityPreflight = async () => { throw new Error('dependency-secret-sentinel'); };
  const failed = await runDacsTestnetSession(run, failedDeps);
  assert.equal(failed.error?.stage, 'capability-preflight');
  assert.equal(failed.error?.detail, 'capability-preflight: phase failed — Error/unclassified');
  assert.ok(!JSON.stringify(failed).includes('dependency-secret-sentinel'));

  const refusedDeps = createDryRunDependencies(run);
  refusedDeps.capabilityPreflight = async () => { throw new DacsTestnetRefusal('capability', 'private refusal'); };
  await assert.rejects(runDacsTestnetSession(run, refusedDeps), DacsTestnetRefusal);
});

test('SEB-3 finalization independently rejects a tampered stored evidence receipt', async () => {
  const run = config({ jobId: 'tampered-receipt' });
  const deps = createDryRunDependencies(run);
  const finalize = deps.finalize.bind(deps);
  deps.finalize = async (input) => {
    const receipt = deps.fixtureState.receipts.get(input.payment.evidenceLogicalAddress);
    assert.ok(receipt);
    deps.fixtureState.receipts.set(input.payment.evidenceLogicalAddress, {
      ...receipt, writer: `cci:${'00'.repeat(32)}`,
    } as AnchorReceipt);
    return finalize(input);
  };
  const result = await runDacsTestnetSession(run, deps);
  assert.equal(result.rollup, 'FAIL');
  assert.equal(result.error?.stage, 'finalization');
});

test('cold verifier outcomes are exercised through the real session', async () => {
  const verdict = (outcome: ColdVerdict['outcome']): ColdVerdict => ({ outcome, detail: 'not copied' });
  for (const agreement of ['pass', 'fail', 'indeterminate'] as const) {
    for (const bundle of ['pass', 'fail', 'indeterminate'] as const) {
      const run = config({ jobId: `cold-${agreement}-${bundle}` });
      const deps = createDryRunDependencies(run);
      deps.verifyAgreement = async () => verdict(agreement);
      deps.verifyBundle = async () => verdict(bundle);
      const result = await runDacsTestnetSession(run, deps);
      const expected = agreement === 'fail' ? 'FAIL'
        : agreement === 'indeterminate' ? 'INDETERMINATE'
          : bundle === 'fail' ? 'FAIL' : bundle === 'indeterminate' ? 'INDETERMINATE' : 'PASS';
      assert.equal(result.rollup, expected, `${agreement}/${bundle}`);
    }
  }

  const run = config({ jobId: 'vet-indeterminate' });
  const deps = createDryRunDependencies(run);
  deps.vetListing = async () => verdict('indeterminate');
  assert.equal((await runDacsTestnetSession(run, deps)).rollup, 'INDETERMINATE');
});

test('config and dependency error sentinels never enter result JSON', async () => {
  const sentinel = 'SENTINEL-CONFIG-AND-ERROR-VALUE';
  const run = config({ query: sentinel, rpc: sentinel });
  const deps = createDryRunDependencies(run);
  deps.publishListing = async () => { throw new Error(sentinel); };
  assert.ok(!JSON.stringify(await runDacsTestnetSession(run, deps)).includes(sentinel));
});

test('LIVE wiring refuses before exposing an anchor capability', async () => {
  const run = config({ mode: 'live' });
  await assert.rejects(createLiveAdapterWiring(run, {}),
    (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'capability');
});

function spawn(args: string[], extraEnv: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/live/dacs-testnet-run.mts', ...args], {
    cwd: process.cwd(), encoding: 'utf8', env: { PATH: process.env.PATH, ...extraEnv }, timeout: 30_000,
  });
}

async function withAllowingPolicy<T>(run: (env: NodeJS.ProcessEnv) => T | Promise<T>): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), 'dacs-testnet-policy-'));
  const policyPath = join(directory, 'policy.json');
  writeFileSync(policyPath, JSON.stringify({
    network: 'testnet', rpcHosts: ['demosnode.discus.sh'], perTransactionCapDem: '10',
    dailyCapDem: '20', killSwitchFile: join(directory, 'kill-switch'),
  }));
  try {
    return await run({ DACS_PAY_POLICY: policyPath, DACS_PAYDEM_JOURNAL: join(directory, 'pay-dem.jsonl') });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('LIVE CLI with policy and exact approval binding exits 2 as capability without exposing env values', async (t) => {
  const sentinel = 'ENV-SENTINEL-MUST-STAY-PRIVATE';
  const run = config({ mode: 'live', jobId: 'live-refusal' });
  const result = await withAllowingPolicy((policyEnv) => spawn(['--job-id', run.jobId, '--json'], {
    ...policyEnv, LIVE: '1', GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(run),
    DEMOS_MNEMONIC: sentinel, DEMOS_SELLER_MNEMONIC: sentinel,
  }));
  if (result.error && (result.error as NodeJS.ErrnoException).code === 'EPERM') {
    t.skip('sandbox refuses nested process creation'); return;
  }
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /"reason":"capability"/);
  assert.ok(!`${result.stdout}${result.stderr}`.includes(sentinel));
});

test('LIVE main with policy reaches capability, while unset policy refuses as policy', async () => {
  const run = config({ mode: 'live', jobId: 'live-refusal' });
  const capture = async (env: NodeJS.ProcessEnv) => {
    const writes: string[] = [];
    const original = process.stderr.write;
    process.stderr.write = ((chunk: string | Uint8Array) => { writes.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try { assert.equal(await main(['--job-id', run.jobId, '--json'], env), 2); }
    finally { process.stderr.write = original; }
    return writes.join('');
  };
  const capability = await withAllowingPolicy((policyEnv) => capture({
    ...policyEnv, LIVE: '1', GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(run),
  }));
  assert.match(capability, /"reason":"capability"/);
  assert.match(await capture({ LIVE: '1' }), /"reason":"policy"/);
});

test('LIVE main maps a checkout-internal pay-dem journal path to config exit 2', async () => {
  const run = config({ mode: 'live', jobId: 'live-refusal' });
  const writes: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => { writes.push(String(chunk)); return true; }) as typeof process.stderr.write;
  try {
    const exit = await withAllowingPolicy((policyEnv) => main(['--job-id', run.jobId, '--json'], {
      ...policyEnv, LIVE: '1', DACS_PAYDEM_JOURNAL: join(process.cwd(), 'pay-dem.jsonl'),
    }));
    assert.equal(exit, 2);
  } finally {
    process.stderr.write = original;
  }
  assert.match(writes.join(''), /"reason":"config"/);
});

test('--fixture-seed is a usage refusal in LIVE mode', async () => {
  const writes: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array) => { writes.push(String(chunk)); return true; }) as typeof process.stderr.write;
  try {
    assert.equal(await main(['--fixture-seed', 'aa'], { LIVE: '1' }), 2);
  } finally {
    process.stderr.write = original;
  }
  assert.match(writes.join(''), /"reason":"usage"/);
});
