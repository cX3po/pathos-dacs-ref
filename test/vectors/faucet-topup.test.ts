/** faucet-topup decision: ample balance skips; a low balance plus a dead faucet fails. */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  AMPLE_MESSAGE,
  classifyBalance,
  jobExitCode,
} from '../../src/live/faucet-ample.js';

test('balance at or above the threshold skips and the job exits 0', () => {
  assert.equal(classifyBalance(1000, 1000), 'ample');
  assert.equal(classifyBalance(162000, 1000), 'ample');
  assert.equal(AMPLE_MESSAGE, 'balance ample, faucet skipped');
  assert.equal(jobExitCode(['ample', 'ample']), 0);
});

test('balance below the threshold and a failed faucet exits non-zero', () => {
  assert.equal(classifyBalance(999, 1000), 'needs-faucet');
  assert.equal(classifyBalance(0, 1000), 'needs-faucet');
  assert.equal(jobExitCode(['faucet-failed']), 1);
  assert.equal(jobExitCode(['ample', 'faucet-failed']), 1);
});

test('a low balance whose faucet request succeeds still exits 0', () => {
  assert.equal(jobExitCode(['requested']), 0);
  assert.equal(jobExitCode(['requested', 'ample']), 0);
});

test('an unreadable balance is not treated as ample', () => {
  assert.equal(classifyBalance(null, 1000), 'unreadable');
  assert.equal(classifyBalance(Number.NaN, 1000), 'unreadable');
  assert.equal(jobExitCode(['unreadable']), 1);
});

import { ampleThreshold, runFaucetTopup, type TopupReport } from '../../src/live/faucet-ample.js';
import { BUYER_MNEMONIC_ENV, sellerMnemonicEnvs } from '../../src/live/organ-profiles.js';

test('threshold defaults and override retain the local cron policy', () => {
  for (const raw of [undefined, '', 'not-a-number', '-1', 'Infinity']) {
    // Explicit undefined follows the environment default; isolate it for this probe.
    const saved = process.env.DEMOS_FAUCET_MIN_DEM;
    delete process.env.DEMOS_FAUCET_MIN_DEM;
    try { assert.equal(ampleThreshold(raw), 1000); }
    finally {
      if (saved === undefined) delete process.env.DEMOS_FAUCET_MIN_DEM;
      else process.env.DEMOS_FAUCET_MIN_DEM = saved;
    }
  }
  assert.equal(ampleThreshold('2500'), 2500);
  assert.equal(ampleThreshold('0'), 0);
});

test('every registered organ seller and buyer skips the faucet when ample', async () => {
  const connected: string[] = [], reports: TopupReport[] = [];
  let requests = 0, settles = 0;
  const results = await runFaucetTopup({
    async connect(env) {
      connected.push(env);
      return { async balance() { return 1000; }, async request() { requests++; return false; } };
    },
    async settle() { settles++; }, report(row) { reports.push(row); },
  }, 1000);
  assert.deepEqual(connected, [BUYER_MNEMONIC_ENV, ...sellerMnemonicEnvs()]);
  assert.equal(connected.length, 4);
  assert.equal(new Set(connected).size, 4);
  assert.deepEqual(results, ['ample', 'ample', 'ample', 'ample']);
  assert.equal(jobExitCode(results), 0);
  assert.equal(requests, 0); assert.equal(settles, 0); assert.equal(reports.length, 4);
});

for (const fault of ['connect', 'read', 'null', 'nan', 'request-false', 'request-throw', 'request-timeout', 'after-read', 'settle'] as const) {
  test(`one ${fault} failure fails the entire job and later wallets still run`, async () => {
    let connected = 0, calls = 0;
    const rows: TopupReport[] = [];
    const result = await runFaucetTopup({
      async connect() {
        const failing = connected++ === 0;
        if (failing && fault === 'connect') throw new Error('synthetic private error');
        let reads = 0;
        return {
          async balance() {
            reads++;
            if (!failing) return 1001;
            if (fault === 'read' || (fault === 'after-read' && reads > 1)) throw new Error('synthetic private error');
            if (fault === 'null') return null;
            if (fault === 'nan') return NaN;
            return 999;
          },
          async request() {
            calls++;
            if (fault === 'request-timeout') throw new DOMException('synthetic timeout', 'TimeoutError');
            if (fault === 'request-throw') throw new Error('synthetic private error');
            return false;
          },
        };
      },
      async settle() { if (fault === 'settle') throw new Error('synthetic private error'); },
      report(row) { rows.push(row); },
    }, 1000);
    assert.equal(jobExitCode(result), 1);
    assert.equal(connected, 4);
    assert.deepEqual(result.slice(1), ['ample', 'ample', 'ample']);
    assert.equal(rows.length, 4);
    assert.ok(!JSON.stringify(rows).includes('synthetic private error'));
    assert.equal(calls, ['connect', 'read', 'null', 'nan'].includes(fault) ? 0 : 1);
  });
}

test('successful low-wallet requests with readable balances all succeed', async () => {
  let requests = 0, settles = 0;
  const results = await runFaucetTopup({
    async connect() { return { async balance() { return 12; }, async request() { requests++; return true; } }; },
    async settle() { settles++; }, report() {},
  }, 1000);
  assert.deepEqual(results, ['requested', 'requested', 'requested', 'requested']);
  assert.equal(requests, 4); assert.equal(settles, 4); assert.equal(jobExitCode(results), 0);
});

import { requestFaucet } from '../../src/live/faucet-ample.js';

test('mixed requested and failed wallets, and an empty run, fail the job', () => {
  assert.equal(jobExitCode(['requested', 'faucet-failed']), 1);
  assert.equal(jobExitCode([]), 1);
});

for (const [name, status, body, expected] of [
  ['ok-empty-object', 200, '{}', true], ['ok-requested', 200, '{"body":{"amount":"1"}}', true],
  ['error', 200, '{"error":"public synthetic error"}', false], ['http-500', 500, '{}', false],
  ['non-json', 200, 'not json', false], ['null', 200, 'null', false], ['array', 200, '[]', false],
] as const) {
  test(`actual HTTP boundary: ${name}`, async () => {
    let calls = 0;
    const fetcher: typeof fetch = async (url, init) => {
      calls++;
      assert.equal(url, 'https://example.test/api/request');
      assert.equal(init?.method, 'POST');
      assert.deepEqual(JSON.parse(init?.body as string), { address: 'synthetic-address' });
      assert.ok(init?.signal instanceof AbortSignal);
      return new Response(body, { status });
    };
    assert.equal(await requestFaucet(fetcher, 'https://example.test', 'synthetic-address'), expected);
    assert.equal(calls, 1);
  });
}

test('hung HTTP fetch times out, aborts its signal and returns failure', async () => {
  let signal: AbortSignal | undefined;
  const fetcher: typeof fetch = async (_url, init) => {
    signal = init?.signal as AbortSignal;
    return await new Promise<Response>(() => {});
  };
  assert.equal(await requestFaucet(fetcher, 'https://example.test', 'synthetic-address', 5), false);
  assert.equal(signal?.aborted, true);
});

test('hung HTTP response body also times out and returns failure', async () => {
  const fetcher: typeof fetch = async () => ({ ok: true, json: () => new Promise(() => {}) }) as unknown as Response;
  assert.equal(await requestFaucet(fetcher, 'https://example.test', 'synthetic-address', 5), false);
});

for (const stage of ['connect', 'balance', 'request', 'settle'] as const) {
  test(`hung ${stage} has a deadline; later wallets run without a retained lock`, async () => {
    let connected = 0;
    const result = await runFaucetTopup({
      async connect() {
        const first = connected++ === 0;
        if (first && stage === 'connect') return await new Promise(() => {});
        return {
          async balance() { return first && stage === 'balance' ? await new Promise(() => {}) : first ? 0 : 1000; },
          async request() { return first && stage === 'request' ? await new Promise(() => {}) : true; },
        };
      },
      async settle() { if (stage === 'settle') await new Promise(() => {}); }, report() {},
    }, 1000, 5);
    assert.equal(jobExitCode(result), 1);
    assert.equal(connected, 1 + sellerMnemonicEnvs().length);
    assert.ok(result.slice(1).every(row => row === 'ample'));
  });
}
