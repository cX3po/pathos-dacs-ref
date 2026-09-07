import test from 'node:test';
import assert from 'node:assert/strict';
import { causeSuffix, describeFailure, runDacsTestnetSession, DacsTestnetRefusal, type DacsTestnetConfig } from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';
import { Sr2AnchorError } from '../../src/demos/storage.js';

const config: DacsTestnetConfig = {
  jobId: '01M1WJYAADW8B9CRMBEZ9DKME5', mode: 'dry-run', organ: 'tlsn', query: 'failure detail fixture',
  rpc: 'https://rpc.fixture.invalid/', priceDem: 1,
} as unknown as DacsTestnetConfig;
const HASH = 'fbefbd19521e8996165b9949972c5964d09af5b7cdbd00d14c644c7bcd3ee12d';

test('a typed anchor failure carries its class, transaction hash and wait window into error.detail, never the message', async () => {
  const deps = createDryRunDependencies(config);
  deps.publishListing = async () => {
    throw new Sr2AnchorError('anchor-not-confirmed', { txHash: HASH, waitMs: 420000 },
      `SR-2 anchor of "dacs1%3Adid%3Ademos%3Aagent%3Aab" not confirmed within 420000ms (tx ${HASH}; never re-broadcast — ${config.rpc})`);
  };
  const result = await runDacsTestnetSession(config, deps);
  assert.equal(result.rollup, 'FAIL');
  assert.equal(result.error?.stage, 'listing');
  assert.equal(result.error?.code, 'phase-failed');
  assert.equal(result.error!.detail, `listing: phase failed — Sr2AnchorError/anchor-not-confirmed; tx ${HASH}; waited 420000ms`);
  assert.ok(!JSON.stringify(result).includes('dacs1%3A') && !JSON.stringify(result).includes(config.rpc as string), 'no message text');
});

test('untyped errors carry only an allowlisted kind: names, hashes, numbers and words in messages never appear', () => {
  const hostile = new Error(`mnemonic twelve words ${config.rpc} PIN=abc within 99ms state=pending tx ${HASH}`);
  hostile.name = 'privateKey=abcdefgh12345678';
  const d = describeFailure(hostile);
  assert.deepEqual(d, { kind: 'Error', class: 'unclassified', txHash: null, waitMs: null, state: null, depth: 0 });
  assert.equal(causeSuffix(d), ' — Error/unclassified');
  assert.equal(describeFailure('plain string').kind, 'Error');
  assert.equal(describeFailure(undefined).class, 'unclassified');
  assert.equal(describeFailure(new TypeError('x')).kind, 'TypeError');
});

test('typed fields are validated at construction and read through the cause chain with limits', () => {
  const bad = new Sr2AnchorError('anchor-not-included', { txHash: 'not-a-hash', waitMs: -5, state: 'supersecret-state' }, 'm');
  assert.deepEqual(bad.diagnostics, { class: 'anchor-not-included', state: 'unknown' });
  const inner = new Sr2AnchorError('anchor-failed-on-chain', { txHash: HASH, state: 'failed' }, 'inner');
  const wrapped = new TypeError('listing failed', { cause: inner });
  const d = describeFailure(wrapped);
  assert.deepEqual(d, { kind: 'TypeError', class: 'anchor-failed-on-chain', txHash: HASH, waitMs: null, state: 'failed', depth: 1 });
  assert.equal(causeSuffix(d), ` — TypeError/anchor-failed-on-chain; tx ${HASH}; state failed; cause depth 1`);
  const loop = new Error('a'); (loop as { cause?: unknown }).cause = loop;
  assert.equal(describeFailure(loop).depth, 0);
  const many = new AggregateError([new Error('e0'), inner], 'many');
  assert.equal(describeFailure(many).kind, 'AggregateError');
  assert.equal(describeFailure(many).class, 'anchor-failed-on-chain');
  const refusal = describeFailure(new DacsTestnetRefusal('capability', 'no'));
  assert.equal(refusal.class, 'refusal-capability');
});
