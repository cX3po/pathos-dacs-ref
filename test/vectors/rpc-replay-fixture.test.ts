import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('the RPC replay corpus drives the real anchor path: bounded termination, typed uncertainty, one broadcast per scenario', () => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/rpc-replay-fixture.mts', '--json'], { encoding: 'utf8', timeout: 120_000,
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', GATEWAY_BROADCAST_TIMEOUT_MS: '150', GATEWAY_BROADCAST_GRACE_MS: '400', GATEWAY_BROADCAST_POLL_MS: '100' } });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1)!);
  assert.equal(out.rollup, 'PASS');
  assert.deepEqual(out.steps.map((s: { step: string }) => s.step), ['delayed-indexing', 'missing-finality-pending-forever', 'timeout-after-broadcast-then-included', 'failed-on-chain', 'conflicting-writer']);
  for (const s of out.steps) { assert.equal(s.outcome, 'pass', s.detail); assert.match(s.detail, /broadcasts=1 /); }
  assert.match(out.steps[1].detail, /anchor-not-confirmed tx=/);
  assert.match(out.steps[3].detail, /anchor-failed-on-chain tx=/);
});
