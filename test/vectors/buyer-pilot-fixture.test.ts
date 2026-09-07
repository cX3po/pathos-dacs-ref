import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('the buyer pilot harness passes every step offline in a fresh process with exactly one payment', () => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/buyer-pilot-fixture.mts', '--json'], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, timeout: 120_000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1)!);
  assert.equal(out.rollup, 'PASS');
  assert.equal(out.payments, 1);
  assert.equal(typeof out.self_purchase, 'boolean');
  const expected = ['discover', 'bind', 'substitution-refused', 'challenge-402', 'pay-capped', 'deliver', 'retry-without-payment', 'self-purchase-labelled'];
  assert.deepEqual(out.steps.map((s: { step: string }) => s.step), expected);
  assert.ok(out.steps.every((s: { outcome: string }) => s.outcome === 'pass'), JSON.stringify(out.steps));
  assert.ok(!/mnemonic|DEMOS_MNEMONIC/.test(r.stdout + r.stderr));
});
