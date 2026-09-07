import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFileDeliveryStore, SCOPE_MISMATCH, type DeliveryScope } from '../../src/live/delivery-store.js';

const scope: DeliveryScope = { recipient: '0x' + 'ab'.repeat(32), sellerPubKeyHex: 'cd'.repeat(32), networkId: 'demos:testnet', amountOs: '100000000', offline: true, implementationVersion: 'test@0/1' };

test('the delivery-recovery harness passes every step in a fresh process', () => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/delivery-recovery-fixture.mts', '--json'], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, timeout: 120_000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1)!);
  assert.equal(out.rollup, 'PASS');
  assert.equal(out.payments, 3);
  assert.deepEqual(out.steps.map((s: { step: string }) => s.step), ['paid', 'restart-redelivers-original', 'eviction-redelivers-original', 'concurrent-duplicate-redelivers', 'cross-request-proof-refused', 'disconnected-buyer-not-recorded', 'scope-mismatch-refused']);
  assert.ok(out.steps.every((s: { outcome: string }) => s.outcome === 'pass'), JSON.stringify(out.steps));
});

test('the file store writes a scope header, keeps payloads on disk, survives a torn tail, and refuses another scope', () => {
  const dir = mkdtempSync(join(tmpdir(), 'delivery-store-'));
  try {
    const path = join(dir, 'd.jsonl');
    const store = createFileDeliveryStore(path, scope);
    assert.deepEqual(store.load(), { keys: [], corrupt: 0 });
    store.append('k1', 'p1');
    assert.equal(readFileSync(path, 'utf8').split('\n')[0], JSON.stringify({ v: 'delivery-store:1', scope }));
    // a torn tail from an interrupted append
    appendFileSync(path, '{"key":"k2","payload":"half');
    const reloaded = createFileDeliveryStore(path, scope);
    assert.deepEqual(reloaded.load(), { keys: ['k1'], corrupt: 1 });
    reloaded.append('k3', 'p3');
    const again = createFileDeliveryStore(path, scope);
    assert.deepEqual(again.load(), { keys: ['k1', 'k3'], corrupt: 1 });
    assert.equal(again.get('k3'), 'p3');
    assert.equal(again.get('k1'), 'p1');
    assert.equal(again.get('missing'), undefined);
    // last payload per key wins; corrupt JSON lines are counted
    writeFileSync(path, readFileSync(path, 'utf8') + 'not json\n' + JSON.stringify({ key: 'k1', payload: 'p1b', at: 't' }) + '\n');
    const last = createFileDeliveryStore(path, scope); last.load();
    assert.equal(last.get('k1'), 'p1b');
    // another deployment scope is refused
    assert.throws(() => createFileDeliveryStore(path, { ...scope, recipient: '0x' + 'ff'.repeat(32) }).load(), (e: unknown) => e instanceof Error && e.message === SCOPE_MISMATCH);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
