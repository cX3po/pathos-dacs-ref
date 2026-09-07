import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createFileDeliveryStore, createMemoryDeliveryStore } from '../../src/live/delivery-store.js';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('the delivery-recovery harness passes every step in a fresh process: restart, eviction, concurrent duplicate, cross-request proof', () => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/delivery-recovery-fixture.mts', '--json'], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, timeout: 120_000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').at(-1)!);
  assert.equal(out.rollup, 'PASS');
  assert.equal(out.payments, 3);
  assert.deepEqual(out.steps.map((s: { step: string }) => s.step), ['paid', 'restart-redelivers-original', 'eviction-redelivers-original', 'concurrent-duplicate-redelivers', 'cross-request-proof-refused']);
  assert.ok(out.steps.every((s: { outcome: string }) => s.outcome === 'pass'), JSON.stringify(out.steps));
});

test('the file store skips and counts corrupt lines and keeps the last payload per key; the memory store mirrors it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'delivery-store-'));
  try {
    const path = join(dir, 'd.jsonl');
    writeFileSync(path, '{"key":"k1","payload":"p1","at":"t"}\nnot json\n{"key":5,"payload":"x"}\n{"key":"k1","payload":"p2","at":"t"}\n');
    const store = createFileDeliveryStore(path);
    const loaded = store.load();
    assert.equal(loaded.corrupt, 2);
    assert.deepEqual([...loaded.records], [['k1', 'p2']]);
    store.append('k2', 'p3');
    assert.equal(store.load().records.get('k2'), 'p3');
    const mem = createMemoryDeliveryStore(); mem.append('a', 'b');
    assert.equal(mem.load().records.get('a'), 'b');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
