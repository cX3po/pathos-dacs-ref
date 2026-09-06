import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TESTNET_FEE_PER_TX_DEM, SESSION_WRITES, main } from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';
import { preflight } from '../../src/live/spend-preflight.js';

test('the session estimate counts the measured 2 DEM fee on every write and on the payment: 13 x 2 + 1 + 2 = 29 DEM', () => {
  assert.equal(TESTNET_FEE_PER_TX_DEM, 2);
  assert.equal(SESSION_WRITES, 13);
  const r = preflight({ purpose: 'estimate', estWrites: SESSION_WRITES, estCostPerWriteDem: TESTNET_FEE_PER_TX_DEM, createCostDem: 1 + TESTNET_FEE_PER_TX_DEM,
    maxSpendDem: 29, balanceDem: 100, balanceMarginDem: 2, operatorApproved: true, dryRunHash: 'x' });
  assert.equal(r.estCostDem, 29);
  const capped = preflight({ purpose: 'estimate', estWrites: SESSION_WRITES, estCostPerWriteDem: TESTNET_FEE_PER_TX_DEM, createCostDem: 1 + TESTNET_FEE_PER_TX_DEM,
    maxSpendDem: 19, balanceDem: 100, balanceMarginDem: 2, operatorApproved: true, dryRunHash: 'x' });
  assert.notEqual(capped.verdict, 'PROCEED', 'the previous 19 DEM cap can no longer admit a session');
});

// The estimate is the executed count: a complete dry-run session writes exactly SESSION_WRITES programs.
test('SESSION_WRITES equals the number of programs a completed dry-run session anchors', async () => {
  let logical: Map<string, unknown> | undefined; const chunks: string[] = [];
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((c: string | Uint8Array) => { chunks.push(String(c)); return true; }) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], {}, (run) => { const deps = createDryRunDependencies(run); logical = deps.fixtureState.byLogical; return deps; });
    assert.equal(exit, 0);
  } finally { process.stdout.write = out; }
  const result = JSON.parse(chunks.join('').trim().split('\n').pop()!);
  assert.equal(result.rollup, 'PASS');
  assert.equal(logical!.size, SESSION_WRITES, [...logical!.keys()].join(', '));
});
