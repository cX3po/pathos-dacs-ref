import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TESTNET_FEE_PER_TX_DEM } from '../../src/live/dacs-testnet-run.mjs';
import { preflight } from '../../src/live/spend-preflight.js';

test('the session estimate counts the measured 2 DEM fee on every write and on the payment: 8 x 2 + 1 + 2 = 19 DEM', () => {
  assert.equal(TESTNET_FEE_PER_TX_DEM, 2);
  const r = preflight({ purpose: 'estimate', estWrites: 8, estCostPerWriteDem: TESTNET_FEE_PER_TX_DEM, createCostDem: 1 + TESTNET_FEE_PER_TX_DEM,
    maxSpendDem: 19, balanceDem: 100, balanceMarginDem: 2, operatorApproved: true, dryRunHash: 'x' });
  assert.equal(r.estCostDem, 19);
  const capped = preflight({ purpose: 'estimate', estWrites: 8, estCostPerWriteDem: TESTNET_FEE_PER_TX_DEM, createCostDem: 1 + TESTNET_FEE_PER_TX_DEM,
    maxSpendDem: 10, balanceDem: 100, balanceMarginDem: 2, operatorApproved: true, dryRunHash: 'x' });
  assert.notEqual(capped.verdict, 'PROCEED', 'the old 10 DEM cap can no longer admit a session');
});
