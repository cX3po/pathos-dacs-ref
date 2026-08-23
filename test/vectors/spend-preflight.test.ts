/** spend-preflight.test.ts — the live-gateway DEM spend gate (fail-closed). */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { preflight } from '../../src/live/spend-preflight.js';

const base = {
  purpose: 'gw', estWrites: 8, estCostPerWriteDem: 1, createCostDem: 1,
  maxSpendDem: 50, balanceDem: 2401, operatorApproved: true, dryRunHash: 'h', balanceMarginDem: 2,
};

test('all arms pass → PROCEED with a sane estimate', () => {
  const r = preflight(base);
  assert.equal(r.verdict, 'PROCEED');
  assert.equal(r.estCostDem, 9);              // 8*1 + 1 create
});
test('missing operator go → BLOCK (strict === true)', () => {
  assert.equal(preflight({ ...base, operatorApproved: false }).verdict, 'BLOCK');
  assert.equal(preflight({ ...base, operatorApproved: 1 as unknown as boolean }).verdict, 'BLOCK');
});
test('no dry-run binding → BLOCK', () => {
  assert.equal(preflight({ ...base, dryRunHash: null }).verdict, 'BLOCK');
  assert.equal(preflight({ ...base, dryRunHash: '' }).verdict, 'BLOCK');
});
test('over cap → BLOCK', () => {
  assert.equal(preflight({ ...base, estWrites: 500 }).verdict, 'BLOCK');
});
test('insufficient balance (incl margin) → BLOCK', () => {
  assert.equal(preflight({ ...base, balanceDem: 10, maxSpendDem: 1000, estWrites: 20 }).verdict, 'BLOCK');
});
test('malformed input → BLOCK before arithmetic (no estCost)', () => {
  const r = preflight({ ...base, estWrites: NaN });
  assert.equal(r.verdict, 'BLOCK');
  assert.equal(r.estCostDem, null);
});
