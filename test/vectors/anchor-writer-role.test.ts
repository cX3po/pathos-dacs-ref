import { test } from 'node:test';
import assert from 'node:assert/strict';
import { anchorNames, anchorWriterRole } from '../../src/live/anchor-naming.js';
import { deriveBundleLogicalAddress } from '../../src/lib/bundle-binding-v1.js';

test('the buyer writes only the buyer bundle copy; the seller/orchestrator writes every other anchor', () => {
  const jobId = 'beta-testnet-20260906T032318Z';
  assert.equal(anchorWriterRole(jobId, deriveBundleLogicalAddress(jobId, 'buyer')), 'buyer');
  assert.equal(anchorWriterRole(jobId, deriveBundleLogicalAddress(jobId, 'seller')), 'seller');
  assert.equal(anchorWriterRole(jobId, deriveBundleLogicalAddress(jobId, 'orchestrator')), 'orchestrator');
  // The hashed bundle address carries no role text: a suffix test alone cannot see it.
  assert.equal(deriveBundleLogicalAddress(jobId, 'buyer').endsWith(':buyer'), false);
  // Another job's buyer bundle is not this job's buyer anchor.
  assert.equal(anchorWriterRole(jobId, deriveBundleLogicalAddress('other-job', 'buyer')), 'orchestrator');
  // The colon-suffixed names still resolve.
  assert.equal(anchorWriterRole(jobId, anchorNames.bundle(jobId, 'buyer')), 'buyer');
  assert.equal(anchorWriterRole(jobId, anchorNames.bundle(jobId, 'seller')), 'seller');
  for (const logical of [anchorNames.agreement(jobId), anchorNames.paymentEvidence(jobId, 'pay-dem', 2), anchorNames.deliverable(jobId), anchorNames.deliveryEvidence(jobId, 3), 'dacs1:listing:abc']) {
    assert.equal(anchorWriterRole(jobId, logical), 'orchestrator', logical);
  }
});
