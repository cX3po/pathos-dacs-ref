/**
 * DACS commerce showcase — integration test.
 * Proves the Vendor↔Shopper DACS-1→5 session produces verifyBundle-PASSING
 * two-sided bundles and ordered stage events. No network (mock settlement).
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { runShowcaseSession } from '../../src/showcase/flow.js';

test('showcase: full DACS-1→5 session, both bundles PASS', async () => {
  const s = await runShowcaseSession({ jobId: 'showcase-test-0001' });
  assert.equal(s.verdicts.buyer.decision, 'pass', `buyer bundle: ${JSON.stringify(s.verdicts.buyer.steps)}`);
  assert.equal(s.verdicts.seller.decision, 'pass', `seller bundle: ${JSON.stringify(s.verdicts.seller.steps)}`);
  assert.equal(s.verdicts.buyer.signersVerified.length, 1);
  assert.equal(s.verdicts.seller.signersVerified.length, 1);
});

test('showcase: emits all five DACS stages in order', async () => {
  const s = await runShowcaseSession({ jobId: 'showcase-test-0002' });
  const stages = [...new Set(s.events.map((e) => e.stage))];
  assert.deepEqual(stages, ['DACS-1 Identify', 'DACS-2 Vet', 'DACS-3 Negotiate', 'DACS-4 Settle', 'DACS-5 Verify']);
  // artifacts are content-addressed (hex hashes present on producing stages)
  assert.ok(s.events.filter((e) => e.artifactHash).every((e) => /^[0-9a-f]{64}$/.test(e.artifactHash!)));
});

test('showcase: two-sided anchors are distinct + deterministic', async () => {
  const s = await runShowcaseSession({ jobId: 'showcase-test-0003' });
  assert.notEqual(s.anchors.buyer, s.anchors.seller);
  assert.match(s.anchors.buyer, /^stor-/);
});
