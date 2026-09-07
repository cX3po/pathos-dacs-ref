import test from 'node:test';
import assert from 'node:assert/strict';
import { gatewayDeliverableFrom } from '../../src/live/organ-gateway-deliverable.js';
import { OrganDeliverableError } from '../../src/live/dacs-testnet-run.mjs';

const NONCE = 'ab'.repeat(32);
const AGREEMENT = 'cd'.repeat(32);
const good = { organ: 'nws_alerts', answer: { coverage: 'verified-empty', active: false, highest_band: 'none', count_band: 'zero', basis: 'supplied-feed verified zero active entries for the committed point' },
  input_commitment: 'ef'.repeat(32), commitment_scheme: 'hmac-sha256(nonce, sorted-json-record)', commitment_nonce: NONCE, fetched_at: '2026-09-07T02:00:00.000Z' };
const run = { jobId: 'gw-job-1', organ: 'nws_alerts', agreementHash: AGREEMENT };

test('the gateway deliverable is the projected public answer plus the agreement hash; the nonce is returned, never anchored', () => {
  const { deliverable, commitmentNonce } = gatewayDeliverableFrom(JSON.stringify({ ...good, answer: { ...good.answer, raw_feed: ['private event'], location: '35.2,-80.8' } }), run);
  assert.deepEqual(deliverable, { v: 'pathos-organ-deliverable:0.1', jobId: 'gw-job-1', agreementHash: AGREEMENT, organ: 'nws_alerts', answer: good.answer,
    input_commitment: good.input_commitment, commitment_scheme: good.commitment_scheme, fetched_at: good.fetched_at });
  assert.equal(commitmentNonce, NONCE);
  assert.ok(!JSON.stringify(deliverable).includes(NONCE));
});

test('a bridge answer that fails projection, a wrong organ, a missing nonce or a bad agreement hash is a delivery failure before anchoring', () => {
  const isDelivery = (e: unknown) => e instanceof OrganDeliverableError;
  assert.throws(() => gatewayDeliverableFrom(JSON.stringify({ ...good, answer: { ...good.answer, highest_band: 'charlotte' } }), run), isDelivery);
  assert.throws(() => gatewayDeliverableFrom(JSON.stringify({ ...good, organ: 'air_quality' }), run), isDelivery);
  assert.throws(() => gatewayDeliverableFrom(JSON.stringify({ ...good, commitment_nonce: undefined }), run), isDelivery);
  assert.throws(() => gatewayDeliverableFrom(JSON.stringify(good), { ...run, agreementHash: 'nope' }), isDelivery);
  assert.throws(() => gatewayDeliverableFrom('{not json', run), isDelivery);
  assert.throws(() => gatewayDeliverableFrom(JSON.stringify({ ...good, answer: { ...good.answer, basis: `basis ${NONCE}` } }), run), isDelivery);
});
