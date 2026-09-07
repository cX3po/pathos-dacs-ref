import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { COMMITMENT_SCHEME, commitmentFor, openCommitment, verifyCommitmentOpening } from '../../src/live/commitment-opening.js';
import { organDeliverableFrom, OrganDeliverableError } from '../../src/live/dacs-testnet-run.mjs';

// The bridge's exact bytes: json.dumps(record, sort_keys=True, default=str) — keys sorted, ", " and ": " separators.
const RECORD_INPUT = '{"active_alerts": [], "location": {"lat": 35.2271, "lon": -80.8431}, "source": "nws"}';
const NONCE = 'ab'.repeat(32);
const COMMITMENT = createHmac('sha256', Buffer.from(NONCE, 'hex')).update(RECORD_INPUT, 'utf8').digest('hex');
const deliverable = { input_commitment: COMMITMENT, commitment_scheme: COMMITMENT_SCHEME };

test('a genuine opening verifies and yields the audited record; the seller side produces the same opening', () => {
  const opening = openCommitment(NONCE, RECORD_INPUT);
  assert.equal(commitmentFor(opening), COMMITMENT);
  const v = verifyCommitmentOpening(deliverable, opening);
  assert.equal(v.ok, true); assert.equal(v.reason, 'opened');
  assert.deepEqual(v.record, { active_alerts: [], location: { lat: 35.2271, lon: -80.8431 }, source: 'nws' });
});

test('a changed record, a changed nonce, a truncated input, a wrong scheme or a malformed commitment fails closed', () => {
  assert.equal(verifyCommitmentOpening(deliverable, { nonce: NONCE, commitment_input: RECORD_INPUT.replace('35.2271', '35.2272') }).reason, 'mismatch');
  assert.equal(verifyCommitmentOpening(deliverable, { nonce: 'cd'.repeat(32), commitment_input: RECORD_INPUT }).reason, 'mismatch');
  assert.equal(verifyCommitmentOpening(deliverable, { nonce: NONCE, commitment_input: RECORD_INPUT.slice(0, -1) }).reason, 'mismatch');
  assert.equal(verifyCommitmentOpening({ ...deliverable, commitment_scheme: 'sha256(record)' }, { nonce: NONCE, commitment_input: RECORD_INPUT }).reason, 'scheme-unsupported');
  assert.equal(verifyCommitmentOpening({ ...deliverable, input_commitment: 'xyz' }, { nonce: NONCE, commitment_input: RECORD_INPUT }).reason, 'commitment-malformed');
  assert.equal(verifyCommitmentOpening(deliverable, { nonce: 'zz', commitment_input: RECORD_INPUT }).reason, 'opening-malformed');
  assert.equal(verifyCommitmentOpening(deliverable, 'nope').reason, 'opening-malformed');
  const notObject = createHmac('sha256', Buffer.from(NONCE, 'hex')).update('[1,2]', 'utf8').digest('hex');
  assert.equal(verifyCommitmentOpening({ ...deliverable, input_commitment: notObject }, { nonce: NONCE, commitment_input: '[1,2]' }).reason, 'record-not-json-object');
  assert.throws(() => openCommitment('zz', RECORD_INPUT));
});

test('the coordinator never anchors the commitment input: a bridge output carrying it in the answer is a delivery failure', () => {
  const good = { organ: 'nws_alerts', answer: { coverage: 'verified-empty', active: false, highest_band: 'none', count_band: 'zero', basis: 'supplied-feed verified zero active entries for the committed point' },
    input_commitment: COMMITMENT, commitment_scheme: COMMITMENT_SCHEME, commitment_nonce: NONCE, fetched_at: '2026-09-07T02:00:00.000Z', commitment_input: RECORD_INPUT };
  const d = organDeliverableFrom(JSON.stringify(good), { jobId: 'j', organ: 'nws_alerts' });
  assert.ok(!JSON.stringify(d).includes(RECORD_INPUT) && !('commitment_input' in d));
  assert.throws(() => organDeliverableFrom(JSON.stringify({ ...good, answer: { ...good.answer, basis: RECORD_INPUT } }), { jobId: 'j', organ: 'nws_alerts' }), (e: unknown) => e instanceof OrganDeliverableError);
});
