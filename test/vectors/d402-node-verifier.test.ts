import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createNodeD402Verifier, paymentFromTransaction } from '../../src/adapters/demos/d402-node-verifier.js';
import { createD402Service } from '../../src/adapters/demos/d402-service.js';

const HASH = '887cdf4125f3c8607fdaec33c6a53ff1e755f1e2eed0b57449edc09190f40075';
const ADDR = '0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2';
const RESOURCE = 'verify:1dbcf75c09c36883';
// the shape demosnode.discus.sh returned for a settled d402 payment on 2026-09-03 (block 222221)
const TX = {
  content: { type: 'd402_payment', from: ADDR, to: ADDR, amount: 0, nonce: '405', timestamp: '1788428317416',
    data: ['d402_payment', { to: ADDR, amount: '100000000', memo: `resourceId:${RESOURCE} - DACS attestation-bundle verification` }] },
  signature: { type: 'ed25519', data: '0x00' }, hash: HASH, status: 'confirmed', blockNumber: 222221, attrs: { reference_block: 222220 },
};
const MEMO = `resourceId:${RESOURCE} - DACS attestation-bundle verification`;
const requirement = { amount: '100000000', recipient: ADDR, resourceId: RESOURCE, description: 'DACS attestation-bundle verification' };

test('paymentFromTransaction accepts a d402 payment included in a block and rejects everything else', () => {
  assert.deepEqual(paymentFromTransaction(TX, HASH), { from: ADDR, to: ADDR, amount: '100000000', memo: MEMO, timestamp: 1788428317416 });
  assert.equal(paymentFromTransaction(TX, '0x' + HASH)?.to, ADDR);
  assert.equal(paymentFromTransaction('error', HASH), null);
  assert.equal(paymentFromTransaction({ ...TX, blockNumber: null }, HASH), null);
  assert.equal(paymentFromTransaction({ ...TX, blockNumber: 0 }, HASH), null);
  assert.equal(paymentFromTransaction({ ...TX, blockNumber: '222221' }, HASH)?.to, ADDR, 'a numeric-string block number is tolerated');
  assert.equal(paymentFromTransaction({ ...TX, blockNumber: 'abc' }, HASH), null);
  for (const bad of ['reverted', 'rolled_back', 'failed', 'rejected']) assert.equal(paymentFromTransaction({ ...TX, status: bad }, HASH), null, bad);
  assert.equal(paymentFromTransaction({ ...TX, content: { ...TX.content, from: '' } }, HASH), null, 'an absent payer is refused');
  assert.equal(paymentFromTransaction(TX, HASH)?.from, ADDR, 'a self-payment (from == to) is accepted');
  assert.equal(paymentFromTransaction({ ...TX, hash: 'ab'.repeat(32) }, HASH), null);
  assert.equal(paymentFromTransaction({ ...TX, content: { ...TX.content, type: 'native' } }, HASH), null);
  assert.equal(paymentFromTransaction({ ...TX, content: { ...TX.content, data: ['d402_payment', { amount: '1' }] } }, HASH), null);
});

test('verify + validatePayment through an injected reader; node errors are valid:false', async () => {
  const calls: string[] = [];
  const reader = { async getTxByHash(h: string) { calls.push(h); if (h === HASH) return TX; if (h === 'boom') throw new Error('node down'); return 'error'; } };
  const v = createNodeD402Verifier({ rpcUrl: 'https://unused.invalid', reader });
  const ok = await v.verify('0x' + HASH);
  assert.equal(ok.valid, true);
  assert.equal(v.validatePayment(ok, requirement), true);
  assert.equal(v.validatePayment(ok, { ...requirement, recipient: '0x' + 'ab'.repeat(32) }), false);
  assert.equal(v.validatePayment(ok, { ...requirement, amount: '100000001' }), false);
  assert.equal(v.validatePayment(ok, { ...requirement, resourceId: 'verify:other' }), false);
  assert.equal((await v.verify('00'.repeat(32))).valid, false);
  assert.equal((await v.verify('boom')).valid, false);
  await v.verify(HASH);
  assert.equal(calls.filter((c) => c === HASH).length, 1, 'second verify of the same hash is served from the cache');
});

test('the gate accepts the settled payment through the node verifier and refuses a replay', async () => {
  const reader = { async getTxByHash(h: string) { return h === HASH ? TX : 'error'; } };
  const service = createD402Service({ recipient: ADDR, rpcUrl: 'https://unused.invalid', verifier: createNodeD402Verifier({ rpcUrl: 'https://unused.invalid', reader }) });
  const resource = { resourceId: RESOURCE, amount: '100000000', description: 'DACS attestation-bundle verification' };
  const paid = await service.gate({ headers: { 'x-payment-proof': HASH }, resource });
  assert.equal(paid.status, 200);
  if (paid.status === 200) assert.equal(paid.payment.amount, '100000000');
  const replay = await service.gate({ headers: { 'x-payment-proof': HASH }, resource });
  assert.equal(replay.status, 402);
  if (replay.status === 402) assert.equal(replay.reason, 'replayed');
  const wrong = await service.gate({ headers: { 'x-payment-proof': HASH }, resource: { ...resource, resourceId: 'verify:other' } });
  assert.equal(wrong.status, 402);
});
