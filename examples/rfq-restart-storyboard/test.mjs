import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { withRun, runChild, storyboard } from './main.mjs';
const child = (root, role, action, extra = {}, options) => runChild({ root, role, action, ...extra }, options);
async function opened(root) {
  for (const r of ['buyer', 'seller']) assert.equal((await child(root, r, 'open')).status, 'ready');
}
test('three turns, exact dual-signed agreement, independent processes, crash reconciliation and replay', () => withRun(async root => {
  const r = await storyboard(root);
  assert.equal(r.proof.turns, 3); assert.equal(r.acceptedAgreement.terms.price.amount, '9.5');
  assert.equal(r.acceptedAgreement.signatures.length, 2);
  for (const role of ['buyer', 'seller']) assert.equal((await readdir(join(root, role, 'mailbox'))).length, role === 'buyer' ? 3 : 2);
}), 30000);
test('distinct role keys, private stores, wrong key refuses without regeneration', () => withRun(async root => {
  await opened(root);
  const buyer = await readFile(join(root, 'buyer/integrity.key')), seller = await readFile(join(root, 'seller/integrity.key'));
  assert.notDeepEqual(buyer, seller);
  for (const role of ['buyer', 'seller']) {
    assert.equal((await stat(join(root, role, 'store'))).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, role, 'integrity.key'))).mode & 0o777, 0o600);
  }
  await writeFile(join(root, 'buyer/integrity.key'), seller);
  await assert.rejects(child(root, 'buyer', 'status'), /Worker failed/);
  await writeFile(join(root, 'buyer/integrity.key'), buyer);
  assert.equal((await child(root, 'buyer', 'status')).loadStatus, 'ok');
}), 15000);
test('tampered persisted bytes fail closed without rewriting state', () => withRun(async root => {
  await opened(root);
  async function files(path) {
    let all = [];
    for (const e of await readdir(path, { withFileTypes: true })) { const p = join(path, e.name); all.push(...e.isDirectory() ? await files(p) : [p]); }
    return all;
  }
  const target = (await files(join(root, 'buyer/store'))).find(p => p.endsWith('.json')); assert.ok(target);
  const original = await readFile(target);
  const modified = original.toString().replace('local-storyboard-channel-01', 'evil-storyboard-channel-01');
  assert.notEqual(modified, original.toString()); await writeFile(target, modified);
  const r = await child(root, 'buyer', 'offer');
  assert.equal(r.status, 'rejected'); assert.equal(r.loadStatus, 'corrupt');
  assert.equal((await readFile(target)).toString(), modified);
  await writeFile(target, original); assert.equal((await child(root, 'buyer', 'status')).loadStatus, 'ok');
}), 15000);
test('transport throw leaves pending packet; restart retries exact packet once', () => withRun(async root => {
  await opened(root);
  const uncertain = await child(root, 'buyer', 'offer', { fault: 'throw' });
  assert.equal(uncertain.status, 'indeterminate'); assert.equal(uncertain.transcript.length, 1);
  const recovered = await child(root, 'buyer', 'resume');
  assert.equal(recovered.status, 'ready'); assert.deepEqual(recovered.packets, uncertain.packets);
  assert.equal(recovered.transcript.length, 1); assert.equal((await readdir(join(root, 'buyer/mailbox'))).length, 1);
}), 15000);
test('hard deadline kills hung publisher; pending packet remains recoverable', () => withRun(async root => {
  await opened(root);
  await assert.rejects(child(root, 'buyer', 'offer', { fault: 'hang' }, { timeoutMs: 1500 }), /hard deadline/);
  const prior = await child(root, 'buyer', 'status'); assert.equal(prior.transcript.length, 1); assert.equal(prior.packets.length, 1);
  const recovered = await child(root, 'buyer', 'resume');
  assert.equal(recovered.status, 'ready'); assert.deepEqual(recovered.packets, prior.packets); assert.equal(recovered.transcript.length, 1);
}), 15000);
test('altered signature rejected; exact packet remains usable', () => withRun(async root => {
  await opened(root);
  const sent = await child(root, 'buyer', 'offer'); const packet = structuredClone(sent.packets[0]); packet.message.signature = 'invalid';
  assert.equal((await child(root, 'seller', 'receive', { packet })).status, 'rejected');
  assert.equal((await child(root, 'seller', 'status')).transcript.length, 0);
  assert.equal((await child(root, 'seller', 'receive', { packet: sent.packets[0] })).status, 'ready');
}), 15000);
test('out-of-band price and wrong-turn action create no turn or mailbox packet', () => withRun(async root => {
  await opened(root);
  assert.equal((await child(root, 'buyer', 'offer', { amount: '100' })).status, 'rejected');
  assert.equal((await child(root, 'seller', 'counter')).status, 'rejected');
  assert.equal((await child(root, 'buyer', 'status')).transcript.length, 0);
  assert.equal((await readdir(join(root, 'buyer/mailbox'))).length, 0);
  assert.equal((await child(root, 'buyer', 'offer')).status, 'ready');
}), 15000);
test('protocol timeout terminal; restart never creates a new proposal', () => withRun(async root => {
  await opened(root);
  const offer = await child(root, 'buyer', 'offer');
  assert.equal((await child(root, 'seller', 'receive', { packet: offer.packets[0] })).status, 'ready');
  const late = await child(root, 'seller', 'counter', { clockOffset: 11000 });
  assert.equal(late.session.status, 'timed-out'); assert.equal(late.transcript.length, 1);
  const restart = await child(root, 'seller', 'counter', { clockOffset: 11000 });
  assert.equal(restart.session.status, 'timed-out'); assert.equal(restart.transcript.length, 1);
}), 15000);

for (const [fault, exit] of [['crash-before-link', 87], ['crash-after-link', 88]]) {
  test(`atomic spool ${fault} recovers in a fresh process without another turn`, () => withRun(async root => {
    await opened(root);
    await child(root, 'buyer', 'offer', { fault }, { expectedExit: exit });
    const prior = await child(root, 'buyer', 'status');
    assert.equal(prior.transcript.length, 1);
    const recovered = await child(root, 'buyer', 'resume');
    assert.equal(recovered.status, 'ready'); assert.deepEqual(recovered.packets, prior.packets);
    assert.equal(recovered.transcript.length, 1);
    const delivered = await child(root, 'seller', 'receive', { packet: recovered.packets[0] });
    assert.equal(delivered.status, 'ready'); assert.equal(delivered.transcript.length, 1);
  }), 15000);
}
