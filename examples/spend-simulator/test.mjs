import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile, readdir, writeFile, unlink } from 'node:fs/promises';
import { simulation, withPrivateRun, runChild, validateDid, validateRpc, CAIRN_DID } from './main.mjs';

test('real SDK reservation survives independent process restart and retains cap', async () => {
  const result = await simulation();
  assert.equal(result.first.status, 'reserved');
  assert.equal(result.restarted.reason, 'cumulative-limit');
  assert.equal(result.restarted.inspection.assets[0].reservedWorstCaseDebit, '60');
  assert.equal(result.restarted.inspection.assets[0].availableHeadroom, '40');
});
test('real SDK refuses reservation crossing minimum reserve', async () => withPrivateRun(async root => {
  const result = await runChild({ root, phase: 'floor' });
  assert.equal(result.status, 'denied'); assert.equal(result.reason, 'insufficient-reserve');
}));
for (const attack of ['missing-record', 'tampered-record', 'wrong-key']) {
  test(`real filesystem store fails closed after ${attack}`, async () => withPrivateRun(async root => {
    await runChild({ root, phase: 'first' });
    const dir = join(root, 'state', 'records');
    const names = await readdir(dir); assert.equal(names.length, 1);
    const record = join(dir, names[0]);
    if (attack === 'missing-record') await unlink(record);
    if (attack === 'tampered-record') {
      const data = JSON.parse(await readFile(record, 'utf8'));
      data.state.reservations = []; // valid JSON, stale MAC: attempted budget reset
      await writeFile(record, JSON.stringify(data), { mode: 0o600 });
    }
    if (attack === 'wrong-key') await writeFile(join(root, 'integrity.key'), Buffer.alloc(32, 1), { mode: 0o600 });
    await assert.rejects(runChild({ root, phase: 'restart' }), /missing|corrupt|unauthenticated|authentication/i);
  }));
}
test('read-only network inputs reject lookalikes, non-testnet and noncanonical subjects', () => {
  for (const endpoint of ['http://node2.demos.sh', 'https://node2.demos.sh.evil.test', 'https://node2.demos.sh/path', 'https://user@node2.demos.sh', 'https://mainnet.demos.sh']) assert.throws(() => validateRpc(endpoint));
  assert.equal(validateRpc('https://demosnode.discus.sh'), 'https://demosnode.discus.sh');
  assert.equal(validateDid(CAIRN_DID), CAIRN_DID);
  for (const did of [CAIRN_DID.toUpperCase(), CAIRN_DID + ' ', 'did:demos:agent:' + 'f'.repeat(100000)]) assert.throws(() => validateDid(did));
});
