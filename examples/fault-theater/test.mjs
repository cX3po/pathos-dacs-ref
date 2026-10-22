import { test, expect } from 'bun:test';
import { readFile, mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fixtures, validity, mutations, gallery, score, deps, html, rejectionReasons } from './main.mjs';
const signed = await fixtures();
test('six signed original and relabelled copies verify', async () => {
  for (const pair of Object.values(signed)) for (const role of ['buyer', 'seller']) {
    const r = await validity(pair[`${role}Copy`], role); expect(r.valid).toBe(true); expect(r.fullySigned).toBe(true);
  }
});
test('two abort perspectives preserve absolute buyer fault', () => {
  expect(signed.selfAbort.buyerCopy.outcome).toBe('aborted-by-self');
  expect(signed.selfAbort.sellerCopy.outcome).toBe('aborted-by-other');
  for (const b of Object.values(signed.selfAbort)) expect(b.faultedParty).toBe('buyer');
});
for (const name of Object.keys(mutations(signed.completed.buyerCopy))) test(`reused corpus rejects ${name}`, async () => {
  const r = await validity(mutations(signed.completed.buyerCopy)[name], 'buyer');
  expect(r.valid).toBe(false); expect(r.reason).toMatch(rejectionReasons[name]);
});
test('authenticated roles prevent relabelled self abort becoming counterparty fault', async () => {
  const r = (await gallery()).comparison;
  expect(r.authenticated.bundleCount).toBe(1); expect(r.authenticated.metrics.counterpartyFaultRate).toBe(0);
  expect(r.untrusted.metrics.counterpartyFaultRate).toBe(1);
  expect(r.unknown.bundleCount).toBe(0); expect(r.unknown.metrics.counterpartyFaultRate).toBe(null);
});
test('wrong address role and unsigned/signed relabels fail', async () => {
  expect((await validity(signed.completed.buyerCopy, 'seller')).valid).toBe(false);
  const b = structuredClone(signed.selfAbort.buyerCopy); b.anchoredByRole = 'seller';
  expect((await validity(b, 'seller')).valid).toBe(false);
  const c = structuredClone(signed.completed.buyerCopy);
  for (const p of c.parties) p.role = p.role === 'buyer' ? 'seller' : 'buyer';
  expect((await validity(c, 'buyer')).valid).toBe(false);
});
test('wrong key, unresolved key and thrown verifier fail; next run recovers', async () => {
  for (const resolvePublicKey of [async () => new Uint8Array(32), async () => null]) expect((await validity(signed.completed.buyerCopy, 'buyer', { ...deps, resolvePublicKey })).valid).toBe(false);
  await expect(validity(signed.completed.buyerCopy, 'buyer', { ...deps, verify: () => { throw Error('synthetic throw'); } })).rejects.toThrow('synthetic throw');
  expect((await validity(signed.completed.buyerCopy, 'buyer')).valid).toBe(true);
});
test('unresolved, thrown and Promise role maps exclude', async () => {
  for (const role of [() => undefined, () => { throw Error('synthetic'); }, () => Promise.resolve('buyer')]) {
    const r = await score(Object.values(signed.selfAbort), role); expect(r.bundleCount).toBe(0); expect(r.metrics.counterpartyFaultRate).toBe(null);
  }
});
test('one sided copy needs authoritative absence', async () => {
  expect((await score([signed.selfAbort.buyerCopy], () => 'buyer')).bundleCount).toBe(0);
  expect((await score([signed.selfAbort.buyerCopy], () => 'buyer', () => 'indeterminate')).bundleCount).toBe(0);
  expect((await score([signed.selfAbort.buyerCopy], () => 'buyer', () => 'absent')).bundleCount).toBe(1);
});
test('mutation bridge missing targets and process failure fail closed and recover', () => {
  expect(() => mutations({})).toThrow();
  const old = process.env.PYTHON;
  try { process.env.PYTHON = '/nonexistent-fault-theater-python'; expect(() => mutations(signed.completed.buyerCopy)).toThrow(); }
  finally { if (old === undefined) delete process.env.PYTHON; else process.env.PYTHON = old; }
  expect(Object.keys(mutations(signed.completed.buyerCopy)).length).toBe(5);
});
test('checked in fixtures reproduce and verify', async () => {
  const saved = JSON.parse(await readFile(new URL('./fixtures.json', import.meta.url), 'utf8')); expect(saved).toEqual(signed);
  for (const pair of Object.values(saved)) for (const role of ['buyer', 'seller']) expect((await validity(pair[`${role}Copy`], role)).valid).toBe(true);
});
test('standalone HTML escapes markup', async () => {
  const r = await gallery(); r.trust = '<script>alert(1)</script>';
  expect(html(r)).not.toContain('<script>'); expect(html(r)).toContain('&lt;script&gt;');
});
test('CLI refuses live mode', () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('./main.mjs', import.meta.url)), '--live'], { timeout: 15000, encoding: 'utf8' }); expect(r.status).toBe(1); expect(r.stderr).toContain('Usage: bun main.mjs');
});

test('real mutation bridge timeout leaves next run recoverable', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'fault-theater-timeout-'));
  const fakePython = join(dir, 'python');
  const old = process.env.PYTHON;
  try {
    await writeFile(fakePython, '#!/usr/bin/python3\nimport time\ntime.sleep(30)\n');
    await chmod(fakePython, 0o700);
    process.env.PYTHON = fakePython;
    expect(() => mutations(signed.completed.buyerCopy)).toThrow('failed or timed out');
  } finally {
    if (old === undefined) delete process.env.PYTHON; else process.env.PYTHON = old;
    // Only this test-created, known wrapper is removed.
    await rm(dir, { recursive: true });
  }
  expect(Object.keys(mutations(signed.completed.buyerCopy)).length).toBe(5);
}, 15000);

test('unsafe SDK local role control follows the fixture labels instead of a constant', async () => {
  const honest = await score(Object.values(signed.selfAbort), { trustBundlePartyRoles: true });
  const relabelled = await score(Object.values(signed.relabelled), { trustBundlePartyRoles: true });
  expect(honest.metrics.counterpartyFaultRate).toBe(0);
  expect(relabelled.metrics.counterpartyFaultRate).toBe(1);
});
