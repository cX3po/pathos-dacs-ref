/**
 * The Stranger Gauntlet — trust-showcase engine tests.
 *
 * Asserts the load-bearing guarantee (§7.5.1 do-not-collapse): the two honest vendors are
 * ACCEPTED, the counterfeit is NOT accepted (decision !== 'accept'), and the counterfeit carries
 * a populated `killedBy` naming the decisive check. If the counterfeit ever verified `accept`,
 * that is a real verifier bug and this suite fails.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { runStrangerGauntlet } from '../../showcase/stranger-gauntlet/gauntlet.mjs';

test('stranger-gauntlet — honest vendors are ACCEPTED (trusted)', () => {
  const res = runStrangerGauntlet();
  const a = res.vendors.find((v) => v.name.startsWith('Vendor A'))!;
  const b = res.vendors.find((v) => v.name.startsWith('Vendor B'))!;
  assert.equal(a.decision, 'accept', 'Vendor A honest bundle must verify accept');
  assert.equal(b.decision, 'accept', 'Vendor B honest bundle must verify accept');
  assert.equal(a.trusted, true);
  assert.equal(b.trusted, true);
  assert.equal(a.killedBy, null, 'an accepted bundle has no killing check');
  assert.equal(b.killedBy, null);
});

test('stranger-gauntlet — counterfeit is NOT accepted (§7.5.1 do-not-collapse)', () => {
  const res = runStrangerGauntlet();
  const c = res.vendors.find((v) => v.name.startsWith('Vendor C'))!;
  assert.notEqual(c.decision, 'accept', 'the counterfeit MUST NEVER be accepted');
  assert.equal(c.trusted, false);
  assert.equal(res.counterfeitCaught, true);
});

test('stranger-gauntlet — counterfeit reports a populated killedBy naming the decisive check', () => {
  const res = runStrangerGauntlet();
  const c = res.vendors.find((v) => v.name.startsWith('Vendor C'))!;
  assert.ok(c.killedBy, 'counterfeit must name the check that killed it');
  assert.ok(typeof c.killedBy!.check === 'string' && c.killedBy!.check.length > 0);
  assert.ok(typeof c.killedBy!.detail === 'string' && c.killedBy!.detail.length > 0);
  // The tamper is a post-signature content-hash change, so the decisive check is the signature.
  assert.equal(c.killedBy!.check, 'signature-invalid', 'content tamper after signing → signature failure');
  assert.equal(c.decision, 'reject', 'a hard signature failure resolves to reject (not indeterminate)');
});

test('stranger-gauntlet — overall verdict is PASS (honest trusted + counterfeit caught)', () => {
  const res = runStrangerGauntlet();
  assert.equal(res.honestBothTrusted, true);
  assert.equal(res.counterfeitCaught, true);
  assert.equal(res.verdict, 'PASS');
});

test('stranger-gauntlet — deterministic: two runs produce identical decisions + hashes', () => {
  const r1 = runStrangerGauntlet();
  const r2 = runStrangerGauntlet();
  assert.deepEqual(
    r1.vendors.map((v) => [v.name, v.decision, v.bundleHash]),
    r2.vendors.map((v) => [v.name, v.decision, v.bundleHash]),
    'fixed-seed keys → identical results across runs',
  );
});
