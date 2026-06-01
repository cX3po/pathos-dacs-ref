/**
 * DACS-4 Settle — HTLC SettlementEvidence vectors
 *
 * Locks in:
 *   - round-trip: build (settled, lock+reveal) → verify PASS
 *   - tamper: mutate a txHash AFTER signing → verify FAIL (signature breaks)
 *   - refund path: build (refunded, lock+refund) → verify PASS
 *   - timelock-asymmetry: reveal at/after source timelock is rejected at build time
 *   - build/verify symmetry: the builder checks observedAt (not just the deadline),
 *     identical to the verifier — a builder cannot mint evidence its verifier rejects
 *   - canonical price: a non-canonical amount fails the finding-#27 check
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { generateKeypair, sign } from '../../src/lib/sign.js';
import { bytesToHex, hexToBytes } from '../../src/lib/verify-bundle.js';
import { jcsHashHex } from '../../src/jcs.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import {
  buildHtlcSettlementEvidence,
  verifyHtlcSettlementEvidence,
} from '../../src/lib/htlc-evidence.js';
import {
  RailAvailability,
  type SettlementEvidence,
  type PriceTerm,
  type HtlcLockTxRef,
  type HtlcRevealTxRef,
  type HtlcRefundTxRef,
} from '../../src/types/settle.js';

/** A deterministic 32-byte preimage + its hashlock. */
const PREIMAGE_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const HASHLOCK_HEX = bytesToHex(sha256(hexToBytes(PREIMAGE_HEX)));

const PRICE: PriceTerm = { amount: '1.500000', asset: 'USDC', decimals: 6 };

function makeLock(timelockExpiry: string): HtlcLockTxRef {
  return {
    phase: 'htlc-lock',
    chain: 'eip155:8453',
    txHash: '0xaaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000',
    hashlock: HASHLOCK_HEX,
    observedAt: '2026-05-28T00:00:00Z',
    timelockExpiry,
    amount: PRICE,
  };
}

function makeReveal(revealDeadline: string, observedAt: string): HtlcRevealTxRef {
  return {
    phase: 'htlc-reveal',
    chain: 'demos',
    txHash: '0xbbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111',
    hashlock: HASHLOCK_HEX,
    observedAt,
    preimage: PREIMAGE_HEX,
    revealDeadline,
  };
}

function makeRefund(refundedAfter: string, observedAt: string): HtlcRefundTxRef {
  return {
    phase: 'htlc-refund',
    chain: 'eip155:8453',
    txHash: '0xcccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222',
    hashlock: HASHLOCK_HEX,
    observedAt,
    refundedAfter,
  };
}

test('round-trip — build settled (lock+reveal) then verify PASS', () => {
  const { privKey, pubKey } = generateKeypair();
  const evidence = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-001',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'seller',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    // reveal lands strictly before the source timelock — the safe HTLC asymmetry
    lock: makeLock('2026-05-28T06:00:00Z'),
    reveal: makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    settledAt: '2026-05-28T05:01:00Z',
  });

  assert.equal(evidence.outcome, 'settled');
  assert.equal(evidence.txRefs.length, 2);

  const result = verifyHtlcSettlementEvidence(evidence);
  assert.equal(result.decision, 'pass', JSON.stringify(result.checks, null, 2));
  // The signed commitment is the JCS hash of the unsigned evidence.
  assert.equal(result.evidenceHashHex.length, 64);
  // Supplying the expected pubkey (matching the recorded one) still passes.
  const resultWithKey = verifyHtlcSettlementEvidence(evidence, pubKey);
  assert.equal(resultWithKey.decision, 'pass');
});

test('tamper — mutating a txHash after signing breaks verification', () => {
  const { privKey, pubKey } = generateKeypair();
  const evidence = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-002',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'seller',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    lock: makeLock('2026-05-28T06:00:00Z'),
    reveal: makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    settledAt: '2026-05-28T05:01:00Z',
  });

  // Mutate the reveal txHash — this is inside the signed canonical payload.
  const tampered = structuredClone(evidence);
  const reveal = tampered.txRefs.find(t => t.phase === 'htlc-reveal');
  assert.ok(reveal);
  reveal.txHash = '0xdeadbeef' + reveal.txHash.slice(10);

  const result = verifyHtlcSettlementEvidence(tampered);
  assert.equal(result.decision, 'fail');
  // The failing check MUST be the signature (the canonical hash changed).
  const sigCheck = result.checks.find(c => c.check === 'signature');
  assert.ok(sigCheck, 'expected a signature check in the walk');
  assert.equal(sigCheck.outcome, 'fail');
});

/** Sign an arbitrary unsigned-evidence object exactly as buildHtlcSettlementEvidence does,
 *  so these vectors carry a VALID signature and isolate the verifier's outcome logic. */
function signUnsigned(unsigned: Record<string, unknown>, privKey: Uint8Array): SettlementEvidence {
  const body = new TextEncoder().encode(jcsHashHex(unsigned));
  const sig = sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, body, privKey);
  return { ...unsigned, signature: Buffer.from(sig).toString('base64') } as unknown as SettlementEvidence;
}

test('fail-closed — a validly-signed evidence with an UNKNOWN outcome verifies FAIL', () => {
  const { privKey, pubKey } = generateKeypair();
  const unsigned = {
    v: 'dacs-4-settlement-evidence:0.1', jobId: 'job-htlc-neg-1', method: 'htlc',
    rail: RailAvailability.Mocked, price: PRICE, settler: 'seller',
    settlerPubkey: bytesToHex(pubKey),
    outcome: 'bogus', // not settled/refunded/failed — verifier must NOT fall through to pass
    txRefs: [makeLock('2026-05-28T06:00:00Z')], settledAt: '2026-05-28T05:01:00Z',
  };
  const result = verifyHtlcSettlementEvidence(signUnsigned(unsigned, privKey), pubKey);
  assert.equal(result.decision, 'fail', JSON.stringify(result.checks, null, 2));
  const uo = result.checks.find(c => c.check === 'unknown-outcome');
  assert.ok(uo && uo.outcome === 'fail', 'expected unknown-outcome to fail closed');
});

test('mutual exclusion — outcome=settled with a refund txRef riding along verifies FAIL', () => {
  const { privKey, pubKey } = generateKeypair();
  const unsigned = {
    v: 'dacs-4-settlement-evidence:0.1', jobId: 'job-htlc-neg-2', method: 'htlc',
    rail: RailAvailability.Mocked, price: PRICE, settler: 'seller',
    settlerPubkey: bytesToHex(pubKey),
    outcome: 'settled',
    // contradictory: a reveal (settled) AND a refund both present on one HTLC
    txRefs: [
      makeLock('2026-05-28T06:00:00Z'),
      makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
      makeRefund('2026-05-28T07:00:00Z', '2026-05-28T07:30:00Z'),
    ], settledAt: '2026-05-28T05:01:00Z',
  };
  const result = verifyHtlcSettlementEvidence(signUnsigned(unsigned, privKey), pubKey);
  assert.equal(result.decision, 'fail', JSON.stringify(result.checks, null, 2));
  const mx = result.checks.find(c => c.check === 'settled-no-refund');
  assert.ok(mx && mx.outcome === 'fail', 'expected settled-no-refund mutual-exclusion to fail');
});

test('fail-closed — outcome=failed with a reveal txRef riding along verifies FAIL (lock-only)', () => {
  const { privKey, pubKey } = generateKeypair();
  const unsigned = {
    v: 'dacs-4-settlement-evidence:0.1', jobId: 'job-htlc-neg-3', method: 'htlc',
    rail: RailAvailability.Failed, price: PRICE, settler: 'seller',
    settlerPubkey: bytesToHex(pubKey),
    outcome: 'failed', // failed must be lock-only — a reveal must not let it pass on rail alone
    txRefs: [
      makeLock('2026-05-28T06:00:00Z'),
      makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    ], settledAt: '2026-05-28T05:01:00Z',
  };
  const result = verifyHtlcSettlementEvidence(signUnsigned(unsigned, privKey), pubKey);
  assert.equal(result.decision, 'fail', JSON.stringify(result.checks, null, 2));
  const lo = result.checks.find(c => c.check === 'failed-lock-only');
  assert.ok(lo && lo.outcome === 'fail', 'expected failed-lock-only to fail closed');
});

test('refund path — build refunded (lock+refund) then verify PASS', () => {
  const { privKey, pubKey } = generateKeypair();
  const evidence = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-003',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'buyer',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    lock: makeLock('2026-05-28T06:00:00Z'),
    // refund waits until at/after the source timelock — no reveal occurred
    refund: makeRefund('2026-05-28T06:00:00Z', '2026-05-28T06:05:00Z'),
    settledAt: '2026-05-28T06:06:00Z',
  });

  assert.equal(evidence.outcome, 'refunded');
  assert.equal(evidence.txRefs.length, 2);

  const result = verifyHtlcSettlementEvidence(evidence);
  assert.equal(result.decision, 'pass', JSON.stringify(result.checks, null, 2));
  const timelockCheck = result.checks.find(c => c.check === 'timelock-asymmetry');
  assert.ok(timelockCheck);
  assert.equal(timelockCheck.outcome, 'pass');
});

test('timelock-asymmetry — reveal not strictly before source timelock is rejected at build', () => {
  const { privKey, pubKey } = generateKeypair();
  assert.throws(
    () =>
      buildHtlcSettlementEvidence({
        jobId: 'job-htlc-004',
        rail: RailAvailability.Mocked,
        price: PRICE,
        settler: 'seller',
        settlerPrivKey: privKey,
        settlerPubkey: pubKey,
        lock: makeLock('2026-05-28T06:00:00Z'),
        // reveal deadline EQUALS the source timelock — unsafe, must throw
        reveal: makeReveal('2026-05-28T06:00:00Z', '2026-05-28T05:30:00Z'),
      }),
    /timelock-asymmetry/
  );
});

test('build/verify symmetry — builder rejects a late reveal observedAt the verifier would also reject', () => {
  const { privKey, pubKey } = generateKeypair();

  // revealDeadline is strictly before the source timelock (would pass the OLD
  // builder), but observedAt lands AT/AFTER it. The verifier checks observedAt and
  // would reject such evidence — so a symmetric builder MUST refuse to mint it.
  assert.throws(
    () =>
      buildHtlcSettlementEvidence({
        jobId: 'job-htlc-006',
        rail: RailAvailability.Mocked,
        price: PRICE,
        settler: 'seller',
        settlerPrivKey: privKey,
        settlerPubkey: pubKey,
        lock: makeLock('2026-05-28T06:00:00Z'),
        // deadline safe (05:00 < 06:00) but observed AT the timelock — unsafe
        reveal: makeReveal('2026-05-28T05:00:00Z', '2026-05-28T06:00:00Z'),
      }),
    /timelock-asymmetry/,
    'builder must reject a reveal whose observedAt is not strictly before the timelock'
  );

  // Symmetry the other direction (refund path): a refund observed BEFORE the
  // timelock must be rejected at build time too, matching the verifier.
  assert.throws(
    () =>
      buildHtlcSettlementEvidence({
        jobId: 'job-htlc-007',
        rail: RailAvailability.Mocked,
        price: PRICE,
        settler: 'buyer',
        settlerPrivKey: privKey,
        settlerPubkey: pubKey,
        lock: makeLock('2026-05-28T06:00:00Z'),
        // refundedAfter satisfies at/after, but observed BEFORE the timelock — unsafe
        refund: makeRefund('2026-05-28T06:00:00Z', '2026-05-28T05:30:00Z'),
      }),
    /before the source lock timelock/,
    'builder must reject a refund whose observedAt is before the timelock'
  );

  // Positive symmetry: a build that the builder accepts must ALSO verify cleanly —
  // build-then-verify round-trip with both observedAt values on the safe side.
  const safeReveal = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-008',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'seller',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    lock: makeLock('2026-05-28T06:00:00Z'),
    reveal: makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    settledAt: '2026-05-28T05:01:00Z',
  });
  const revealResult = verifyHtlcSettlementEvidence(safeReveal);
  assert.equal(revealResult.decision, 'pass', JSON.stringify(revealResult.checks, null, 2));
  const revealTimelock = revealResult.checks.find(c => c.check === 'timelock-asymmetry');
  assert.ok(revealTimelock);
  assert.equal(revealTimelock.outcome, 'pass');

  const safeRefund = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-009',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'buyer',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    lock: makeLock('2026-05-28T06:00:00Z'),
    refund: makeRefund('2026-05-28T06:00:00Z', '2026-05-28T06:05:00Z'),
    settledAt: '2026-05-28T06:06:00Z',
  });
  const refundResult = verifyHtlcSettlementEvidence(safeRefund);
  assert.equal(refundResult.decision, 'pass', JSON.stringify(refundResult.checks, null, 2));
  const refundTimelock = refundResult.checks.find(c => c.check === 'timelock-asymmetry');
  assert.ok(refundTimelock);
  assert.equal(refundTimelock.outcome, 'pass');
});

test('negative settlement amount → verify FAIL on price-positive (contradictory value)', () => {
  // A validly-signed settled evidence whose settled price.amount is negative. A negative
  // HTLC settlement moves negative value — contradictory. Constructed like the other
  // fail-closed vectors (signUnsigned), so the signature itself verifies and the
  // price-positive check is the load-bearing rejection.
  const { privKey, pubKey } = generateKeypair();
  const NEG_PRICE: PriceTerm = { amount: '-1.500000', asset: 'USDC', decimals: 6 };
  const unsigned = {
    v: 'dacs-4-settlement-evidence:0.1', jobId: 'job-htlc-neg-amount-1', method: 'htlc',
    rail: RailAvailability.Mocked, price: NEG_PRICE, settler: 'seller',
    settlerPubkey: bytesToHex(pubKey),
    outcome: 'settled',
    txRefs: [
      makeLock('2026-05-28T06:00:00Z'),
      makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    ], settledAt: '2026-05-28T05:01:00Z',
  };
  const result = verifyHtlcSettlementEvidence(signUnsigned(unsigned, privKey), pubKey);
  assert.equal(result.decision, 'fail', JSON.stringify(result.checks, null, 2));
  const pp = result.checks.find(c => c.check === 'price-positive');
  assert.ok(pp && pp.outcome === 'fail', 'expected price-positive to fail on a negative settlement amount');
  assert.match(pp.detail, /positive/);
});

test('zero settlement amount → verify FAIL on price-positive (settles no value)', () => {
  const { privKey, pubKey } = generateKeypair();
  const ZERO_PRICE: PriceTerm = { amount: '0.000000', asset: 'USDC', decimals: 6 };
  const unsigned = {
    v: 'dacs-4-settlement-evidence:0.1', jobId: 'job-htlc-zero-amount-1', method: 'htlc',
    rail: RailAvailability.Mocked, price: ZERO_PRICE, settler: 'seller',
    settlerPubkey: bytesToHex(pubKey),
    outcome: 'settled',
    txRefs: [
      makeLock('2026-05-28T06:00:00Z'),
      makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    ], settledAt: '2026-05-28T05:01:00Z',
  };
  const result = verifyHtlcSettlementEvidence(signUnsigned(unsigned, privKey), pubKey);
  assert.equal(result.decision, 'fail', JSON.stringify(result.checks, null, 2));
  const pp = result.checks.find(c => c.check === 'price-positive');
  assert.ok(pp && pp.outcome === 'fail', 'expected price-positive to fail on a zero settlement amount');
  assert.match(pp.detail, /positive/);
});

test('canonical price — a non-canonical amount fails the finding-#27 check', () => {
  const { privKey, pubKey } = generateKeypair();
  const evidence = buildHtlcSettlementEvidence({
    jobId: 'job-htlc-005',
    rail: RailAvailability.Mocked,
    price: PRICE,
    settler: 'seller',
    settlerPrivKey: privKey,
    settlerPubkey: pubKey,
    lock: makeLock('2026-05-28T06:00:00Z'),
    reveal: makeReveal('2026-05-28T05:00:00Z', '2026-05-28T04:30:00Z'),
    settledAt: '2026-05-28T05:01:00Z',
  });

  // Force a non-canonical amount post-build (e.g. "1.5" where decimals=6 wants "1.500000").
  // Re-signing is not done, so the signature will ALSO fail — but we assert the price check
  // specifically catches the non-canonical form.
  const mutated = structuredClone(evidence);
  mutated.price = { amount: '1.5', asset: 'USDC', decimals: 6 };

  const result = verifyHtlcSettlementEvidence(mutated);
  assert.equal(result.decision, 'fail');
  const priceCheck = result.checks.find(c => c.check === 'price-canonical');
  assert.ok(priceCheck);
  assert.equal(priceCheck.outcome, 'fail');
});
