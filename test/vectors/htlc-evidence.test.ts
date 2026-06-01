/**
 * DACS-4 Settle — HTLC SettlementEvidence vectors
 *
 * Locks in:
 *   - round-trip: build (settled, lock+reveal) → verify PASS
 *   - tamper: mutate a txHash AFTER signing → verify FAIL (signature breaks)
 *   - refund path: build (refunded, lock+refund) → verify PASS
 *   - timelock-asymmetry: reveal at/after source timelock is rejected at build time
 *   - canonical price: a non-canonical amount fails the finding-#27 check
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex, hexToBytes } from '../../src/lib/verify-bundle.js';
import {
  buildHtlcSettlementEvidence,
  verifyHtlcSettlementEvidence,
} from '../../src/lib/htlc-evidence.js';
import {
  RailAvailability,
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
