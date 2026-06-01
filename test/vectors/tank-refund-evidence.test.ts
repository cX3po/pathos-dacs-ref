/**
 * Liquidity-tank REFUND verifier — conformance vectors.
 *
 * Drop-in fixtures a CORRECT verifier MUST reject (and the one it MUST accept).
 * Defines what a CORRECT refund proves, locking in:
 *   - valid refund after expiry (confirmed deposit + at/after lockExpiry +
 *     recipient == depositor + not-consumed + majority AUTHORIZED sigs)  → PASS
 *   - refund before expiry                                               → FAIL
 *   - refund of an already-consumed (released) deposit                   → FAIL
 *   - sub-quorum                                                         → FAIL
 *   - omitted authoritative consumed ledger                              → INDETERMINATE
 *   - refundRecipient != original depositor                              → FAIL
 *
 * Two AUTHORITATIVE trust anchors (verifier-supplied, never from the evidence):
 *   - consumedDepositLedger (REQUIRED — its absence cannot reach a PASS)
 *   - authorizedShardSet (only member-shard signatures count toward quorum)
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  verifyTankRefund,
  buildTankRefundCommitment,
  signTankRefundCommitment,
  type TankRefundEvidence,
} from '../../src/lib/tank-refund-evidence.js';
import {
  type ShardSignature,
  type SourceChainDepositProof,
} from '../../src/lib/settlement-evidence-verifier.js';
import { type PriceTerm } from '../../src/types/settle.js';

const AMOUNT: PriceTerm = { amount: '100.000000', asset: 'USDC', decimals: 6 };
const BRIDGE_ID = 'bridge:demos<->eip155:8453:v1';
const DEPOSITOR = '0xdepositorAlice';
const DEPOSIT_ID = 'eip155:8453:0xdep0001:0';

const SHARD_SET_SIZE = 5;
const REQUIRED_QUORUM = 3;

const LOCK_EXPIRY = '2026-05-31T00:00:00Z';
const AFTER_EXPIRY = '2026-05-31T01:00:00Z';
const BEFORE_EXPIRY = '2026-05-30T23:00:00Z';

function makeConfirmedDeposit(overrides: Partial<SourceChainDepositProof> = {}): SourceChainDepositProof {
  return {
    deposit_id: DEPOSIT_ID,
    source_chain: 'eip155:8453',
    deposit_tx: '0xdep0001',
    bridge_id: BRIDGE_ID,
    amount: AMOUNT,
    confirmed: true,
    confirmations: 32,
    requiredConfirmations: 12,
    depositor: DEPOSITOR,
    observedAt: '2026-05-30T00:00:00Z',
    confirmedAt: '2026-05-30T00:10:00Z',
    ...overrides,
  };
}

function makeEvidence(overrides: Partial<TankRefundEvidence> = {}): TankRefundEvidence {
  return {
    v: 'dacs-tank-refund-evidence:0.1',
    jobId: 'job-tank-refund-001',
    bridge_id: BRIDGE_ID,
    amount: AMOUNT,
    refundRecipient: DEPOSITOR,
    source_chain_deposit_proof: makeConfirmedDeposit(),
    lockExpiry: LOCK_EXPIRY,
    refundedAfter: AFTER_EXPIRY,
    refund_tx: { chain: 'eip155:8453', txHash: '0xrefund0001' },
    shard_quorum_signatures: [],
    ...overrides,
  };
}

/** Sign the evidence commitment with `count` fresh distinct keypairs; return sigs + signer hexes. */
function signWithKeys(
  evidence: TankRefundEvidence,
  count: number
): { sigs: ShardSignature[]; signerHexes: string[] } {
  const commitment = buildTankRefundCommitment(evidence);
  const sigs: ShardSignature[] = [];
  const signerHexes: string[] = [];
  for (let i = 0; i < count; i++) {
    const { privKey, pubKey } = generateKeypair();
    sigs.push(signTankRefundCommitment(commitment, privKey, pubKey));
    signerHexes.push(bytesToHex(pubKey));
  }
  return { sigs, signerHexes };
}

test('valid refund after expiry → PASS', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('refund before expiry → FAIL', () => {
  const evidence = makeEvidence({ refundedAfter: BEFORE_EXPIRY });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /refund-before-expiry/);
});

test('refund of already-consumed (released) deposit → FAIL', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    // the deposit was ALREADY released — refunding it would double-pay
    consumedDepositLedger: [DEPOSIT_ID],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /double-pay/);
});

test('sub-quorum (2-of-5) → FAIL', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, 2);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /sub-quorum/);
});

test('omitted consumedDepositLedger → INDETERMINATE (never PASS)', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    // consumedDepositLedger intentionally omitted
  });
  assert.equal(result.decision, 'indeterminate', result.reason);
  assert.equal(result.ok, false);
});

test('negative refund amount → FAIL (rejected before deposit/equality compare)', () => {
  // A negative amount that also "matches" a negative deposit-proof amount would pass
  // the equality check — the reject-first positive-amount guard must catch it first.
  const NEG: PriceTerm = { amount: '-100.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: NEG,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: NEG }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /refund amount must be a positive value/);
});

test('zero refund amount → FAIL', () => {
  const ZERO: PriceTerm = { amount: '0.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: ZERO,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: ZERO }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /refund amount must be a positive value/);
});

test('refundRecipient != original depositor → FAIL', () => {
  const evidence = makeEvidence({ refundRecipient: '0xattackerMallory' });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankRefund(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /does not equal the deposit's original depositor/);
});
