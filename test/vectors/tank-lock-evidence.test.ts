/**
 * Liquidity-tank LOCK verifier — conformance vectors.
 *
 * Drop-in fixtures a CORRECT verifier MUST reject (and the ones it MUST accept).
 * Locks in the negative-evidence guarantees for a tank lock:
 *   - valid locked (confirmed deposit + majority AUTHORIZED sigs)      → PASS
 *   - partial-release within the locked ceiling                        → PASS
 *   - partial-release exceeding the locked amount                      → FAIL
 *   - deposit not confirmed                                            → FAIL
 *   - sub-quorum                                                       → FAIL
 *   - attacker generates N fresh keys (non-members of the shard set)   → FAIL
 *   - omitted authorizedShardSet                                       → INDETERMINATE
 *
 * Trust anchor: only signatures from MEMBER shards count toward quorum (a producer
 * cannot self-declare its signers as shards). Omitting the authorized set cannot
 * reach a PASS — it is indeterminate.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  verifyTankLock,
  buildTankLockCommitment,
  signTankLockCommitment,
  type TankLockEvidence,
} from '../../src/lib/tank-lock-evidence.js';
import {
  type ShardSignature,
  type SourceChainDepositProof,
} from '../../src/lib/settlement-evidence-verifier.js';
import { type PriceTerm } from '../../src/types/settle.js';

const AMOUNT: PriceTerm = { amount: '100.000000', asset: 'USDC', decimals: 6 };
const BRIDGE_ID = 'bridge:demos<->eip155:8453:v1';

const SHARD_SET_SIZE = 5;
const REQUIRED_QUORUM = 3;

function makeConfirmedDeposit(overrides: Partial<SourceChainDepositProof> = {}): SourceChainDepositProof {
  return {
    deposit_id: 'eip155:8453:0xdep0001:0',
    source_chain: 'eip155:8453',
    deposit_tx: '0xdep0001',
    bridge_id: BRIDGE_ID,
    amount: AMOUNT,
    confirmed: true,
    confirmations: 32,
    requiredConfirmations: 12,
    depositor: '0xdepositorAlice',
    observedAt: '2026-05-30T00:00:00Z',
    confirmedAt: '2026-05-30T00:10:00Z',
    ...overrides,
  };
}

function makeEvidence(overrides: Partial<TankLockEvidence> = {}): TankLockEvidence {
  return {
    v: 'dacs-tank-lock-evidence:0.1',
    jobId: 'job-tank-001',
    bridge_id: BRIDGE_ID,
    amount: AMOUNT,
    lockState: 'locked',
    lockExpiry: '2026-05-31T00:00:00Z',
    source_chain_deposit_proof: makeConfirmedDeposit(),
    shard_quorum_signatures: [],
    ...overrides,
  };
}

/** Sign the evidence commitment with `count` fresh distinct keypairs; return sigs + signer hexes. */
function signWithKeys(
  evidence: TankLockEvidence,
  count: number
): { sigs: ShardSignature[]; signerHexes: string[] } {
  const commitment = buildTankLockCommitment(evidence);
  const sigs: ShardSignature[] = [];
  const signerHexes: string[] = [];
  for (let i = 0; i < count; i++) {
    const { privKey, pubKey } = generateKeypair();
    sigs.push(signTankLockCommitment(commitment, privKey, pubKey));
    signerHexes.push(bytesToHex(pubKey));
  }
  return { sigs, signerHexes };
}

test('valid locked — confirmed deposit + majority (3-of-5) AUTHORIZED sigs → PASS', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('partial-release within ceiling → PASS', () => {
  const evidence = makeEvidence({
    lockState: 'partially_released',
    releasedAmount: { amount: '40.000000', asset: 'USDC', decimals: 6 },
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('partial-release exceeding amount → FAIL', () => {
  const evidence = makeEvidence({
    lockState: 'partially_released',
    releasedAmount: { amount: '120.000000', asset: 'USDC', decimals: 6 },
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /exceeds locked amount/);
});

test('deposit not confirmed → FAIL', () => {
  const evidence = makeEvidence({
    source_chain_deposit_proof: makeConfirmedDeposit({ confirmed: false, confirmedAt: undefined }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /not confirmed/);
});

test('sub-quorum (2-of-5) → FAIL', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, 2);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /sub-quorum/);
});

test('attacker generates N fresh keys (non-members) → FAIL', () => {
  const evidence = makeEvidence();
  // Attacker mints a full quorum of VALID signatures from fresh keys...
  const { sigs } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // ...but the authorized shard set is a DISJOINT set of real shards. The attacker's
  // valid signatures are non-members and do NOT count toward quorum.
  const realShards = Array.from({ length: SHARD_SET_SIZE }, () => bytesToHex(generateKeypair().pubKey));

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: realShards,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /sub-quorum/);
  assert.match(result.reason, /non-members/);
});

test('negative tank amount → FAIL (rejected before deposit/ceiling compare)', () => {
  // A negative amount that also "matches" a negative deposit-proof amount would pass
  // the equality check — the reject-first positive-amount guard must catch it first.
  const NEG: PriceTerm = { amount: '-100.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: NEG,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: NEG }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /tank amount must be a positive value/);
});

test('zero tank amount → FAIL', () => {
  const ZERO: PriceTerm = { amount: '0.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: ZERO,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: ZERO }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /tank amount must be a positive value/);
});

test('partial-release with releasedAmount = -1 → FAIL (distinct from exceeds-ceiling)', () => {
  // A negative releasedAmount trivially passes the "<= amount" ceiling, so it must be
  // rejected by its own non-negative guard — NOT by the exceeds-ceiling check.
  const evidence = makeEvidence({
    lockState: 'partially_released',
    releasedAmount: { amount: '-1.000000', asset: 'USDC', decimals: 6 },
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /releasedAmount must be >= 0/);
  assert.doesNotMatch(result.reason, /exceeds locked amount/);
});

test('omitted authorizedShardSet → INDETERMINATE (never PASS)', () => {
  const evidence = makeEvidence();
  const { sigs } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyTankLock(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    // authorizedShardSet intentionally omitted
  });
  assert.equal(result.decision, 'indeterminate', result.reason);
  assert.equal(result.ok, false);
});
