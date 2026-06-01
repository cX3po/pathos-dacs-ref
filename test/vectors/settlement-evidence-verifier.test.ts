/**
 * Negative-evidence bridge-release verifier — conformance vectors
 *
 * These are drop-in fixtures a CORRECT verifier MUST reject (and one it MUST
 * accept). They are the two yellowpaper guarantees the v0.2 escrow code skips:
 *   (a) a confirmed source-chain deposit that binds to bridge_id + amount
 *   (b) a MAJORITY-of-shard signature set (>= requiredQuorum distinct valid signers)
 *
 * Locks in:
 *   - single-signer release (sub-quorum)        → FAIL
 *   - release without a confirmed deposit        → FAIL
 *   - double-confirm same bridge_id (deposit reuse) → FAIL
 *   - expire-then-confirm race                   → FAIL
 *   - valid (confirmed deposit + majority sigs)  → PASS
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import {
  verifyBridgeRelease,
  buildReleaseCommitment,
  signReleaseCommitment,
  type BridgeReleaseEvidence,
  type ShardSignature,
  type SourceChainDepositProof,
} from '../../src/lib/settlement-evidence-verifier.js';
import { type PriceTerm } from '../../src/types/settle.js';

const AMOUNT: PriceTerm = { amount: '100.000000', asset: 'USDC', decimals: 6 };
const BRIDGE_ID = 'bridge:demos<->eip155:8453:v1';

/** A 3-of-5 bridge shard set — majority = 3. */
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
    observedAt: '2026-05-30T00:00:00Z',
    confirmedAt: '2026-05-30T00:10:00Z',
    depositWindowExpiry: '2026-05-31T00:00:00Z',
    ...overrides,
  };
}

function makeEvidence(overrides: Partial<BridgeReleaseEvidence> = {}): BridgeReleaseEvidence {
  return {
    v: 'pathos-bridge-release-evidence:0.1',
    jobId: 'job-bridge-001',
    bridge_id: BRIDGE_ID,
    amount: AMOUNT,
    source_chain_deposit_proof: makeConfirmedDeposit(),
    shard_quorum_signatures: [],
    release_tx: {
      dest_chain: 'demos',
      release_tx: '0xrel0001',
      recipient: 'demo1recipientaddress',
      releasedAt: '2026-05-30T00:15:00Z',
    },
    ...overrides,
  };
}

/** Sign `evidence`'s commitment with `count` fresh distinct shard keypairs. */
function signWith(evidence: BridgeReleaseEvidence, count: number): ShardSignature[] {
  const commitment = buildReleaseCommitment(evidence);
  const sigs: ShardSignature[] = [];
  for (let i = 0; i < count; i++) {
    const { privKey, pubKey } = generateKeypair();
    sigs.push(signReleaseCommitment(commitment, privKey, pubKey));
  }
  return sigs;
}

test('valid — confirmed deposit + majority (3-of-5) distinct valid sigs → PASS', () => {
  const evidence = makeEvidence();
  evidence.shard_quorum_signatures = signWith(evidence, REQUIRED_QUORUM);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('single-signer release (sub-quorum) → FAIL', () => {
  const evidence = makeEvidence();
  // Only ONE shard signs where 3 are required.
  evidence.shard_quorum_signatures = signWith(evidence, 1);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.equal(result.ok, false);
  assert.match(result.reason, /sub-quorum/);
});

test('sub-quorum-by-duplication — same signer signing 3× counts once → FAIL', () => {
  const evidence = makeEvidence();
  const commitment = buildReleaseCommitment(evidence);
  const { privKey, pubKey } = generateKeypair();
  const one = signReleaseCommitment(commitment, privKey, pubKey);
  // Same valid signer repeated to fake a quorum.
  evidence.shard_quorum_signatures = [one, { ...one }, { ...one }];

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail', 'duplicate signer must not satisfy a 3-of-5 majority');
  assert.match(result.reason, /sub-quorum/);
});

test('release without a confirmed deposit → FAIL', () => {
  const evidence = makeEvidence({
    source_chain_deposit_proof: makeConfirmedDeposit({ confirmed: false, confirmedAt: undefined }),
  });
  // Even with a full majority of valid sigs, an unconfirmed deposit must reject.
  evidence.shard_quorum_signatures = signWith(evidence, REQUIRED_QUORUM);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /not confirmed/);
});

test('double-confirm same bridge_id (deposit already consumed) → FAIL', () => {
  const evidence = makeEvidence();
  evidence.shard_quorum_signatures = signWith(evidence, REQUIRED_QUORUM);
  // The deposit backing this release was already consumed by a prior release on this bridge.
  evidence.consumedDepositLedger = [evidence.source_chain_deposit_proof.deposit_id];

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /double-confirm|double-spend|consumed/);
});

test('expire-then-confirm race — confirmation lands after deposit window closes → FAIL', () => {
  const evidence = makeEvidence({
    source_chain_deposit_proof: makeConfirmedDeposit({
      // window closes at 00:00, confirmation lands at 00:30 — refund-eligible race.
      depositWindowExpiry: '2026-05-31T00:00:00Z',
      confirmedAt: '2026-05-31T00:30:00Z',
    }),
  });
  evidence.shard_quorum_signatures = signWith(evidence, REQUIRED_QUORUM);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /expire-then-confirm|refund-eligible/);
});

test('binding — deposit amount mismatch (cheaper deposit, larger payout) → FAIL', () => {
  const evidence = makeEvidence({
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: { amount: '1.000000', asset: 'USDC', decimals: 6 } }),
  });
  evidence.shard_quorum_signatures = signWith(evidence, REQUIRED_QUORUM);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /amount/);
});

test('binding — signatures over a DIFFERENT commitment do not count (replay protection) → FAIL', () => {
  const evidence = makeEvidence();
  // Sign a commitment for a DIFFERENT release_tx, then attach to this evidence.
  const otherEvidence = makeEvidence({ release_tx: { ...evidence.release_tx, release_tx: '0xOTHER' } });
  evidence.shard_quorum_signatures = signWith(otherEvidence, REQUIRED_QUORUM);

  const result = verifyBridgeRelease(evidence, { requiredQuorum: REQUIRED_QUORUM, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail', 'signatures bound to another release must not authorise this one');
  assert.match(result.reason, /sub-quorum/);
});

test('config — requiredQuorum below true majority of shardSetSize is rejected', () => {
  const evidence = makeEvidence();
  evidence.shard_quorum_signatures = signWith(evidence, 2);
  // 2 is NOT a majority of 5 (need >= 3).
  const result = verifyBridgeRelease(evidence, { requiredQuorum: 2, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /majority/);
});
