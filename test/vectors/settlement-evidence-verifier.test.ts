/**
 * Negative-evidence bridge-release verifier — conformance vectors
 *
 * These are drop-in fixtures a CORRECT verifier MUST reject (and one it MUST
 * accept). They are the two yellowpaper guarantees the v0.2 escrow code skips:
 *   (a) a confirmed source-chain deposit that binds to bridge_id + amount
 *   (b) a MAJORITY-of-shard signature set (>= requiredQuorum distinct valid signers
 *       that are MEMBERS of the AUTHORIZED shard set)
 *
 * Locks in:
 *   - single-signer release (sub-quorum)        → FAIL
 *   - release without a confirmed deposit        → FAIL
 *   - double-confirm same bridge_id (deposit reuse, AUTHORITATIVE ledger) → FAIL
 *   - omitted authoritative ledger               → INDETERMINATE (never PASS)
 *   - omitted authorized shard set               → INDETERMINATE (never PASS)
 *   - attacker generates N fresh keys (not shards) → FAIL (non-members don't count)
 *   - expire-then-confirm race                   → FAIL
 *   - valid (confirmed deposit + majority sigs from AUTHORIZED shards) → PASS
 *
 * Two trust anchors are AUTHORITATIVE (verifier-supplied via options), NOT read
 * from the evidence object:
 *   - the consumed-deposit ledger (an empty `consumedDepositLedger: []` means
 *     "ledger known, deposit not consumed"); omitting it cannot reach a PASS.
 *   - the authorized shard set (`authorizedShardSet`): only signatures from MEMBER
 *     shards count toward quorum. A producer cannot self-declare its signers as
 *     shards, so omitting the set cannot reach a PASS either. This defeats the
 *     forge-N-fresh-keys attack — a valid signature is not an authorised one.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
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

/**
 * Sign `evidence`'s commitment with `count` fresh distinct shard keypairs, returning
 * BOTH the signatures and the signer pubkey hexes (so a test can register them as the
 * authorized shard set). The keys are "real shards" only because the caller chooses to
 * authorize them — an attacker case withholds them from the authorized set instead.
 */
function signWithKeys(
  evidence: BridgeReleaseEvidence,
  count: number
): { sigs: ShardSignature[]; signerHexes: string[] } {
  const commitment = buildReleaseCommitment(evidence);
  const sigs: ShardSignature[] = [];
  const signerHexes: string[] = [];
  for (let i = 0; i < count; i++) {
    const { privKey, pubKey } = generateKeypair();
    sigs.push(signReleaseCommitment(commitment, privKey, pubKey));
    signerHexes.push(bytesToHex(pubKey));
  }
  return { sigs, signerHexes };
}

/** Back-compat thin wrapper: just the signatures (caller supplies the authorized set separately). */
function signWith(evidence: BridgeReleaseEvidence, count: number): ShardSignature[] {
  return signWithKeys(evidence, count).sigs;
}

test('valid — confirmed deposit + majority (3-of-5) distinct AUTHORIZED sigs → PASS', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // Both trust anchors supplied: empty consumed ledger (deposit not consumed) AND the
  // authorized shard set (these three signers ARE the registered shards). Without
  // either the verdict is indeterminate — see the dedicated tests below.
  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('single-signer release (sub-quorum) → FAIL', () => {
  const evidence = makeEvidence();
  // Only ONE shard signs where 3 are required.
  const { sigs, signerHexes } = signWithKeys(evidence, 1);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail');
  assert.equal(result.ok, false);
  assert.match(result.reason, /sub-quorum/);
});

test('sub-quorum-by-duplication — same authorized signer signing 3× counts once → FAIL', () => {
  const evidence = makeEvidence();
  const commitment = buildReleaseCommitment(evidence);
  const { privKey, pubKey } = generateKeypair();
  const one = signReleaseCommitment(commitment, privKey, pubKey);
  // Same valid AUTHORIZED signer repeated to fake a quorum.
  evidence.shard_quorum_signatures = [one, { ...one }, { ...one }];

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: [bytesToHex(pubKey)],
  });
  assert.equal(result.decision, 'fail', 'duplicate signer must not satisfy a 3-of-5 majority');
  assert.match(result.reason, /sub-quorum/);
});

test('attacker generates N fresh keys (NOT authorized shards) → FAIL (non-members do not count)', () => {
  // The exact Codex-flagged attack: an attacker who is NOT a bridge shard mints
  // requiredQuorum fresh keypairs and signs the REAL commitment with each. Every
  // signature verifies cryptographically — but NONE belong to the authorized shard
  // set, so the verifier MUST count zero toward quorum and FAIL.
  const evidence = makeEvidence();
  const { sigs } = signWithKeys(evidence, REQUIRED_QUORUM); // attacker keys, NOT registered
  evidence.shard_quorum_signatures = sigs;

  // The authorized shard set is some OTHER (legitimate) set the attacker doesn't hold.
  const { signerHexes: realShardHexes } = signWithKeys(makeEvidence(), SHARD_SET_SIZE);

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: realShardHexes,
  });
  assert.equal(result.decision, 'fail', 'fresh non-member keys must not satisfy quorum');
  assert.equal(result.ok, false);
  assert.match(result.reason, /sub-quorum/);
  // The reason should make clear the valid-but-unauthorized signatures were rejected.
  assert.match(result.reason, /non-member|authorized/);
});

test('partial-authorization — 2 authorized + 1 attacker key (quorum 3) → FAIL (attacker key does not top up)', () => {
  // Two genuine shards sign; an attacker adds one fresh non-member key to reach the
  // raw count of 3. Only the 2 authorized signers count → sub-quorum.
  const evidence = makeEvidence();
  const commitment = buildReleaseCommitment(evidence);
  const authorizedHexes: string[] = [];
  const sigs: ShardSignature[] = [];
  for (let i = 0; i < 2; i++) {
    const { privKey, pubKey } = generateKeypair();
    sigs.push(signReleaseCommitment(commitment, privKey, pubKey));
    authorizedHexes.push(bytesToHex(pubKey));
  }
  // Attacker's fresh key — valid signature, NOT in the authorized set.
  const attacker = generateKeypair();
  sigs.push(signReleaseCommitment(commitment, attacker.privKey, attacker.pubKey));
  // Authorized set is the two real shards plus three other registered shards the
  // attacker doesn't control (a true 5-shard set), so requiredQuorum=3 is a majority.
  for (let i = 0; i < 3; i++) authorizedHexes.push(bytesToHex(generateKeypair().pubKey));
  evidence.shard_quorum_signatures = sigs;

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: authorizedHexes,
  });
  assert.equal(result.decision, 'fail', 'only 2 of 3 signers are authorized shards → sub-quorum');
  assert.match(result.reason, /sub-quorum/);
});

test('omitted authorized shard set — majority-of-shard unprovable → INDETERMINATE (not PASS)', () => {
  const evidence = makeEvidence();
  const { sigs } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // Ledger supplied but NO authorizedShardSet: the verifier cannot establish that the
  // signers are registered shards, so it MUST NOT coerce to 'pass' (§7.5.1).
  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
  });
  assert.equal(result.decision, 'indeterminate', result.reason);
  assert.equal(result.ok, false);
  assert.match(result.reason, /authorizedShardSet|shard/);
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

test('double-confirm same bridge_id (deposit already in AUTHORITATIVE ledger) → FAIL', () => {
  const evidence = makeEvidence();
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // The deposit backing this release was already consumed by a prior release on this
  // bridge. The replayed deposit_id is in the AUTHORITATIVE (verifier-supplied) ledger
  // — NOT on the evidence object, which a malicious producer would simply omit.
  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [evidence.source_chain_deposit_proof.deposit_id],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /double-confirm|double-spend|consumed/);
});

test('omitted authoritative ledger — double-spend guarantee unprovable → INDETERMINATE (not PASS)', () => {
  const evidence = makeEvidence();
  // A fully valid release in every other respect (confirmed deposit + majority sigs).
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // No authoritative consumedDepositLedger supplied (but the shard set IS supplied, so
  // the indeterminate verdict is attributable to the ledger, not the shard gate). The
  // verifier cannot assert the deposit was not already consumed → MUST NOT coerce to
  // 'pass' (§7.5.1).
  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'indeterminate', result.reason);
  assert.equal(result.ok, false);
  assert.match(result.reason, /authoritative|ledger/);

  // Sanity: the SAME evidence with an empty authoritative ledger passes — proving the
  // indeterminate verdict is caused solely by the omitted ledger, not another defect.
  const withLedger = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(withLedger.decision, 'pass', withLedger.reason);
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

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
  });
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
  const { sigs, signerHexes } = signWithKeys(otherEvidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  // Even though the signers ARE authorized shards, their signatures are over a
  // different commitment, so they do not verify against THIS release → sub-quorum.
  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', 'signatures bound to another release must not authorise this one');
  assert.match(result.reason, /sub-quorum/);
});

test('negative release amount → FAIL (matching negative deposit cannot pass equality)', () => {
  // Both the release amount AND the deposit-proof amount are equally negative, so the
  // priceEqual binding check would PASS — proving the positive-amount guard must run
  // first. A negative monetary release is contradictory value evidence.
  const NEG: PriceTerm = { amount: '-100.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: NEG,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: NEG }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.equal(result.ok, false);
  assert.match(result.reason, /positive/);
});

test('zero release amount → FAIL (a release of zero moves no value)', () => {
  const ZERO: PriceTerm = { amount: '0.000000', asset: 'USDC', decimals: 6 };
  const evidence = makeEvidence({
    amount: ZERO,
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: ZERO }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.equal(result.ok, false);
  assert.match(result.reason, /positive/);
});

test('negative deposit-proof amount (positive release) → FAIL on the deposit guard', () => {
  // Release amount is positive but the backing deposit amount is negative — the deposit
  // guard rejects before priceEqual (and the amounts wouldn't match anyway). Proves the
  // proof.amount guard is wired independently of the release-amount guard.
  const evidence = makeEvidence({
    source_chain_deposit_proof: makeConfirmedDeposit({ amount: { amount: '-100.000000', asset: 'USDC', decimals: 6 } }),
  });
  const { sigs, signerHexes } = signWithKeys(evidence, REQUIRED_QUORUM);
  evidence.shard_quorum_signatures = sigs;

  const result = verifyBridgeRelease(evidence, {
    requiredQuorum: REQUIRED_QUORUM,
    shardSetSize: SHARD_SET_SIZE,
    consumedDepositLedger: [],
    authorizedShardSet: signerHexes,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /deposit proof amount must be a positive value/);
});

test('config — requiredQuorum below true majority of shardSetSize is rejected', () => {
  const evidence = makeEvidence();
  evidence.shard_quorum_signatures = signWith(evidence, 2);
  // 2 is NOT a majority of 5 (need >= 3).
  const result = verifyBridgeRelease(evidence, { requiredQuorum: 2, shardSetSize: SHARD_SET_SIZE });
  assert.equal(result.decision, 'fail');
  assert.match(result.reason, /majority/);
});
