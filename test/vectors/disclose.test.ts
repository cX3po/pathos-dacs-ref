/**
 * dacs-disclose — conformance vectors + adversarial tests (spec §3 / §5 P1).
 *
 * Drop-in fixtures a CORRECT selective-disclosure verifier MUST accept / reject. Locks in
 * the §3 guarantees:
 *   - happy path: reveal verifies (membership + audience + freshness + signature)   → PASS
 *   - wrong salt opening the commitment                                             → FAIL
 *   - forged/tampered commitment (not a member of the signed root)                  → FAIL
 *   - tampered claim (plaintext changed after commitment)                           → FAIL
 *   - missing claim (commitment not in the set)                                     → FAIL
 *   - reveal replayed to a DIFFERENT verifier_id (non-transferable)                 → FAIL
 *   - expired reveal (outside freshness window)                                     → FAIL
 *   - reused / wrong nonce (non-replayable)                                         → FAIL
 *   - consent-scope mismatch                                                        → FAIL
 *   - Merkle membership round-trips for EVERY leaf in a multi-claim set             → PASS
 *
 * Crypto-critical invariant (Codex HIGH): a captured reveal is bound to its audience +
 * challenge, so it is non-replayable and non-transferable. The "different verifier_id" and
 * "wrong nonce" tests are the teeth on that.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  attestClaimCommitment,
  computeCommitment,
  computeCommitmentRoot,
  buildMerklePath,
  verifyMerklePath,
  produceReveal,
  verifyDisclosedClaim,
  MIN_SALT_BYTES,
  type ClaimCommitment,
  type RevealChallenge,
  type DisclosedClaim,
} from '../../src/lib/disclose.js';
import type { ClaimReference } from '../../src/types/identity.js';

/* ---------------------------------- fixtures -------------------------------- */

const CLAIM_LEI: ClaimReference = { scheme: 'lei', identifier: '549300ABCDEF12345678' };
const CLAIM_CRD: ClaimReference = { scheme: 'finra-crd', identifier: '1234567' };
const CLAIM_UEI: ClaimReference = { scheme: 'sam-uei', identifier: 'ABC123DEF456' };

// A future expiry so the freshness window is open at test-fixed `now`.
const NOW = 1_800_000_000_000;
const FUTURE = NOW + 60_000;

function freshChallenge(overrides: Partial<RevealChallenge> = {}): RevealChallenge {
  return {
    verifier_id: 'verifier:acme-marketplace',
    consent_receipt_id: 'receipt:consent-0001',
    nonce: 'nonce-deadbeef-0001',
    expiry: FUTURE,
    ...overrides,
  };
}

/**
 * Build a full disclosure scene: attester commits a SET of claims, holder gets the
 * commitment for ONE claim plus a Merkle path against the signed root, and produces an
 * audience-bound reveal. Returns everything a verifier needs.
 */
function scene(
  reveal: ClaimReference = CLAIM_LEI,
  setClaims: ClaimReference[] = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI],
  challenge: RevealChallenge = freshChallenge()
): {
  commitment: ClaimCommitment;
  root: string;
  disclosed: DisclosedClaim;
  presentationPubKeyHex: string;
} {
  // Attester produces a commitment per claim (CSPRNG salt, kept secret until reveal).
  const commitments = setClaims.map((c) => attestClaimCommitment(c, `verifiedBy:${c.scheme}`));
  const target = commitments.find((c) => c.claim.scheme === reveal.scheme && c.claim.identifier === reveal.identifier)!;
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, target.commitment);

  // Holder's presentation key (the bundle presentation key).
  const { privKey, pubKey } = generateKeypair();
  const disclosed = produceReveal(target, path, challenge, privKey);
  return { commitment: target, root, disclosed, presentationPubKeyHex: bytesToHex(pubKey) };
}

/* ------------------------------- happy path -------------------------------- */

test('happy path — reveal verifies (membership + audience + freshness + signature) → PASS', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
    now: NOW,
  });
  assert.equal(result.decision, 'pass', result.reason);
  assert.equal(result.ok, true);
});

test('attester salt discipline — salt is CSPRNG, >=128-bit, unique per claim', () => {
  const a = attestClaimCommitment(CLAIM_LEI);
  const b = attestClaimCommitment(CLAIM_LEI);
  // >=128-bit (default 256-bit = 64 hex chars)
  assert.ok(a.salt.length / 2 >= MIN_SALT_BYTES, 'salt below 128-bit floor');
  // unique per call even for the SAME claim
  assert.notEqual(a.salt, b.salt, 'salt reused across commitments');
  assert.notEqual(a.commitment, b.commitment, 'commitment collided across distinct salts');
});

test('attester rejects sub-128-bit salt length', () => {
  assert.throws(() => attestClaimCommitment(CLAIM_LEI, undefined, 8), /salt must be >=/);
});

test('Merkle membership round-trips for EVERY leaf in the set → PASS', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  for (const c of commitments) {
    const path = buildMerklePath(setHex, c.commitment);
    assert.ok(verifyMerklePath(c.commitment, path, root), `leaf ${c.claim.scheme} did not fold to root`);
  }
});

test('Merkle root is order-independent (same SET → same ROOT)', () => {
  const cs = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI].map((c) => attestClaimCommitment(c));
  const hexes = cs.map((c) => c.commitment);
  const r1 = computeCommitmentRoot(hexes);
  const r2 = computeCommitmentRoot([hexes[2]!, hexes[0]!, hexes[1]!]);
  assert.equal(r1, r2, 'root depends on input order — membership would not be stable');
});

test('single-claim set: root membership still verifies', () => {
  const { root, disclosed, presentationPubKeyHex } = scene(CLAIM_LEI, [CLAIM_LEI]);
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'pass', result.reason);
});

/* --------------------------- adversarial: opening -------------------------- */

test('wrong salt opening the commitment → FAIL (membership)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  // Swap the salt for a different (valid-length) one — commitment no longer matches.
  const tampered: DisclosedClaim = { ...disclosed, salt: bytesToHex(new Uint8Array(32).fill(7)) };
  const result = verifyDisclosedClaim(tampered, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /membership failure/);
});

test('tampered claim (plaintext changed after commitment) → FAIL', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  // Holder swaps the revealed claim identifier but keeps the original salt+path.
  const tampered: DisclosedClaim = {
    ...disclosed,
    claim: { scheme: 'lei', identifier: '000000000000FORGED00' },
  };
  const result = verifyDisclosedClaim(tampered, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /membership failure/);
});

test('forged commitment not in the signed set → FAIL (no valid path)', () => {
  const { presentationPubKeyHex } = scene();
  // Build a set that does NOT contain the holder's claim, then a different root.
  const otherSet = [CLAIM_CRD, CLAIM_UEI].map((c) => attestClaimCommitment(c));
  const otherRoot = computeCommitmentRoot(otherSet.map((c) => c.commitment));
  // Holder forges a commitment for a claim not in otherSet and fabricates a path.
  const forged = attestClaimCommitment(CLAIM_LEI);
  assert.throws(() => buildMerklePath(otherSet.map((c) => c.commitment), forged.commitment), /not a member/);
  // Even handing a bogus single-step path, membership fails against the real root.
  const disclosed: DisclosedClaim = {
    claim: forged.claim,
    salt: forged.salt,
    merkle_path: [{ sibling: bytesToHex(new Uint8Array(32).fill(9)), side: 'right' }],
    reveal_sig: bytesToHex(new Uint8Array(64)),
    challenge: freshChallenge(),
  };
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: otherRoot,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /membership failure/);
});

test('missing claim (commitment not in set) → FAIL & buildMerklePath throws', () => {
  const setHex = [CLAIM_CRD, CLAIM_UEI].map((c) => computeCommitment(attestClaimCommitment(c).salt, c));
  const missing = attestClaimCommitment(CLAIM_LEI);
  assert.throws(() => buildMerklePath(setHex, missing.commitment), /not a member/);
});

/* ----------------------- adversarial: audience binding --------------------- */

test('reveal replayed to a DIFFERENT verifier_id → FAIL (non-transferable)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  // The reveal was minted for "acme-marketplace"; a different verifier captures it.
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: 'verifier:evil-relay', // NOT the audience the reveal was bound to
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /audience mismatch/);
});

test('reused / wrong nonce → FAIL (non-replayable)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: 'nonce-a-DIFFERENT-fresh-challenge', // verifier issued a new nonce
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /nonce mismatch/);
});

test('consent-scope mismatch → FAIL', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    expectedConsentReceiptId: 'receipt:some-other-consent',
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent-scope mismatch/);
});

/* ----------------------- adversarial: freshness ---------------------------- */

test('expired reveal → FAIL', () => {
  const { root, disclosed, presentationPubKeyHex } = scene(CLAIM_LEI, undefined, freshChallenge({ expiry: NOW - 1 }));
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /expired/);
});

test('reveal exactly at expiry → FAIL (expiry is exclusive upper bound)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene(CLAIM_LEI, undefined, freshChallenge({ expiry: NOW }));
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /expired/);
});

/* ----------------------- adversarial: signature ---------------------------- */

test('reveal_sig signed by a NON-holder key → FAIL', () => {
  const { commitment, root } = scene();
  const setHex = [commitment.commitment, attestClaimCommitment(CLAIM_CRD).commitment];
  // Rebuild a 2-leaf set containing the real commitment so membership can pass...
  const root2 = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, commitment.commitment);
  // ...but sign the reveal with an ATTACKER key, while the verifier expects the holder key.
  const attacker = generateKeypair();
  const holder = generateKeypair();
  const challenge = freshChallenge();
  const disclosed = produceReveal(commitment, path, challenge, attacker.privKey);
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root2,
    presentationPubKey: bytesToHex(holder.pubKey), // holder key, not attacker's
    expectedVerifierId: challenge.verifier_id,
    expectedNonce: challenge.nonce,
    now: NOW,
  });
  void root;
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /reveal_sig does not verify/);
});

test('tampered reveal_sig bits → FAIL', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  const sigBytes = Buffer.from(disclosed.reveal_sig, 'hex');
  sigBytes[0]! ^= 0xff;
  const tampered: DisclosedClaim = { ...disclosed, reveal_sig: sigBytes.toString('hex') };
  const result = verifyDisclosedClaim(tampered, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /reveal_sig does not verify/);
});

test('reveal bound to a DIFFERENT nonce cannot be re-signed for a new challenge (signature covers nonce)', () => {
  // Prove the nonce is INSIDE the signed preimage: take a valid reveal, then swap the
  // challenge nonce in the artifact while keeping the original signature. Even if the
  // verifier's expectedNonce matched the SWAPPED nonce, the signature would not verify.
  const { root, disclosed, presentationPubKeyHex } = scene();
  const swapped: DisclosedClaim = {
    ...disclosed,
    challenge: { ...disclosed.challenge, nonce: 'nonce-swapped-by-attacker' },
  };
  const result = verifyDisclosedClaim(swapped, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: 'nonce-swapped-by-attacker', // matches the swapped artifact value
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /reveal_sig does not verify/);
});

/* ----------------------- adversarial: malformed inputs --------------------- */

test('sub-128-bit salt on the reveal path → FAIL', () => {
  const { disclosed, root, presentationPubKeyHex } = scene();
  const shortSalt: DisclosedClaim = { ...disclosed, salt: bytesToHex(new Uint8Array(8).fill(1)) };
  const result = verifyDisclosedClaim(shortSalt, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /salt too short/);
});

test('malformed presentationPubKey → FAIL', () => {
  const { root, disclosed } = scene();
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: 'not-hex-zz',
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /malformed presentationPubKey/);
});

test('empty commitment set → computeCommitmentRoot throws', () => {
  assert.throws(() => computeCommitmentRoot([]), /empty commitment set/);
});
