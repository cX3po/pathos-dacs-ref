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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id, // FIX 1: consent fail-closed
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
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
    expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /malformed presentationPubKey/);
});

test('empty commitment set → computeCommitmentRoot throws', () => {
  assert.throws(() => computeCommitmentRoot([]), /empty commitment set/);
});

/* ===========================================================================
 * FIX 1 — consent verification is FAIL-CLOSED by default (consent CORE).
 * Omitting consent on the default path is a hard error, never a silent skip.
 * The only skip is the LOUD, deliberate allowUnscopedConsent opt-out.
 * =========================================================================== */

test('FIX 1: omitting consent on the DEFAULT path → throws (fail-closed, not a silent pass)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  // No expectedConsentReceiptId, no allowUnscopedConsent → consent would otherwise be SKIPPED.
  // Must throw rather than silently verify without consent.
  assert.throws(
    () =>
      verifyDisclosedClaim(disclosed, {
        signedRoot: root,
        presentationPubKey: presentationPubKeyHex,
        expectedVerifierId: disclosed.challenge.verifier_id,
        expectedNonce: disclosed.challenge.nonce,
        now: NOW,
      }),
    /consent verification is REQUIRED/
  );
});

test('FIX 1: supplying BOTH consent id AND allowUnscopedConsent → throws (contradiction)', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  assert.throws(
    () =>
      verifyDisclosedClaim(disclosed, {
        signedRoot: root,
        presentationPubKey: presentationPubKeyHex,
        expectedVerifierId: disclosed.challenge.verifier_id,
        expectedNonce: disclosed.challenge.nonce,
        expectedConsentReceiptId: disclosed.challenge.consent_receipt_id,
        allowUnscopedConsent: true,
        now: NOW,
      }),
    /contradictory consent config/
  );
});

test('FIX 1: explicit allowUnscopedConsent:true is the ONLY way to verify without a consent id → PASS', () => {
  const { root, disclosed, presentationPubKeyHex } = scene();
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    allowUnscopedConsent: true, // loud, deliberate lower-assurance no-consent mode
    now: NOW,
  });
  assert.equal(result.decision, 'pass', result.reason);
});

test('FIX 1: with consent required, a non-matching consent id still FAILS (ordering: consent before expiry)', () => {
  // Even an EXPIRED reveal fails on consent FIRST (consent is checked before expiry per spec §3).
  const { root, disclosed, presentationPubKeyHex } = scene(CLAIM_LEI, undefined, freshChallenge({ expiry: NOW - 1 }));
  const result = verifyDisclosedClaim(disclosed, {
    signedRoot: root,
    presentationPubKey: presentationPubKeyHex,
    expectedVerifierId: disclosed.challenge.verifier_id,
    expectedNonce: disclosed.challenge.nonce,
    expectedConsentReceiptId: 'receipt:not-the-one-bound',
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent-scope mismatch/); // NOT /expired/ — consent checked first
});

/* ===========================================================================
 * FIX 2 — produceReveal enforces the salt floor + commitment consistency on
 * the HOLDER side. It must refuse to MINT an artifact the verifier will reject.
 * =========================================================================== */

test('FIX 2: produceReveal with a SUB-128-bit salt → throws (does not mint a doomed reveal)', () => {
  const c = attestClaimCommitment(CLAIM_LEI);
  const shortSalt = bytesToHex(new Uint8Array(8).fill(1)); // 64-bit
  // Rebuild a self-consistent commitment over the short salt so ONLY the floor check trips.
  const bad: ClaimCommitment = { ...c, salt: shortSalt, commitment: computeCommitment(shortSalt, c.claim) };
  const { privKey } = generateKeypair();
  assert.throws(() => produceReveal(bad, [], freshChallenge(), privKey), /salt too short/);
});

test('FIX 2: produceReveal with a NON-HEX salt → throws', () => {
  const c = attestClaimCommitment(CLAIM_LEI);
  const bad: ClaimCommitment = { ...c, salt: 'not-hex-zz' };
  const { privKey } = generateKeypair();
  assert.throws(() => produceReveal(bad, [], freshChallenge(), privKey), /non-empty hex|not valid hex/);
});

test('FIX 2: produceReveal with a MISMATCHED commitment (does not open to salt+claim) → throws', () => {
  const c = attestClaimCommitment(CLAIM_LEI); // valid 256-bit salt
  // Keep the good salt but corrupt the commitment so it no longer opens to (salt, claim).
  const bad: ClaimCommitment = { ...c, commitment: bytesToHex(new Uint8Array(32).fill(0xab)) };
  const { privKey } = generateKeypair();
  assert.throws(() => produceReveal(bad, [], freshChallenge(), privKey), /does not open to/);
});

test('FIX 2: produceReveal with a CONSISTENT, floored commitment → succeeds (no false positive)', () => {
  const c = attestClaimCommitment(CLAIM_LEI);
  const { privKey } = generateKeypair();
  const out = produceReveal(c, [], freshChallenge(), privKey);
  assert.equal(out.salt, c.salt);
  assert.equal(out.reveal_sig.length, 128); // 64-byte ed25519 sig as hex
});

/* ===========================================================================
 * FIX 3 — verifyMerklePath rejects non-32-byte hash widths (fail-closed
 * against non-canonical proof encodings).
 * =========================================================================== */

test('FIX 3: a SIBLING that is not 32 bytes → rejected', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, commitments[0]!.commitment);
  // Truncate the first sibling to 16 bytes — a non-canonical, short proof step.
  const badPath = path.map((s, i) => (i === 0 ? { ...s, sibling: bytesToHex(new Uint8Array(16).fill(5)) } : s));
  assert.equal(verifyMerklePath(commitments[0]!.commitment, badPath, root), false);
});

test('FIX 3: a ROOT that is not 32 bytes → rejected', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const path = buildMerklePath(setHex, commitments[0]!.commitment);
  const shortRoot = bytesToHex(new Uint8Array(16).fill(9)); // 16-byte root
  assert.equal(verifyMerklePath(commitments[0]!.commitment, path, shortRoot), false);
});

test('FIX 3: a COMMITMENT that is not 32 bytes → rejected', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, commitments[0]!.commitment);
  const shortCommitment = bytesToHex(new Uint8Array(20).fill(3)); // 20-byte commitment
  assert.equal(verifyMerklePath(shortCommitment, path, root), false);
});

test('FIX 3: a too-LONG (33-byte) sibling → rejected (width is exact, not a floor)', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, commitments[0]!.commitment);
  const badPath = path.map((s, i) => (i === 0 ? { ...s, sibling: bytesToHex(new Uint8Array(33).fill(5)) } : s));
  assert.equal(verifyMerklePath(commitments[0]!.commitment, badPath, root), false);
});

test('FIX 3: canonical 32-byte proof still verifies → PASS (no false negative)', () => {
  const commitments = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI].map((c) => attestClaimCommitment(c));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  for (const c of commitments) {
    const path = buildMerklePath(setHex, c.commitment);
    assert.ok(verifyMerklePath(c.commitment, path, root), `canonical leaf ${c.claim.scheme} rejected`);
  }
});
