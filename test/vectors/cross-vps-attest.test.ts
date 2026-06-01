/**
 * Cross-VPS multi-attestation harness — vectors
 *
 * Locks in the DAHR single-node-relay trust-gap closure:
 *   - 3/3 identical responses → 'agreed', verify PASS, no divergences
 *   - 2/3 agree (threshold 2) → 'agreed' on majority hash, odd node recorded as divergence, verify PASS
 *   - 1/3 each different → 'no-quorum', verify reflects it
 *   - tampered attestation signature → verify FAIL
 *   - UNAUTHORIZED signer (pubkeyId not in authorized set) → excluded from quorum
 *   - one node REPLAYING its own attestation counts ONCE (distinct-signer quorum)
 *
 * Quorum is over DISTINCT AUTHORIZED signers, not raw attestations: the threshold is
 * met only when >= threshold distinct authorized nodes agree on the SAME hash. The
 * authorized set is keyed on pubkeyId; distinctness on (nodeId, pubkeyId). These
 * tests pass an explicit `authorizedPubkeys` set so the trust path is exercised.
 *
 * The fleet is mocked via injectable NodeAttestor functions — no live R1/R2/R3.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  buildCrossVpsAttestation,
  verifyCrossVpsAgreementReceipt,
  type NodeAttestor,
  type NodeSigner,
  type CrossVpsRequest,
} from '../../src/lib/cross-vps-attest.js';

const REQUEST: CrossVpsRequest = {
  url: 'https://api.gleif.org/api/v1/lei-records/5493001KJTIIGC8Y1R12',
  method: 'GET',
};

/** Build a NodeSigner with a fresh keypair; pubkeyId = hex(pubKey). */
function makeSigner(nodeId: string): NodeSigner {
  const { privKey, pubKey } = generateKeypair();
  return { nodeId, privKey, pubKey, pubkeyId: bytesToHex(pubKey) };
}

/** A NodeAttestor that always returns `payload` for the given node/region. */
function fixedAttestor(nodeId: string, region: string, payload: unknown): NodeAttestor {
  return async () => ({ nodeId, region, rawResponse: payload });
}

const R1 = { nodeId: 'r1-na', region: 'NA' };
const R2 = { nodeId: 'r2-eu', region: 'EU' };
const R3 = { nodeId: 'r3-eu', region: 'EU' };

/** The authorized pubkeyId set for a list of signers (their pubkeyIds). */
function authorizedOf(signers: NodeSigner[]): string[] {
  return signers.map((s) => s.pubkeyId);
}

test('3/3 identical → agreed, verify PASS, no divergences', async () => {
  const payload = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED', name: 'ACME CORP' };
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R2.nodeId, R2.region, payload),
    fixedAttestor(R3.nodeId, R3.region, payload),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-1', attestors, signers, 3, authorizedOf(signers));

  assert.equal(receipt.decision, 'agreed');
  assert.equal(receipt.quorum.n, 3);
  assert.equal(receipt.quorum.m, 3);
  assert.equal(receipt.divergences.length, 0);
  assert.notEqual(receipt.agreedResponseHash, '');
  // All three nodes hashed the same response.
  const hashes = new Set(receipt.attestations.map((a) => a.responseHash));
  assert.equal(hashes.size, 1);

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.decision, 'agreed');
});

test('2/3 agree, 1 differs, threshold 2 → agreed on majority, odd node recorded, verify PASS', async () => {
  const good = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED' };
  const doctored = { lei: '5493001KJTIIGC8Y1R12', status: 'LAPSED' }; // R3 was fed a tampered response
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, good),
    fixedAttestor(R2.nodeId, R2.region, good),
    fixedAttestor(R3.nodeId, R3.region, doctored),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-2', attestors, signers, 2, authorizedOf(signers));

  assert.equal(receipt.decision, 'agreed');
  assert.equal(receipt.quorum.n, 2);
  assert.equal(receipt.quorum.m, 3);
  // The odd node out is recorded as a divergence.
  assert.equal(receipt.divergences.length, 1);
  assert.equal(receipt.divergences[0]?.nodeId, R3.nodeId);
  // The agreed hash is the majority (good) hash, not R3's doctored hash.
  const r3 = receipt.attestations.find((a) => a.nodeId === R3.nodeId);
  assert.ok(r3);
  assert.notEqual(receipt.agreedResponseHash, r3.responseHash);
  assert.equal(receipt.divergences[0]?.responseHash, r3.responseHash);

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.decision, 'agreed');
});

test('1/3 each different → no-quorum, verify reflects it', async () => {
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, { v: 'A' }),
    fixedAttestor(R2.nodeId, R2.region, { v: 'B' }),
    fixedAttestor(R3.nodeId, R3.region, { v: 'C' }),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-3', attestors, signers, 2, authorizedOf(signers));

  assert.equal(receipt.decision, 'no-quorum');
  assert.equal(receipt.quorum.n, 0);
  assert.equal(receipt.quorum.m, 3);
  assert.equal(receipt.agreedResponseHash, '');
  // No quorum ⇒ every node is recorded as a divergence.
  assert.equal(receipt.divergences.length, 3);

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.decision, 'no-quorum');
});

test('tampered attestation signature → verify FAIL', async () => {
  const payload = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED' };
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R2.nodeId, R2.region, payload),
    fixedAttestor(R3.nodeId, R3.region, payload),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-4', attestors, signers, 3, authorizedOf(signers));
  // Sanity: clean receipt verifies before tampering.
  assert.equal(verifyCrossVpsAgreementReceipt(receipt).ok, true);

  // Flip the last hex byte of R2's signature (deterministic, stays valid hex, wrong sig).
  const victim = receipt.attestations[1]!;
  const lastChar = victim.signature.slice(-1);
  const flipped = lastChar === '0' ? '1' : '0';
  victim.signature = victim.signature.slice(0, -1) + flipped;

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, false);
  assert.match(result.reason, /signature did NOT verify/);
});

test('unauthorized signer is excluded from quorum — 2 authorized + 1 unauthorized, threshold 3 → no-quorum', async () => {
  // Three nodes return the SAME response, but only R1 + R2 are authorized signers.
  // The attacker node R3 holds a valid key and signs the same hash — but its pubkeyId
  // is NOT in the authorized set, so it MUST NOT count. With threshold 3, the two
  // authorized signers cannot reach quorum.
  const payload = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED' };
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R2.nodeId, R2.region, payload),
    fixedAttestor(R3.nodeId, R3.region, payload),
  ];
  // Authorize only R1 + R2 — R3 is an unauthorized (attacker) signer.
  const authorized = [signers[0]!.pubkeyId, signers[1]!.pubkeyId];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-unauth', attestors, signers, 3, authorized);

  // Only 2 distinct AUTHORIZED signers agree → below threshold 3.
  assert.equal(receipt.decision, 'no-quorum');
  assert.equal(receipt.quorum.n, 0);
  assert.equal(receipt.quorum.m, 3);
  // R3 is recorded as unauthorized and excluded from quorum.
  assert.ok(receipt.unauthorized, 'unauthorized set must be recorded');
  assert.equal(receipt.unauthorized!.length, 1);
  assert.equal(receipt.unauthorized![0]?.nodeId, R3.nodeId);

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.decision, 'no-quorum');

  // And a forged receipt that claims R3 counted (decision agreed, n=3) must FAIL verify.
  const forged = structuredClone(receipt);
  forged.decision = 'agreed';
  forged.quorum.n = 3;
  forged.agreedResponseHash = receipt.attestations[0]!.responseHash;
  forged.divergences = [];
  const forgedResult = verifyCrossVpsAgreementReceipt(forged);
  assert.equal(forgedResult.ok, false, 'a receipt counting an unauthorized signer must not verify');
});

test('one node replaying its own attestation counts ONCE — distinct-signer quorum, threshold 2 → no-quorum', async () => {
  // A single relay R1 tries to self-declare a quorum by returning its (identical)
  // attestation multiple times. Distinctness is keyed on (nodeId, pubkeyId), so all
  // three R1 attestations collapse to ONE signer. With threshold 2, one signer is
  // sub-quorum even though there are three matching attestation rows.
  const payload = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED' };
  const r1Signer = makeSigner(R1.nodeId);
  // Three attestors, all the SAME node R1 with the SAME key — a replaying relay.
  const signers = [r1Signer];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R1.nodeId, R1.region, payload),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-replay', attestors, signers, 2, [r1Signer.pubkeyId]);

  // Three attestation rows, but only ONE distinct authorized signer → below threshold 2.
  assert.equal(receipt.quorum.m, 3);
  assert.equal(receipt.decision, 'no-quorum');
  assert.equal(receipt.quorum.n, 0);

  const result = verifyCrossVpsAgreementReceipt(receipt);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.decision, 'no-quorum');

  // A forged receipt that counts the three replayed rows as a 3-quorum must FAIL verify.
  const forged = structuredClone(receipt);
  forged.decision = 'agreed';
  forged.quorum.n = 3;
  forged.agreedResponseHash = receipt.attestations[0]!.responseHash;
  forged.divergences = [];
  const forgedResult = verifyCrossVpsAgreementReceipt(forged);
  assert.equal(forgedResult.ok, false, 'replayed self-attestations must not satisfy a distinct-signer quorum');
});
