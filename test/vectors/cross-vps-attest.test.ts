/**
 * Cross-VPS multi-attestation harness — vectors
 *
 * Locks in the DAHR single-node-relay trust-gap closure:
 *   - 3/3 identical responses → 'agreed', verify PASS, no divergences
 *   - 2/3 agree (threshold 2) → 'agreed' on majority hash, odd node recorded as divergence, verify PASS
 *   - 1/3 each different → 'no-quorum', verify reflects it
 *   - tampered attestation signature → verify FAIL
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

test('3/3 identical → agreed, verify PASS, no divergences', async () => {
  const payload = { lei: '5493001KJTIIGC8Y1R12', status: 'ISSUED', name: 'ACME CORP' };
  const signers = [makeSigner(R1.nodeId), makeSigner(R2.nodeId), makeSigner(R3.nodeId)];
  const attestors: NodeAttestor[] = [
    fixedAttestor(R1.nodeId, R1.region, payload),
    fixedAttestor(R2.nodeId, R2.region, payload),
    fixedAttestor(R3.nodeId, R3.region, payload),
  ];

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-1', attestors, signers, 3);

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

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-2', attestors, signers, 2);

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

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-3', attestors, signers, 2);

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

  const receipt = await buildCrossVpsAttestation(REQUEST, 'job-4', attestors, signers, 3);
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
