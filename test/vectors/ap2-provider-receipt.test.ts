/**
 * pay-ap2 (§9.5.6) TEST-AGENT attested-provider-receipt vectors (DACS-Standard #221/#222).
 *
 * Locks in the AP2-1..AP2-4 mechanics the test agent (src/live/ap2-test-agent.mts) exercises:
 *   AP2-1  session binding round-trips jobId (MUST) + agreementHash (SHOULD) through provider metadata
 *   AP2-2  attested-fetch cross-checks status/amount/currency/binding; a bare/unsigned receipt fails,
 *          a broken binding fails, a wrong amount fails, a non-captured status fails
 *   AP2-3  the credential scope disclosed to the relay is read-only payment-status
 *   AP2-4  the emitted §9.7 payment evidence carries finalityModel 'provider-receipt'
 *   + the buyer-signed attested-receipt record verifies under SETTLEMENT_EVIDENCE, and the
 *     mock facilitator receipt verifies under the dacs-x extension separator.
 *
 * MOCK: the facilitator + attestation are stubs (per-run key / dahr-stub-single-fetch) — this
 * test verifies the DACS verification CONTRACT, not a real PSP/FIDO signature.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair, sign, verify } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS, DACS_X_EXTENSION_SEPARATORS } from '../../src/domain-sep.js';
import { jcsHashHex } from '../../src/jcs.js';
import {
  emitSettlementEvidenceV1,
  evidenceHashV1,
  signSettlementEvidenceV1,
} from '../../src/lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../../src/lib/verify-settlement-evidence-v1.js';
import {
  PAY_AP2_RAIL_ID,
  AP2_METADATA_KEYS,
  createMockFacilitator,
  createAp2PaymentSession,
  signMockProviderReceipt,
  attestAp2Receipt,
  verifyAp2AgreementArtifact,
  signAp2AttestedReceiptRecord,
  ap2RecordHashHex,
  ap2SimulationDisposition,
  verifyMockAp2AttestedReceiptRecord,
  AP2_SIMULATION_ASSURANCE,
  AP2_SIMULATION_VERDICT,
  MOCK_AP2_RECEIPT_SEP,
  type Ap2AttestedReceiptRecord,
  type Ap2ProviderReceipt,
  type MockAp2PaymentEvidence,
} from '../../src/live/ap2-provider-receipt.js';

const JOB = 'ap2-test-job-1';
const AMT = '1.5'; // CD-1 canonical (the verifier rejects "1.50")
const CUR = 'USD';
const ENDPOINT = 'https://api.stripe.invalid/v1/payment_intents';

function cci(pubKey: Uint8Array): string {
  return Array.from(pubKey, (x) => x.toString(16).padStart(2, '0')).join('');
}

function buildVerifiedAgreement(overrides: { amount?: string; currency?: string } = {}) {
  const buyer = generateKeypair();
  const seller = generateKeypair();
  const body = {
    v: 'dacs-agreement:0.1',
    jobId: JOB,
    listingRef: { listingId: 'listing-1', contentHash: 'b'.repeat(64) },
    terms: {
      price: { amount: overrides.amount ?? AMT, currency: overrides.currency ?? CUR },
      rail: PAY_AP2_RAIL_ID,
      deliverableType: 'storage-program',
    },
    buyer: { scheme: 'cci' as const, identifier: cci(buyer.pubKey) },
    seller: { scheme: 'cci' as const, identifier: cci(seller.pubKey) },
  };
  const hashBytes = new TextEncoder().encode(jcsHashHex(body));
  const artifact = {
    ...body,
    signatures: [
      {
        party: body.buyer,
        algorithm: 'ed25519' as const,
        value: Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, hashBytes, buyer.privKey)).toString('base64'),
      },
      {
        party: body.seller,
        algorithm: 'ed25519' as const,
        value: Buffer.from(sign(DOMAIN_SEPARATORS.AGREEMENT, hashBytes, seller.privKey)).toString('base64'),
      },
    ],
  };
  return { artifact, verified: verifyAp2AgreementArtifact(artifact) };
}

const { verified: VERIFIED_AGREEMENT } = buildVerifiedAgreement();
const { verified: OTHER_VERIFIED_AGREEMENT } = buildVerifiedAgreement();
const AGREE = VERIFIED_AGREEMENT.agreementHash;

function buildReceipt() {
  const session = createAp2PaymentSession({ jobId: JOB, agreementHash: AGREE, amount: AMT, currency: CUR });
  const fac = createMockFacilitator();
  return { session, fac, receipt: signMockProviderReceipt(session, fac, 1_700_000_000_000) };
}

function buildMockPaymentEvidence(receipt: Ap2ProviderReceipt, buyer = generateKeypair()) {
  let evidence: MockAp2PaymentEvidence = {
    ...emitSettlementEvidenceV1({
      kind: 'payment', jobId: JOB, phase: PAY_AP2_RAIL_ID, phaseIndex: 3, outcome: 'success',
      paymentTxRefs: [{ rail: PAY_AP2_RAIL_ID, txHash: `ap2:${receipt.providerTxId}`, kind: 'payment' }],
      paymentAmount: AMT, paymentCurrency: CUR,
      finalityModel: 'provider-receipt', finalityObservedAt: receipt.capturedAt, observedAt: 2,
    }),
    ...ap2SimulationDisposition(),
  } as MockAp2PaymentEvidence;
  evidence = signSettlementEvidenceV1(
    evidence,
    `cci:${Array.from(buyer.pubKey, (x) => x.toString(16).padStart(2, '0')).join('')}`,
    buyer.privKey,
  ) as MockAp2PaymentEvidence;
  return { buyer, evidence };
}

test('AP2 simulation disposition is explicitly mock and never claims verified settlement', () => {
  const disposition = ap2SimulationDisposition();
  assert.deepEqual(disposition, {
    simulation: true,
    assurance: AP2_SIMULATION_ASSURANCE,
    verdict: AP2_SIMULATION_VERDICT,
  });
  assert.equal(
    disposition.verdict,
    'SIMULATION PASS (mock AP2 provider + stub attestation — NOT verified settlement)',
  );
  assert.doesNotMatch(disposition.verdict, /^PASS$/);
});

test('AP2-1: provider session binds dacs_job_id (MUST) + dacs_agreement_hash (SHOULD) into metadata', () => {
  const { session } = buildReceipt();
  assert.equal(session.metadata[AP2_METADATA_KEYS.jobId], JOB);
  assert.equal(session.metadata[AP2_METADATA_KEYS.agreementHash], AGREE);
});

test('mock facilitator receipt signature verifies under the dacs-x-ap2-receipt separator', () => {
  const { fac, receipt } = buildReceipt();
  assert.equal(MOCK_AP2_RECEIPT_SEP, DACS_X_EXTENSION_SEPARATORS.AP2_MOCK_RECEIPT);
  const { facilitatorSignature, ...unsigned } = receipt;
  const facPub = Uint8Array.from((fac.facilitatorPubKey.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)));
  const sig = Uint8Array.from(Buffer.from(facilitatorSignature, 'base64'));
  const body = new TextEncoder().encode(jcsHashHex(unsigned));
  assert.equal(verify(MOCK_AP2_RECEIPT_SEP, sig, body, facPub), true);
});

test('AP2-2: attested fetch cross-checks pass on a good receipt → receiptAttestation (read-only scope)', () => {
  const { receipt } = buildReceipt();
  const att = attestAp2Receipt({
    receipt, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1_700_000_000_001,
  });
  assert.equal(att.type, 'dahr-stub-single-fetch');
  assert.equal(att.observedStatus, 'captured');
  assert.equal(att.credentialScope, 'payment-status:read-only'); // AP2-3
  assert.equal(att.statusEndpoint, ENDPOINT);
});

test('AP2-2: broken AP2-1 binding (metadata jobId mismatch) fails closed', () => {
  // A LEGITIMATELY-signed receipt whose provider metadata carries the WRONG jobId — the
  // facilitator signature is valid, so this isolates the AP2-1 binding check (not the sig check).
  const fac = createMockFacilitator();
  const wrongSession = createAp2PaymentSession({ jobId: 'other-job', agreementHash: AGREE, amount: AMT, currency: CUR });
  const receipt = signMockProviderReceipt(wrongSession, fac, 1_700_000_000_000);
  assert.throws(() => attestAp2Receipt({
    receipt, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  }), /AP2-1 binding broken/);
});

test('AP2-2: tampering metadata after signing is caught by the facilitator signature check (fail-closed)', () => {
  // Post-sign metadata tampering breaks the receipt signature FIRST — the binding is protected by
  // the signature, so a bare edited receipt can never pass. (Complements the legitimate-mismatch case.)
  const { receipt } = buildReceipt();
  const tampered = { ...receipt, metadata: { ...receipt.metadata, [AP2_METADATA_KEYS.jobId]: 'other-job' } };
  assert.throws(() => attestAp2Receipt({
    receipt: tampered, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  }), /signature does not verify/);
});

test('AP2-2: amount mismatch vs agreement fails closed (a bare provider ref is not verified evidence)', () => {
  const { receipt } = buildReceipt();
  const { verified: wrongTerms } = buildVerifiedAgreement({ amount: '9.99' });
  assert.throws(() => attestAp2Receipt({
    receipt, verifiedAgreement: wrongTerms,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  }), /amount/);
});

test('AP2-2: non-captured / unsigned receipt fails closed', () => {
  const { receipt } = buildReceipt();
  const notCaptured = { ...receipt, status: 'pending' as unknown as 'captured' };
  assert.throws(() => attestAp2Receipt({
    receipt: notCaptured, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  }), /captured|signature/);
  const unsigned = { ...receipt, facilitatorSignature: '' };
  assert.throws(() => attestAp2Receipt({
    receipt: unsigned, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  }), /unsigned|signature/);
});

test('AP2-4: emitted §9.7 pay-ap2 payment evidence carries finalityModel provider-receipt and verifies structurally', () => {
  const ev = signSettlementEvidenceV1(emitSettlementEvidenceV1({
    kind: 'payment', jobId: JOB, phase: PAY_AP2_RAIL_ID, phaseIndex: 3, outcome: 'success',
    paymentTxRefs: [{ rail: PAY_AP2_RAIL_ID, txHash: 'ap2:mock_pi_x', kind: 'payment' }],
    paymentAmount: AMT, paymentCurrency: CUR,
    finalityModel: 'provider-receipt', finalityObservedAt: 1, observedAt: 2,
  }), `cci:${'b'.repeat(64)}`, generateKeypair().privKey);
  assert.equal((ev as { settlementFinality?: { model?: string } }).settlementFinality?.model, 'provider-receipt');
  assert.equal(verifySettlementEvidenceV1(ev).decision, 'pass');
});

test('buyer-signed AP2 attested-receipt record verifies under SETTLEMENT_EVIDENCE (bundle-referenced evidence)', () => {
  const { receipt } = buildReceipt();
  const att = attestAp2Receipt({
    receipt, verifiedAgreement: VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  });
  const { buyer, evidence } = buildMockPaymentEvidence(receipt);
  const buyerCci = Array.from(buyer.pubKey, (x) => x.toString(16).padStart(2, '0')).join('');
  let rec: Ap2AttestedReceiptRecord = {
    v: 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1',
    simulation: true, assurance: AP2_SIMULATION_ASSURANCE,
    jobId: JOB, phase: PAY_AP2_RAIL_ID, phaseIndex: 3, agreementHash: AGREE,
    paymentEvidenceHash: evidenceHashV1(evidence),
    finalityModel: 'provider-receipt', providerReceipt: receipt, receiptAttestation: att, observedAt: 5,
  };
  rec = signAp2AttestedReceiptRecord(
    rec,
    evidence,
    VERIFIED_AGREEMENT,
    `cci:${buyerCci}`,
    buyer.privKey,
  );
  const sig = Uint8Array.from(Buffer.from(rec.signature!.value, 'base64'));
  const body = new TextEncoder().encode(ap2RecordHashHex(rec));
  assert.equal(verify(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, sig, body, buyer.pubKey), true);
  const semantic = verifyMockAp2AttestedReceiptRecord(rec, evidence, VERIFIED_AGREEMENT);
  assert.equal(semantic.simulation, true);
  assert.equal(semantic.assurance, 'mock');
  assert.equal(Object.values(semantic.checks).every(Boolean), true);
  // The `v` string contains "settlement-evidence" so verify-bundle-v1 classifies it as evidence.
  assert.match(rec.v, /settlement-evidence/);
});

test('buyer cannot re-sign AP2 content with a failed agreement cross-check (fails closed)', () => {
  const wrongAgreement = OTHER_VERIFIED_AGREEMENT.agreementHash;
  const fac = createMockFacilitator();
  const wrongSession = createAp2PaymentSession({
    jobId: JOB, agreementHash: wrongAgreement, amount: AMT, currency: CUR,
  });
  const receipt = signMockProviderReceipt(wrongSession, fac, 1_700_000_000_000);
  const att = attestAp2Receipt({
    receipt,
    verifiedAgreement: OTHER_VERIFIED_AGREEMENT,
    statusEndpoint: ENDPOINT,
    fetchedAt: 1,
  });
  const { buyer, evidence } = buildMockPaymentEvidence(receipt);
  const badRecord: Ap2AttestedReceiptRecord = {
    v: 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1',
    simulation: true, assurance: AP2_SIMULATION_ASSURANCE,
    jobId: JOB, phase: PAY_AP2_RAIL_ID, phaseIndex: 3,
    agreementHash: VERIFIED_AGREEMENT.agreementHash,
    paymentEvidenceHash: evidenceHashV1(evidence),
    finalityModel: 'provider-receipt', providerReceipt: receipt, receiptAttestation: att, observedAt: 5,
  };

  assert.throws(
    () => signAp2AttestedReceiptRecord(
      badRecord,
      evidence,
      VERIFIED_AGREEMENT,
      'cci:buyer',
      buyer.privKey,
    ),
    /provider agreement binding does not match verified agreement/,
  );
  assert.equal(badRecord.signature, undefined);
});

test('co-tampered agreement reference + AP2 content, validly re-signed, is rejected against independently verified agreement', () => {
  const { verified: tamperedAgreement } = buildVerifiedAgreement();
  const wrongAgreement = tamperedAgreement.agreementHash;
  const fac = createMockFacilitator();
  const wrongSession = createAp2PaymentSession({
    jobId: JOB, agreementHash: wrongAgreement, amount: AMT, currency: CUR,
  });
  const receipt = signMockProviderReceipt(wrongSession, fac, 1_700_000_000_000);
  // The stub attestation is internally consistent only with the wrong agreement.
  const att = attestAp2Receipt({
    receipt,
    verifiedAgreement: tamperedAgreement,
    statusEndpoint: ENDPOINT, fetchedAt: 1,
  });
  const { buyer, evidence } = buildMockPaymentEvidence(receipt);
  const badRecord: Ap2AttestedReceiptRecord = {
    v: 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1',
    simulation: true, assurance: AP2_SIMULATION_ASSURANCE,
    jobId: JOB, phase: PAY_AP2_RAIL_ID, phaseIndex: 3,
    agreementHash: wrongAgreement,
    paymentEvidenceHash: evidenceHashV1(evidence),
    finalityModel: 'provider-receipt', providerReceipt: receipt, receiptAttestation: att, observedAt: 5,
  };

  assert.throws(
    () => signAp2AttestedReceiptRecord(
      badRecord,
      evidence,
      VERIFIED_AGREEMENT,
      'cci:buyer',
      buyer.privKey,
    ),
    /record agreementHash does not match verified agreement/,
  );
  assert.equal(badRecord.signature, undefined);

  // Even bypassing the sanctioned signer and producing a cryptographically valid buyer signature
  // cannot turn the bad AP2 semantics into a verifying extension record.
  const value = Buffer.from(sign(
    DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE,
    new TextEncoder().encode(ap2RecordHashHex(badRecord)),
    buyer.privKey,
  )).toString('base64');
  const resignedBadRecord: Ap2AttestedReceiptRecord = {
    ...badRecord,
    signature: { algorithm: 'ed25519', signer: 'cci:buyer', value },
  };
  assert.equal(verify(
    DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE,
    Uint8Array.from(Buffer.from(value, 'base64')),
    new TextEncoder().encode(ap2RecordHashHex(resignedBadRecord)),
    buyer.pubKey,
  ), true, 'positive control: the buyer re-signature is cryptographically valid');
  assert.throws(
    () => verifyMockAp2AttestedReceiptRecord(
      resignedBadRecord,
      evidence,
      VERIFIED_AGREEMENT,
    ),
    /record agreementHash does not match verified agreement/,
  );
});
