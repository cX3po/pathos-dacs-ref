/**
 * ap2-provider-receipt.ts — pay-ap2 (§9.5.6) attested provider-receipt construction.
 *
 * DACS-4 v0.3 (DACS-Standard #221/#222) strengthens the `pay-ap2` rail with four
 * rules the fiat PoC validated end-to-end (Stripe test mode + DAHR on Demos testnet):
 *
 *   AP2-1  Session binding — the handler MUST bind the session into the provider-side
 *          payment metadata at CREATION: pinned keys `dacs_job_id` (MUST) +
 *          `dacs_agreement_hash` (SHOULD). Registered as the SB-3 binding for pay-ap2.
 *   AP2-2  Attested receipt verification — a success-outcome record MUST verify the
 *          receipt via an SR-3 ATTESTED FETCH of the provider's payment-status endpoint
 *          (same consensus-backed-proxy machinery as the DACS-2 `lei` recipe), checking
 *          captured-status + amount/currency vs the agreement + the AP2-1 binding.
 *          Recorded in the `ap2` txRef field `receiptAttestation` (REQUIRED on success).
 *          A bare provider reference MUST NOT be presented as verified settlement evidence.
 *   AP2-3  Least-privilege credential — the provider credential disclosed for the attested
 *          fetch MUST be read-only payment-status scope (it transits the SR-3 relay).
 *   AP2-4  Finality — `provider-receipt` finality asserts CAPTURE, not irreversibility;
 *          post-capture reversals go through §9.7.1 amendments (chargeback → #220).
 *
 * ── TEST-AGENT SCOPE / MOCK DISCLOSURE ─────────────────────────────────────────────────
 * This is a TEST agent. It exercises the DACS-4 pay-ap2 VERIFICATION path WITHOUT real
 * Google/FIDO AP2 infrastructure or a live Stripe/PSP facilitator. Everything the real
 * facilitator + attestation layer would produce is MOCKED here and CLEARLY LABELLED:
 *
 *   - The facilitator's signed provider-receipt is signed by a PER-RUN ed25519 stub key
 *     (`facilitatorKind: 'mock-ap2-facilitator'`), NOT a real Stripe/PSP/FIDO signature.
 *   - The AP2-2 SR-3 receiptAttestation is a DAHR-STUB-shaped attestation
 *     (`type: 'dahr-stub-single-fetch'`, mirroring src/demos/dahr.ts's honest-stub label)
 *     — it proves "this process constructed this receipt", NOT a validator-quorum fetch of
 *     a real provider status endpoint.
 *
 * What is REAL: the DACS-4 evidence SHAPE, the AP2-1 binding round-trip
 * (jobId+agreementHash into provider metadata → back out of the attested status response),
 * the amount/currency/status cross-checks, the ed25519 signing discipline, and the
 * DACS-5 bundle roll-up. A real deployment swaps the mock facilitator for a live PSP and
 * the DAHR stub for a consensus-backed-proxy fetch — the verification contract is unchanged.
 */

import { sha256 } from '@noble/hashes/sha2';
import { generateKeypair, sign, verify } from '../lib/sign.js';
import { DOMAIN_SEPARATORS, DACS_X_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../jcs.js';
import { evidenceHashV1 } from '../lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../lib/verify-settlement-evidence-v1.js';
import type { SettlementEvidenceV1, SettlementEvidenceV1Payment } from '../types/settle.js';

const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export const PAY_AP2_RAIL_ID = 'pay-ap2';
export const AP2_SIMULATION_ASSURANCE = 'mock' as const;
export const AP2_SIMULATION_VERDICT =
  'SIMULATION PASS (mock AP2 provider + stub attestation — NOT verified settlement)' as const;

/** The terminal disposition for this mock-only AP2 extension path. */
export interface Ap2SimulationDisposition {
  simulation: true;
  assurance: typeof AP2_SIMULATION_ASSURANCE;
  verdict: typeof AP2_SIMULATION_VERDICT;
}

export function ap2SimulationDisposition(): Ap2SimulationDisposition {
  return {
    simulation: true,
    assurance: AP2_SIMULATION_ASSURANCE,
    verdict: AP2_SIMULATION_VERDICT,
  };
}

/** §9.7 payment evidence emitted by this test path. The marker is signed and hash-significant. */
export type MockAp2PaymentEvidence = SettlementEvidenceV1Payment & Ap2SimulationDisposition;

/** AP2-1: the pinned session-binding metadata keys the handler writes into provider metadata. */
export const AP2_METADATA_KEYS = { jobId: 'dacs_job_id', agreementHash: 'dacs_agreement_hash' } as const;

const VERIFIED_AP2_AGREEMENT = Symbol('verified-ap2-agreement');

/**
 * Agreement facts trusted by the AP2 semantic verifier.
 *
 * This value must come from `verifyAp2AgreementArtifact`, after fetching the agreement through
 * the bundle's agreementRef. It is deliberately separate from the AP2 record: the record cannot
 * choose the hash or terms against which it is checked.
 */
export interface VerifiedAp2Agreement {
  readonly [VERIFIED_AP2_AGREEMENT]: true;
  agreementHash: string;
  jobId: string;
  amount: string;
  currency: string;
  rail: typeof PAY_AP2_RAIL_ID;
}

type Ap2AgreementParty = { scheme: 'cci'; identifier: string };
type Ap2AgreementSignature = {
  party: Ap2AgreementParty;
  algorithm: 'ed25519';
  value: string;
};

function requireVerifiedAp2Agreement(agreement: VerifiedAp2Agreement): void {
  if (agreement[VERIFIED_AP2_AGREEMENT] !== true) {
    throw new Error('AP2 agreement: terms were not produced by fetched-artifact signature verification');
  }
}

/**
 * Verify the fetched DACS-3 agreement and extract the independently trusted AP2 terms.
 *
 * Both declared parties must provide valid ed25519 signatures over the canonical unsigned
 * agreement hash. Callers must separately content-hash-match the fetched bytes to agreementRef;
 * this function authenticates those fetched bytes and derives the semantic-verification anchor.
 */
export function verifyAp2AgreementArtifact(artifact: unknown): VerifiedAp2Agreement {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    throw new Error('AP2 agreement: fetched artifact is not an object');
  }
  const agreement = artifact as Record<string, unknown>;
  const { signatures: rawSignatures, ...unsigned } = agreement;
  const terms = unsigned.terms as Record<string, unknown> | undefined;
  const price = terms?.price as Record<string, unknown> | undefined;
  const buyer = unsigned.buyer as Record<string, unknown> | undefined;
  const seller = unsigned.seller as Record<string, unknown> | undefined;
  if (unsigned.v !== 'dacs-agreement:0.1'
    || typeof unsigned.jobId !== 'string' || unsigned.jobId.length === 0
    || terms?.rail !== PAY_AP2_RAIL_ID
    || typeof price?.amount !== 'string' || price.amount.length === 0
    || typeof price?.currency !== 'string' || price.currency.length === 0) {
    throw new Error('AP2 agreement: fetched artifact has invalid job/amount/currency/rail terms');
  }
  const parties = [buyer, seller];
  if (parties.some((p) => p?.scheme !== 'cci'
    || typeof p.identifier !== 'string'
    || !/^[0-9a-fA-F]{64}$/.test(p.identifier))) {
    throw new Error('AP2 agreement: buyer/seller cci keys are malformed');
  }
  if (!Array.isArray(rawSignatures)) {
    throw new Error('AP2 agreement: signatures are missing');
  }

  const agreementHash = jcsHashHex(unsigned);
  const hashBytes = new TextEncoder().encode(agreementHash);
  const verifiedParties = new Set<string>();
  const authorizedParties = new Set(parties.map((p) => (p!.identifier as string).toLowerCase()));
  for (const raw of rawSignatures) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('AP2 agreement: signature entry is malformed');
    }
    const sig = raw as Partial<Ap2AgreementSignature>;
    const identifier = sig.party?.identifier?.toLowerCase();
    if (sig.party?.scheme !== 'cci' || !identifier || !authorizedParties.has(identifier)
      || sig.algorithm !== 'ed25519' || typeof sig.value !== 'string') {
      throw new Error('AP2 agreement: signature is not from an authorized agreement party');
    }
    const pubKey = Uint8Array.from(identifier.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
    const sigBytes = Uint8Array.from(Buffer.from(sig.value, 'base64'));
    if (sigBytes.length !== 64
      || !verify(DOMAIN_SEPARATORS.AGREEMENT, sigBytes, hashBytes, pubKey)) {
      throw new Error('AP2 agreement: party signature does not verify');
    }
    verifiedParties.add(identifier);
  }
  if ([...authorizedParties].some((identifier) => !verifiedParties.has(identifier))) {
    throw new Error('AP2 agreement: both buyer and seller signatures are required');
  }

  const verified = {
    agreementHash,
    jobId: unsigned.jobId,
    amount: price.amount,
    currency: price.currency,
    rail: PAY_AP2_RAIL_ID,
  } as VerifiedAp2Agreement;
  Object.defineProperty(verified, VERIFIED_AP2_AGREEMENT, { value: true });
  return Object.freeze(verified);
}

/**
 * A MOCK AP2 facilitator (test-agent stand-in for Stripe/PSP + the AP2 provider layer).
 * A real deployment never constructs this — the receipt comes from the PSP, signed by the
 * PSP, fetched under SR-3 attestation. The per-run ed25519 key is the honest-stub marker.
 */
export interface MockFacilitator {
  facilitatorKind: 'mock-ap2-facilitator';
  /** hex ed25519 public key that "signs" the provider receipt (per-run, throwaway). */
  facilitatorPubKey: string;
  privKey: Uint8Array;
}

export function createMockFacilitator(): MockFacilitator {
  const kp = generateKeypair();
  return { facilitatorKind: 'mock-ap2-facilitator', facilitatorPubKey: bytesToHex(kp.pubKey), privKey: kp.privKey };
}

/** The provider-side payment session (what the facilitator "created" with the AP2-1 binding). */
export interface Ap2PaymentSession {
  providerTxId: string;
  amount: string;    // CD-1 canonical decimal string
  currency: string;  // e.g. "USD"
  /** AP2-1: session binding written into provider metadata AT CREATION. */
  metadata: Record<string, string>;
}

/**
 * AP2-1 — create the provider payment session, binding jobId (MUST) + agreementHash (SHOULD)
 * into the provider-side metadata. The mock stands in for a real PSP `paymentIntent.create`.
 */
export function createAp2PaymentSession(opts: {
  jobId: string;
  agreementHash: string;
  amount: string;
  currency: string;
  providerTxId?: string;
}): Ap2PaymentSession {
  return {
    providerTxId: opts.providerTxId ?? `mock_pi_${jcsHashHex({ jobId: opts.jobId, at: 'ap2-create' }).slice(0, 24)}`,
    amount: opts.amount,
    currency: opts.currency,
    metadata: {
      [AP2_METADATA_KEYS.jobId]: opts.jobId,
      [AP2_METADATA_KEYS.agreementHash]: opts.agreementHash,
    },
  };
}

/** The facilitator's signed success receipt (mock: PSP-signed status=captured record). */
export interface Ap2ProviderReceipt {
  v: 'ap2-provider-receipt:mock:0.1';
  providerTxId: string;
  status: 'captured';
  amount: string;
  currency: string;
  /** AP2-1: the binding metadata the status response returns (round-trips jobId+agreementHash). */
  metadata: Record<string, string>;
  capturedAt: number;
  facilitatorKind: 'mock-ap2-facilitator';
  facilitatorPubKey: string;
  /** base64 ed25519 over "dacs-x-ap2-receipt:v1:" || sha256hex(JCS(receipt-minus-signature)). MOCK. */
  facilitatorSignature: string;
}

/**
 * Test-agent domain separator for the MOCK facilitator signature. Uses the sanctioned
 * `dacs-x-` extension namespace (registered in domain-sep.ts DACS_X_EXTENSION_SEPARATORS)
 * so a mocked provider signature can NEVER be confused with a real DACS core signature.
 */
export const MOCK_AP2_RECEIPT_SEP = DACS_X_EXTENSION_SEPARATORS.AP2_MOCK_RECEIPT;

/** Facilitator "captures" the payment and signs the provider receipt (MOCK). */
export function signMockProviderReceipt(session: Ap2PaymentSession, fac: MockFacilitator, capturedAt: number): Ap2ProviderReceipt {
  const body = {
    v: 'ap2-provider-receipt:mock:0.1' as const,
    providerTxId: session.providerTxId,
    status: 'captured' as const,
    amount: session.amount,
    currency: session.currency,
    metadata: session.metadata,
    capturedAt,
    facilitatorKind: fac.facilitatorKind,
    facilitatorPubKey: fac.facilitatorPubKey,
  };
  const hashBytes = new TextEncoder().encode(jcsHashHex(body));
  const facilitatorSignature = Buffer.from(sign(MOCK_AP2_RECEIPT_SEP, hashBytes, fac.privKey)).toString('base64');
  return { ...body, facilitatorSignature };
}

/**
 * AP2-2 — the SR-3 attested-fetch record over the provider payment-status endpoint.
 *
 * MOCK: this is a DAHR-STUB-shaped attestation (type 'dahr-stub-single-fetch', mirroring
 * src/demos/dahr.ts). It records "the payment-status response was fetched at time T and
 * these bytes were seen" — but does NOT carry the validator-quorum signature true SR-3
 * consensus-backed-proxy provides. The honest-stub label makes the gap visible to a
 * consuming verifier (a high-stakes verifier can refuse `dahr-stub-*`).
 */
export interface Ap2ReceiptAttestation {
  /** Honest-stub label — NOT a real consensus-backed-proxy attestation. */
  type: 'dahr-stub-single-fetch';
  /** The provider payment-status endpoint the SR-3 relay fetched (read-only scope — AP2-3). */
  statusEndpoint: string;
  /** sha256 hex of the provider-receipt bytes the attested fetch returned. */
  responseHash: string;
  /** AP2-3: the credential scope disclosed to the relay MUST be read-only payment-status. */
  credentialScope: 'payment-status:read-only';
  fetchedAt: string;
  /** The captured-status the attested response asserted (AP2-2 cross-check input). */
  observedStatus: 'captured';
}

/**
 * AP2-2 — verify the provider receipt via the attested fetch, cross-checking captured-status
 * + amount/currency vs the agreement + the AP2-1 binding. Returns the receiptAttestation on
 * pass, or throws with the specific check that failed (a bare receipt MUST NOT pass).
 *
 * MOCK boundary: the "attested fetch" re-reads the mock facilitator receipt in-process and
 * verifies its mock signature. A real agent hands the status endpoint + read-only credential
 * to the SR-3 relay and verifies the returned bytes' validator-quorum signature.
 */
export function attestAp2Receipt(opts: {
  receipt: Ap2ProviderReceipt;
  verifiedAgreement: VerifiedAp2Agreement;
  statusEndpoint: string;
  fetchedAt: number;
}): Ap2ReceiptAttestation {
  const r = opts.receipt;
  const agreement = opts.verifiedAgreement;
  requireVerifiedAp2Agreement(agreement);
  // 0) MOCK attested-fetch: re-verify the facilitator signature over the receipt bytes. This
  //    stands in for the SR-3 relay returning provider-status bytes the verifier authenticates.
  const { facilitatorSignature, ...unsigned } = r;
  if (!facilitatorSignature || facilitatorSignature.length < 16) {
    throw new Error('AP2-2 attest: provider receipt is unsigned — a bare provider reference is not verified settlement evidence');
  }
  const hashBytes = new TextEncoder().encode(jcsHashHex(unsigned));
  const facPub = Uint8Array.from((r.facilitatorPubKey.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)));
  const sigBytes = Uint8Array.from(Buffer.from(facilitatorSignature, 'base64'));
  if (!verify(MOCK_AP2_RECEIPT_SEP, sigBytes, hashBytes, facPub)) {
    throw new Error('AP2-2 attest: provider receipt facilitator signature does not verify (mock facilitator)');
  }
  // 1) captured-status.
  if (r.status !== 'captured') throw new Error(`AP2-2 attest: provider status is "${r.status}", not captured`);
  // 2) amount/currency vs the agreement.
  if (r.amount !== agreement.amount) throw new Error(`AP2-2 attest: receipt amount "${r.amount}" != agreed "${agreement.amount}"`);
  if (r.currency !== agreement.currency) throw new Error(`AP2-2 attest: receipt currency "${r.currency}" != agreed "${agreement.currency}"`);
  // 3) AP2-1 binding round-trip: jobId (MUST) + agreementHash (SHOULD) came back from provider metadata.
  if (r.metadata[AP2_METADATA_KEYS.jobId] !== agreement.jobId) {
    throw new Error(`AP2-2 attest: provider metadata ${AP2_METADATA_KEYS.jobId} "${r.metadata[AP2_METADATA_KEYS.jobId]}" != verified agreement jobId "${agreement.jobId}" (AP2-1 binding broken)`);
  }
  if (r.metadata[AP2_METADATA_KEYS.agreementHash] !== agreement.agreementHash) {
    throw new Error(`AP2-2 attest: provider metadata ${AP2_METADATA_KEYS.agreementHash} != verified agreement hash (AP2-1 binding broken)`);
  }
  const responseHash = bytesToHex(sha256(jcsCanonical(r)));
  return {
    type: 'dahr-stub-single-fetch',
    statusEndpoint: opts.statusEndpoint,
    responseHash,
    credentialScope: 'payment-status:read-only',
    fetchedAt: new Date(opts.fetchedAt).toISOString(),
    observedStatus: 'captured',
  };
}

/**
 * The pay-ap2 attested-receipt EVIDENCE RECORD the buyer (phase orchestrator) emits + signs
 * and anchors alongside the payment evidence. It carries the mocked facilitator receipt +
 * the AP2-2 receiptAttestation so a DACS-5 verifier can fetch it, hash-match it, and confirm
 * it was signed by an authorized deal party (the buyer) — exactly like the deliverable path.
 *
 * `v` contains "settlement-evidence" so verify-bundle-v1.ts classifyArtifact() files it as an
 * `evidence` artifact (authorized signer = a bundle party, verified under SETTLEMENT_EVIDENCE).
 */
export interface Ap2AttestedReceiptRecord {
  v: 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1';
  /** Signed, hash-significant assurance boundary: this can never claim real settlement. */
  simulation: true;
  assurance: typeof AP2_SIMULATION_ASSURANCE;
  jobId: string;
  phase: 'pay-ap2';
  phaseIndex: number;
  agreementHash: string;
  /** Exact signed §9.7 payment evidence this extension record semantically verifies. */
  paymentEvidenceHash: string;
  /** AP2-4: provider-receipt finality asserts capture, not irreversibility. */
  finalityModel: 'provider-receipt';
  providerReceipt: Ap2ProviderReceipt;
  /** AP2-2: the SR-3 attested-fetch record (REQUIRED on success). */
  receiptAttestation: Ap2ReceiptAttestation;
  observedAt: number;
  /** ed25519 §B.7 ComponentSignature by the buyer, over SETTLEMENT_EVIDENCE || hash(unsigned). */
  signature?: { algorithm: 'ed25519'; signer: string; value: string };
}

/** hash = sha256(JCS(record minus signature)), hex — same discipline as evidenceHashV1. */
export function ap2RecordHashHex(rec: Ap2AttestedReceiptRecord): string {
  const { signature: _sig, ...unsigned } = rec;
  void _sig;
  return jcsHashHex(unsigned);
}

export interface VerifyMockAp2RecordResult extends Ap2SimulationDisposition {
  checks: {
    mockFacilitatorSignature: true;
    responseHash: true;
    agreementBinding: true;
    paymentTermsAndStatus: true;
    paymentEvidenceOneToOneLink: true;
  };
}

/**
 * Explicit semantic dispatch for the AP2 mock extension.
 *
 * The core DACS-5 walk intentionally remains generic. This extension verifier supplies the
 * AP2-specific checks before emission/signing and whenever a consumer evaluates this mock record.
 * It throws on any mismatch, including a buyer trying to re-sign semantically invalid AP2 content.
 */
export function verifyMockAp2AttestedReceiptRecord(
  rec: Ap2AttestedReceiptRecord,
  paymentEvidence: SettlementEvidenceV1,
  verifiedAgreement: VerifiedAp2Agreement,
): VerifyMockAp2RecordResult {
  requireVerifiedAp2Agreement(verifiedAgreement);
  if (rec.v !== 'dacs-x-ap2-attested-receipt-settlement-evidence:0.1'
    || rec.simulation !== true
    || rec.assurance !== AP2_SIMULATION_ASSURANCE) {
    throw new Error('AP2 extension: mock record must carry signed simulation:true and assurance:"mock" markers');
  }
  if (rec.phase !== PAY_AP2_RAIL_ID) throw new Error('AP2 extension: record phase must be pay-ap2');
  if (rec.finalityModel !== 'provider-receipt') {
    throw new Error('AP2 extension: record finalityModel must be provider-receipt (capture only)');
  }
  if (verifiedAgreement.rail !== PAY_AP2_RAIL_ID) {
    throw new Error('AP2 extension: verified agreement rail is not pay-ap2');
  }
  if (rec.agreementHash !== verifiedAgreement.agreementHash) {
    throw new Error('AP2 extension: record agreementHash does not match verified agreement');
  }
  if (rec.jobId !== verifiedAgreement.jobId || rec.phase !== verifiedAgreement.rail) {
    throw new Error('AP2 extension: record job/rail does not match verified agreement');
  }

  const r = rec.providerReceipt;
  if (r.v !== 'ap2-provider-receipt:mock:0.1' || r.facilitatorKind !== 'mock-ap2-facilitator') {
    throw new Error('AP2 extension: provider receipt is not explicitly mock');
  }
  const { facilitatorSignature, ...unsignedReceipt } = r;
  const facPubHex = r.facilitatorPubKey;
  if (!/^[0-9a-f]{64}$/.test(facPubHex)) {
    throw new Error('AP2 extension: mock facilitator public key is malformed');
  }
  const facPub = Uint8Array.from((facPubHex.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)));
  const sigBytes = Uint8Array.from(Buffer.from(facilitatorSignature, 'base64'));
  const receiptHashBytes = new TextEncoder().encode(jcsHashHex(unsignedReceipt));
  if (!verify(MOCK_AP2_RECEIPT_SEP, sigBytes, receiptHashBytes, facPub)) {
    throw new Error('AP2 extension: mock facilitator signature does not verify');
  }

  const att = rec.receiptAttestation;
  if (att.type !== 'dahr-stub-single-fetch'
    || att.credentialScope !== 'payment-status:read-only'
    || att.observedStatus !== 'captured') {
    throw new Error('AP2 extension: receipt attestation is not the expected read-only captured-status stub');
  }
  const expectedResponseHash = bytesToHex(sha256(jcsCanonical(r)));
  if (att.responseHash !== expectedResponseHash) {
    throw new Error('AP2 extension: receipt attestation responseHash does not match provider receipt');
  }

  if (r.status !== 'captured') throw new Error('AP2 extension: provider status is not captured');
  if (r.metadata[AP2_METADATA_KEYS.jobId] !== verifiedAgreement.jobId) {
    throw new Error('AP2 extension: provider job binding does not match verified agreement');
  }
  if (r.metadata[AP2_METADATA_KEYS.agreementHash] !== verifiedAgreement.agreementHash) {
    throw new Error('AP2 extension: provider agreement binding does not match verified agreement');
  }
  if (r.amount !== verifiedAgreement.amount || r.currency !== verifiedAgreement.currency) {
    throw new Error('AP2 extension: provider amount/currency does not match verified agreement');
  }

  const structural = verifySettlementEvidenceV1(paymentEvidence);
  if (structural.decision !== 'pass') {
    throw new Error(`AP2 extension: linked payment evidence is invalid: ${structural.reasons.join('; ')}`);
  }
  const pay = paymentEvidence as MockAp2PaymentEvidence;
  if (pay.simulation !== true || pay.assurance !== AP2_SIMULATION_ASSURANCE
    || pay.verdict !== AP2_SIMULATION_VERDICT) {
    throw new Error('AP2 extension: linked payment evidence lacks signed mock/simulation assurance');
  }
  if (pay.jobId !== rec.jobId || pay.phase !== rec.phase || pay.phaseIndex !== rec.phaseIndex
    || pay.outcome !== 'success') {
    throw new Error('AP2 extension: record and payment evidence job/phase/outcome linkage mismatch');
  }
  if (pay.jobId !== verifiedAgreement.jobId || pay.phase !== verifiedAgreement.rail
    || pay.paymentAmount.amount !== verifiedAgreement.amount
    || pay.paymentAmount.currency !== verifiedAgreement.currency) {
    throw new Error('AP2 extension: payment evidence job/amount/currency/rail does not match verified agreement');
  }
  if (pay.paymentAmount.amount !== r.amount || pay.paymentAmount.currency !== r.currency) {
    throw new Error('AP2 extension: provider amount/currency does not match payment evidence');
  }
  if (pay.settlementFinality?.model !== 'provider-receipt'
    || pay.settlementFinality.finalityObservedAt !== r.capturedAt) {
    throw new Error('AP2 extension: provider capture does not match payment-evidence finality');
  }
  if (pay.paymentTxRefs.length !== 1) {
    throw new Error('AP2 extension: payment evidence must link exactly one AP2 provider receipt');
  }
  const [txRef] = pay.paymentTxRefs;
  if (!txRef || txRef.rail !== PAY_AP2_RAIL_ID
    || txRef.txHash !== `ap2:${r.providerTxId}` || txRef.kind !== 'payment') {
    throw new Error('AP2 extension: payment evidence txRef does not link this AP2 provider receipt');
  }
  if (rec.paymentEvidenceHash !== evidenceHashV1(pay)) {
    throw new Error('AP2 extension: paymentEvidenceHash does not bind the exact linked payment evidence');
  }

  return {
    ...ap2SimulationDisposition(),
    checks: {
      mockFacilitatorSignature: true,
      responseHash: true,
      agreementBinding: true,
      paymentTermsAndStatus: true,
      paymentEvidenceOneToOneLink: true,
    },
  };
}

/**
 * Buyer signs only after AP2 extension semantics pass. A buyer signature cannot launder a bad
 * receipt, stale response hash, broken agreement binding, or mismatched payment evidence.
 */
export function signAp2AttestedReceiptRecord(
  rec: Ap2AttestedReceiptRecord,
  paymentEvidence: SettlementEvidenceV1,
  verifiedAgreement: VerifiedAp2Agreement,
  signer: string,
  privKey: Uint8Array,
): Ap2AttestedReceiptRecord {
  verifyMockAp2AttestedReceiptRecord(rec, paymentEvidence, verifiedAgreement);
  const hashBytes = new TextEncoder().encode(ap2RecordHashHex(rec));
  const value = Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, hashBytes, privKey)).toString('base64');
  return { ...rec, signature: { algorithm: 'ed25519', signer, value } };
}
