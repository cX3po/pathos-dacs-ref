/**
 * Spec-conformant SettlementEvidence V1 emission (§9.7).
 *
 * This is the INDEPENDENT-EMISSION path: given the logical inputs of a settlement,
 * pathos constructs the §9.7 uniform evidence shape (`evidenceVersion: "1"`) such
 * that `evidenceHashV1(emitted)` byte-matches the dacs-sdk's evidenceHash for the
 * same logical settlement. That upgrades the settlement cross-impl claim from
 * "both re-hash the same shared fixture" to "both impls emit the same bytes".
 *
 * evidenceHash = sha256(JCS(evidence minus `signature`)) — the same canonical-form
 * discipline the AttestationBundle uses (src/lib/dacs-drift.ts evaluateSettlement),
 * so the field SET + values fully determine the hash (JCS sorts keys, so emission
 * order is irrelevant — only the present fields and their values matter).
 *
 * CLOSED, SANITIZING CONSTRUCTOR (F1): the emitter does NOT reuse caller-supplied
 * nested objects wholesale. EVERY nested object is rebuilt from explicit whitelisted
 * scalar subfields — paymentTxRefs entries → {rail,txHash,kind}; paymentAmount →
 * {amount,currency}; settlementFinality → {model,finalityBlocks?,finalityCommitmentLevel?,
 * finalityObservedAt}; deliverableAnchor → {kind,locator}. Any extra subfield a caller
 * smuggles in (e.g. paymentAmount.extra) is DROPPED before hashing, so a caller cannot
 * leak unhashed-by-the-SDK fields into the bytes and break cross-impl convergence.
 *
 * SCOPE (F5): only the §9.7 REQUIRED-for-success fields are constructed here. The §9.7
 * OPTIONAL fields are NOT YET SUPPORTED by this emitter:
 *   - reason                (failure-outcome explanation)
 *   - paymentFee            (PriceTerm)
 *   - attestationRef        (AttestationRef)
 *   - amendmentRefs         (AttestationRef[])
 *   - supersedesEvidenceRef (AttestationRef, the :resolved record)
 * The byte-match convergence is demonstrated on the payment + delivery SUCCESS fixtures
 * only. Extending to the optional fields + failure-with-reason records is future work.
 */

import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import { sign } from './sign.js';
import type {
  SettlementEvidenceV1,
  SettlementEvidenceV1Payment,
  SettlementEvidenceV1Delivery,
  SettlementSignatureV1,
  SettlementFinalityRecordV1,
  PaymentTxRefV1,
  SettlementPriceV1,
} from '../types/settle.js';

/** Common params present on both payment and delivery emission. */
interface EmitBase {
  jobId: string;
  phase: string;
  /**
   * Pipeline phase index. Matches the SDK/cross-impl fixture convention (phaseIndex
   * carried in the evidence body); the spec §9.7 type block does not list it — to be
   * reconciled with RB. (F4)
   */
  phaseIndex: number;
  outcome: 'success' | 'failure';
  observedAt: number;
  /** Optional object-form signature ({algorithm,signer,value}). Omitted by default. */
  signature?: SettlementSignatureV1;
}

/**
 * One payment tx reference, supplied as PRIMITIVES (not a nested object). The emitter
 * reconstructs the §9.7 ChainTxRef from exactly these three scalars.
 */
export interface EmitPaymentTxRef {
  rail: string;
  txHash: string;
  kind: string;
}

export interface EmitPaymentParams extends EmitBase {
  kind: 'payment';
  /** Each entry is reconstructed to EXACTLY {rail,txHash,kind} — extras dropped. */
  paymentTxRefs: EmitPaymentTxRef[];
  /** Reconstructed to EXACTLY {amount,currency}. */
  paymentAmount: string;
  paymentCurrency: string;
  /**
   * settlementFinality, supplied as PRIMITIVES; reconstructed to the whitelisted shape.
   * REQUIRED for outcome:'success' (PC-6). For outcome:'failure' the emitter OMITS
   * settlementFinality entirely (settlement.ts L240 — finality is forbidden outside
   * success-payment), so these may be left undefined on a failure record.
   */
  finalityModel?: SettlementFinalityRecordV1['model'];
  finalityObservedAt?: number;
  /** model === "block-depth": number of blocks waited (optional). */
  finalityBlocks?: number;
  /** model === "commitment-level": Solana commitment level (optional). */
  finalityCommitmentLevel?: SettlementFinalityRecordV1['finalityCommitmentLevel'];
  /** Optional failure-outcome explanation (§9.7 `reason`); ignored on success. */
  reason?: string;
}

export interface EmitDeliveryParams extends EmitBase {
  kind: 'delivery';
  deliverableContentHash: string;
  /** deliverableAnchor, supplied as PRIMITIVES; reconstructed to EXACTLY {kind,locator}. */
  deliverableAnchorKind: string;
  deliverableAnchorLocator: string;
}

export type EmitSettlementEvidenceV1Params = EmitPaymentParams | EmitDeliveryParams;

/**
 * Build a canonical §9.7 SettlementEvidence V1 record from its logical inputs.
 *
 * Unsigned by default; pass `signature` (object form) to attach a §9.7
 * ComponentSignature. The returned object carries the fixture/SDK field set for the
 * supported success variants — no extra fields — so JCS canonicalisation reproduces
 * the SDK's bytes.
 */
export function emitSettlementEvidenceV1(params: EmitSettlementEvidenceV1Params): SettlementEvidenceV1 {
  if (params.kind === 'payment') {
    // Rebuild each tx ref from EXACTLY the three whitelisted scalars — extras dropped.
    const paymentTxRefs: PaymentTxRefV1[] = params.paymentTxRefs.map((ref) => ({
      rail: ref.rail,
      txHash: ref.txHash,
      kind: ref.kind,
    }));
    // Rebuild paymentAmount from scalars.
    const paymentAmount: SettlementPriceV1 = {
      amount: params.paymentAmount,
      currency: params.paymentCurrency,
    };
    const ev: SettlementEvidenceV1Payment = {
      evidenceVersion: '1',
      jobId: params.jobId,
      phase: params.phase,
      phaseIndex: params.phaseIndex,
      outcome: params.outcome,
      paymentTxRefs,
      paymentAmount,
      observedAt: params.observedAt,
    };
    // PC-6 (settlement.ts L237/L240): settlementFinality is REQUIRED on a success
    // payment and FORBIDDEN on a failure payment. Only emit it on success — otherwise
    // the emitter would produce evidence its own verifier rejects. (F3)
    if (params.outcome === 'success') {
      // Rebuild settlementFinality from scalars; only present optional subfields are carried.
      const settlementFinality: SettlementFinalityRecordV1 = {
        model: params.finalityModel as SettlementFinalityRecordV1['model'],
        finalityObservedAt: params.finalityObservedAt as number,
      };
      if (params.finalityBlocks !== undefined) settlementFinality.finalityBlocks = params.finalityBlocks;
      if (params.finalityCommitmentLevel !== undefined) {
        settlementFinality.finalityCommitmentLevel = params.finalityCommitmentLevel;
      }
      ev.settlementFinality = settlementFinality;
    } else if (params.reason !== undefined) {
      // A failure payment may carry an optional explanation; finality stays omitted.
      ev.reason = params.reason;
    }
    if (params.signature !== undefined) ev.signature = params.signature;
    return ev;
  }
  const ev: SettlementEvidenceV1Delivery = {
    evidenceVersion: '1',
    jobId: params.jobId,
    phase: params.phase,
    phaseIndex: params.phaseIndex,
    outcome: params.outcome,
    deliverableContentHash: params.deliverableContentHash,
    // Rebuild deliverableAnchor from EXACTLY {kind,locator} — extras dropped.
    deliverableAnchor: { kind: params.deliverableAnchorKind, locator: params.deliverableAnchorLocator },
    observedAt: params.observedAt,
  };
  if (params.signature !== undefined) ev.signature = params.signature;
  return ev;
}

/**
 * evidenceHash = sha256(JCS(evidence minus `signature`)), hex.
 *
 * Same discipline as src/lib/dacs-drift.ts evaluateSettlement — the signature is
 * stripped before hashing, so a signed and an unsigned-but-otherwise-identical
 * record hash the same.
 */
export function evidenceHashV1(e: SettlementEvidenceV1): string {
  const { signature: _sig, ...unsigned } = e as SettlementEvidenceV1 & { signature?: unknown };
  void _sig;
  return jcsHashHex(unsigned);
}

/**
 * Attach a real ed25519 §9.7 signature over the canonical evidence hash.
 *
 * Referenced-artifact verification reconstructs the unsigned evidence, hashes its
 * JCS form, then verifies `dacs-evidence:v1:` || UTF8(hex evidenceHash). Keep that
 * byte contract here so producers cannot accidentally sign the evidence body.
 */
export function signSettlementEvidenceV1(
  evidence: SettlementEvidenceV1,
  signer: string,
  privKey: Uint8Array,
): SettlementEvidenceV1 {
  const hashBytes = new TextEncoder().encode(evidenceHashV1(evidence));
  const value = Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, hashBytes, privKey)).toString('base64');
  return { ...evidence, signature: { algorithm: 'ed25519', signer, value } };
}
