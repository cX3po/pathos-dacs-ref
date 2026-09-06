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
 * scalar subfields — paymentTxRefs entries → their ChainTxRef arm's members; paymentAmount →
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
  outcome: 'success' | 'failure';
  observedAt: number;
  /** Optional object-form signature ({algorithm,signer,value}). Omitted by default. */
  signature?: SettlementSignatureV1;
}

/** One payment tx reference: a §9.7 ChainTxRef arm, or the legacy {rail, txHash, kind} form. Rebuilt per arm from whitelisted scalars. */
export type EmitPaymentTxRef = PaymentTxRefV1;

const SPEC_ONLY_MEMBERS = new Set(['chainId', 'blockNumber', 'address', 'writeTxHash', 'logIndex', 'cluster', 'signature', 'instructionIndex', 'httpResource',
  'paymentReceiptHash', 'settlementTxHash', 'protocolVersion', 'mandateId', 'providerRef', 'receiptAttestation', 'contractAddress', 'lockTxHash', 'revealTxHash',
  'claimTxHash', 'refundTxHash', 'bridgeId', 'sourceChainId', 'destChainId', 'releaseTxHash', 'recoveryDeadline']);
const opt = <T,>(k: string, v: T | undefined): Record<string, T> => (v !== undefined ? { [k]: v } : {});
function rebuildTxRef(ref: EmitPaymentTxRef): PaymentTxRefV1 {
  if ('rail' in ref) {
    // The legacy form is exactly {rail, txHash, kind?}; a legacy entry that also carries a spec-arm member is neither form.
    if (Object.keys(ref).some((k) => SPEC_ONLY_MEMBERS.has(k))) throw new Error('paymentTxRefs entry mixes the legacy {rail,txHash,kind} form with ChainTxRef members');
    return { rail: ref.rail, txHash: ref.txHash, ...opt('kind', ref.kind) };
  }
  switch (ref.kind) {
    case 'demos': return { kind: 'demos', txHash: ref.txHash, ...opt('blockNumber', ref.blockNumber) };
    case 'storage-program': return { kind: 'storage-program', address: ref.address, writeTxHash: ref.writeTxHash };
    case 'evm': return { kind: 'evm', chainId: ref.chainId, txHash: ref.txHash };
    case 'evm-event': return { kind: 'evm-event', chainId: ref.chainId, txHash: ref.txHash, logIndex: ref.logIndex };
    case 'solana': return { kind: 'solana', cluster: ref.cluster, signature: ref.signature };
    case 'solana-instruction': return { kind: 'solana-instruction', cluster: ref.cluster, signature: ref.signature, instructionIndex: ref.instructionIndex };
    case 'x402': return { kind: 'x402', httpResource: ref.httpResource, paymentReceiptHash: ref.paymentReceiptHash, protocolVersion: ref.protocolVersion,
      ...opt('settlementTxHash', ref.settlementTxHash), ...opt('chainId', ref.chainId) };
    case 'x402-event': return { kind: 'x402-event', httpResource: ref.httpResource, paymentReceiptHash: ref.paymentReceiptHash, settlementTxHash: ref.settlementTxHash,
      chainId: ref.chainId, logIndex: ref.logIndex, protocolVersion: ref.protocolVersion };
    case 'ap2': return { kind: 'ap2', mandateId: ref.mandateId, providerRef: ref.providerRef, protocolVersion: ref.protocolVersion,
      ...(ref.receiptAttestation !== undefined ? { receiptAttestation: { anchor: { kind: ref.receiptAttestation.anchor.kind, locator: ref.receiptAttestation.anchor.locator },
        contentHash: ref.receiptAttestation.contentHash, ...opt('signer', ref.receiptAttestation.signer) } } : {}) };
    case 'htlc-lock': return { kind: 'htlc-lock', chainId: ref.chainId, contractAddress: ref.contractAddress, lockTxHash: ref.lockTxHash };
    case 'htlc-reveal': return { kind: 'htlc-reveal', chainId: ref.chainId, contractAddress: ref.contractAddress, revealTxHash: ref.revealTxHash };
    case 'htlc-claim': return { kind: 'htlc-claim', chainId: ref.chainId, contractAddress: ref.contractAddress, claimTxHash: ref.claimTxHash };
    case 'htlc-refund': return { kind: 'htlc-refund', chainId: ref.chainId, contractAddress: ref.contractAddress, refundTxHash: ref.refundTxHash };
    case 'liquidity-tank': return { kind: 'liquidity-tank', bridgeId: ref.bridgeId, sourceChainId: ref.sourceChainId, destChainId: ref.destChainId, lockTxHash: ref.lockTxHash,
      ...opt('releaseTxHash', ref.releaseTxHash), ...opt('recoveryDeadline', ref.recoveryDeadline) };
    default: throw new Error(`unknown ChainTxRef kind ${String((ref as { kind: unknown }).kind)}`);
  }
}

export interface EmitPaymentParams extends EmitBase {
  kind: 'payment';
  /** Each entry is rebuilt from its arm's whitelisted members — extras dropped. */
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
    // Rebuild each tx ref from its arm's whitelisted members — extras dropped.
    const paymentTxRefs: PaymentTxRefV1[] = params.paymentTxRefs.map(rebuildTxRef);
    // Rebuild paymentAmount from scalars.
    const paymentAmount: SettlementPriceV1 = {
      amount: params.paymentAmount,
      currency: params.paymentCurrency,
    };
    const ev: SettlementEvidenceV1Payment = {
      evidenceVersion: '1',
      jobId: params.jobId,
      phase: params.phase,
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
