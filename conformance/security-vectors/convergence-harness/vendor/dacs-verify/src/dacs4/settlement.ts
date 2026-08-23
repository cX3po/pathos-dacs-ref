import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { verifyArtifactSignature } from "../signing.ts";
import { canonicalDecimal, assertPositiveAmount } from "../decimal.ts";
import { schemeOf, type ClaimReference } from "../dacs1.ts";
import { cf4Encode } from "../logical-address.ts";
import type { AttestationRef, ChainTxRef } from "../dacs5/bundle.ts";

// §9.4.3 / signing registry: the canonical AttestationRef.kind label for a DACS-4 SettlementEvidence reference.
const DACS4_EVIDENCE_KIND = "dacs-4-evidence";

export type SettlementDecision = "pass" | "fail" | "indeterminate" | "error";

// §5 (L222) — phase handler return
export type PhaseHandlerResult = {
  ok: boolean;
  reason?: string;
  txRefs?: ChainTxRef[];
  explorerUrls?: string[];
  contextDelta?: Record<string, unknown>;
  attestationRef?: AttestationRef;
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity";
};

// §9.7 (L2696) — uniform settlement record
export type SettlementEvidence = {
  evidenceVersion: "1";
  jobId: string;
  phase: PaymentPhaseType | DeliveryPhaseType;
  // §9.5.1 PC-2 (R5-3): repeated pay-* phases are discriminated by a fixed structural phaseIndex segment.
  phaseIndex: number;
  outcome: "success" | "failure";
  reason?: string;
  paymentTxRefs?: ChainTxRef[];
  paymentAmount?: PriceTerm;
  paymentFee?: PriceTerm;
  deliverableContentHash?: string;
  deliverableAnchor?: { kind: string; locator: string };
  attestationRef?: AttestationRef;
  // §9.5.1 PC-2 (R5-3): the optional :resolved record supersedes the interim asymmetric settlement evidence.
  supersedesEvidenceRef?: AttestationRef;
  settlementFinality?: SettlementFinalityRecord;
  amendmentRefs?: AttestationRef[];
  observedAt: number;
  signature: ComponentSignature;
};

export type SettlementFinalityRecord = {
  model: "block-depth" | "commitment-level" | "provider-receipt" | "htlc-reveal" | "liquidity-tank";
  finalityBlocks?: number;
  finalityCommitmentLevel?: "processed" | "confirmed" | "finalized";
  finalityObservedAt: number;
};

export type PaymentPhaseType = "pay-evm-erc20" | "pay-solana-spl" | "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank" | "pay-ap2" | "pay-x402";
export type DeliveryPhaseType = "deliver-storage-program" | "deliver-entitlement" | "deliver-attested-payload";

export type ComponentSignature = {
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate";
  signer: ClaimReference;
  value: string;
};

export type PriceTerm = { amount: string; currency: string };

// §9.4.1 (L2424)
export type RailDefinition = {
  railVersion: number;   // §9.4.1 L2426 / RD-3 L2534: the spec field IS railVersion (NOT registryVersion — that is the distinct railRegistryVersion on SessionContext/AttestationBundle)
  railId: string;
  railType: "evm-erc20" | "solana-spl" | "cross-chain-htlc" | "cross-chain-liquidity-tank" | "ap2" | "x402";
  asset: AssetSpec;
  network: NetworkSpec;
  phaseHandler: PaymentPhaseType;
  parameters: Record<string, unknown>;
  availability: RailAvailability;
  governance: { proposedBy: ClaimReference; acceptedAt: number; supersedes?: number; anchoring: "in-code" | "single-signer" | "multisig"; emergency?: { isEmergency: true; failureObservation: string }; deprecated?: boolean; deprecationReason?: string };
  signature: { algorithm: string; signer: ClaimReference; value: string };
};
export type RailAvailability = "live" | "operator_gated" | "closed_data" | "bilateral" | "mocked" | "disabled" | "failed";
export type AssetSpec =
  | { kind: "erc20"; chainId: number; contract: string; symbol: string; decimals: number }
  | { kind: "spl"; cluster: "mainnet" | "devnet" | "testnet"; mint: string; symbol: string; decimals: number }
  | { kind: "native-evm"; chainId: number; symbol: string; decimals: number }
  | { kind: "native-solana"; cluster: "mainnet" | "devnet" | "testnet"; symbol: "SOL"; decimals: 9 }
  | { kind: "fiat-via-ap2"; isoCurrency: string; provider: string }
  | { kind: "stablecoin-cross-chain"; canonicalSymbol: string; routes: unknown[] };
export type NetworkSpec =
  | { kind: "evm"; chainId: number; rpcAttestation: "consensus-backed-proxy" | "evm-rpc" }
  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet" }
  | { kind: "ap2-provider"; providerEndpoint: string }
  | { kind: "x402-resource"; resourceBaseUrl: string }
  | { kind: "cross-chain"; mechanism: "htlc" | "liquidity-tank" | "substrate-native" };

// §9.5.1 (L2562)
export type PaymentPhaseInput = {
  jobId: string;
  agreement: Record<string, unknown>;
  rail: RailDefinition;
  payer: { bundleHash: string; primaryClaim: ClaimReference; payingKey: ClaimReference };
  payee: { bundleHash: string; primaryClaim: ClaimReference; payeeAddress: string };
  amount: PriceTerm;
  sessionContext: Record<string, unknown>;
};

export const PAYMENT_PHASE_TYPES: ReadonlySet<PaymentPhaseType> = new Set([
  "pay-evm-erc20",
  "pay-solana-spl",
  "pay-cross-chain-htlc",
  "pay-cross-chain-liquidity-tank",
  "pay-ap2",
  "pay-x402",
]);

export const DELIVERY_PHASE_TYPES: ReadonlySet<DeliveryPhaseType> = new Set([
  "deliver-storage-program",
  "deliver-entitlement",
  "deliver-attested-payload",
]);

const ERROR_CLASSES: ReadonlySet<string> = new Set(["permanent", "transient", "counterparty", "substrate", "settlement-atomicity"]);
const SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);
const FINALITY_COMMITMENTS: ReadonlySet<string> = new Set(["processed", "confirmed", "finalized"]);
const HASH_RE = /^[0-9a-f]{64}$/;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map([...BASE58_ALPHABET].map((char, index) => [char, index]));
const SOLANA_SIGNATURE_MAX_BASE58_LENGTH = 88;

export function evidenceHash(evidence: SettlementEvidence): string {
  return sha256Hex(canonicalize(withoutSignature(evidence as unknown as Record<string, unknown>, "signature")));
}

export function paymentEvidenceAddress(jobId: string, railId: string, phaseIndex: number, resolved = false): string {
  return `dacs4:payment:${jobId}:${cf4Encode(railId)}:${phaseIndex}${resolved ? ":resolved" : ""}`;
}

export type SettlementTxObligation = {
  settlementTxId: string;
  jobId: string;
  phaseIndex: number;
};

export type SettlementTxReuseConflict = {
  settlementTxId: string;
  first: Omit<SettlementTxObligation, "settlementTxId">;
  second: Omit<SettlementTxObligation, "settlementTxId">;
};

export type SettlementTxUniquenessResult =
  | { decision: "pass"; consumed: SettlementTxObligation[] }
  | { decision: "fail"; conflict: SettlementTxReuseConflict; consumed: SettlementTxObligation[] }
  | { decision: "error"; reason: string; consumed: SettlementTxObligation[] };

export function settlementTxId(tx: ChainTxRef, phase?: PaymentPhaseType, finality?: SettlementFinalityRecord): string {
  const hasEvmCoordinates = tx.chainId !== undefined || tx.logIndex !== undefined;
  const hasSolanaCoordinates = tx.cluster !== undefined || tx.signature !== undefined || tx.instructionIndex !== undefined;

  if (hasEvmCoordinates && hasSolanaCoordinates) {
    throw new Error("invalid settlement tx ref: EVM and Solana coordinates must not be mixed");
  }
  if (phase === "pay-x402") validateX402TxKindFinality(tx, finality);
  if (phase !== undefined && requiresEvmEventCoordinates(phase, finality) && (tx.chainId === undefined || tx.logIndex === undefined)) {
    throw new Error("invalid EVM settlement tx ref: chainId and logIndex are required");
  }
  if (phase !== undefined && isSolanaSettlementPhase(phase) && (tx.cluster === undefined || tx.instructionIndex === undefined)) {
    throw new Error("invalid Solana settlement tx ref: cluster and instructionIndex are required");
  }

  if (hasEvmCoordinates) {
    const chainId = canonicalChainId(tx.chainId);
    const txHash = canonicalEvmTxHash(tx.txHash);
    const logIndex = canonicalIndex(tx.logIndex, "logIndex");
    return `evm:${chainId}:${txHash}:${logIndex}`;
  }

  if (hasSolanaCoordinates) {
    const cluster = canonicalCluster(tx.cluster);
    const signature = canonicalSolanaSignature(tx.txHash);
    if (tx.signature !== undefined && canonicalSolanaSignature(tx.signature) !== signature) {
      throw new Error("invalid Solana settlement tx ref: signature must match txHash");
    }
    const instructionIndex = canonicalIndex(tx.instructionIndex, "instructionIndex");
    return `solana:${cluster}:${signature}:${instructionIndex}`;
  }

  return `${cf4Encode(tx.rail)}:${cf4Encode(tx.kind ?? "")}:${cf4Encode(tx.txHash)}`;
}

export function verifySettlementTxUniqueness(evidenceSet: readonly SettlementEvidence[]): SettlementTxUniquenessResult {
  const consumed = new Map<string, Omit<SettlementTxObligation, "settlementTxId">>();
  const consumedList: SettlementTxObligation[] = [];

  for (const evidence of evidenceSet) {
    if (!PAYMENT_PHASE_TYPES.has(evidence.phase as PaymentPhaseType)) continue;
    if (evidence.outcome !== "success") continue;
    for (const tx of evidence.paymentTxRefs ?? []) {
      let id: string;
      try {
        id = settlementTxId(tx, evidence.phase as PaymentPhaseType, evidence.settlementFinality);
      } catch (error) {
        return { decision: "error", reason: error instanceof Error ? error.message : "invalid settlement tx ref", consumed: consumedList };
      }
      const next = { jobId: evidence.jobId, phaseIndex: evidence.phaseIndex };
      const prior = consumed.get(id);
      if (prior === undefined) {
        consumed.set(id, next);
        consumedList.push({ settlementTxId: id, ...next });
        continue;
      }
      if (prior.jobId !== next.jobId || prior.phaseIndex !== next.phaseIndex) {
        return { decision: "fail", conflict: { settlementTxId: id, first: prior, second: next }, consumed: consumedList };
      }
    }
  }

  return { decision: "pass", consumed: consumedList };
}

export function currencyResolves(amount: PriceTerm, asset: AssetSpec): boolean {
  switch (asset.kind) {
    case "erc20":
    case "spl":
    case "native-evm":
    case "native-solana":
      return amount.currency === asset.symbol;
    case "fiat-via-ap2":
      return amount.currency === asset.isoCurrency;
    case "stablecoin-cross-chain":
      return amount.currency === asset.canonicalSymbol;
  }
}

export function verifySettlementEvidence(input: {
  result: PhaseHandlerResult;
  evidence: SettlementEvidence;
  expectedOrchestrator: ClaimReference;   // the authorized phase-orchestrator signer (§9.7); caller supplies it from the session
  paymentInput?: PaymentPhaseInput;
  resolveKey: (signer: ClaimReference) => Uint8Array | null | undefined;
}): SettlementDecision {
  try {
    const { result, evidence, expectedOrchestrator, paymentInput, resolveKey } = input;

    // PC-1 (§9.5.1 L2559): handler result and evidence MUST match the closed structural shape.
    if (!isStructurallySupported(result, evidence, paymentInput)) return "fail";

    const isPayment = PAYMENT_PHASE_TYPES.has(evidence.phase as PaymentPhaseType);
    const isDelivery = DELIVERY_PHASE_TYPES.has(evidence.phase as DeliveryPhaseType);
    if (isPayment && paymentInput === undefined) return "fail";
    if (isDelivery && paymentInput !== undefined) return "fail";
    if (!isPayment && !isDelivery) return "fail";
    if (paymentInput !== undefined && evidence.jobId !== paymentInput.jobId) return "fail";

    // §9.4.1 (L2436) / §9.14 (L2624): one-to-one phase↔pinned-rail — evidence.phase MUST equal the rail's
    // declared phaseHandler. Otherwise signed evidence could claim a different handler than the rail selected
    // (e.g. a pay-solana-spl evidence verified against an evm-erc20 rail).
    if (isPayment && evidence.phase !== paymentInput!.rail.phaseHandler) return "fail";

    // PC-4 (§9.5.1 L2559): success has no errorClass; failure MUST carry a valid errorClass.
    if (result.ok === true && result.errorClass !== undefined) return "fail";
    if (result.ok === false && (result.errorClass === undefined || !ERROR_CLASSES.has(result.errorClass))) return "fail";
    // PC-4 (§9.7 L2696): settlement outcome records the phase-handler classification.
    if ((result.ok && evidence.outcome !== "success") || (!result.ok && evidence.outcome !== "failure")) return "fail";
    // PC-4 (§9.7 L2706): failure settlement evidence MUST explain the reason.
    if (evidence.outcome === "failure" && (typeof evidence.reason !== "string" || evidence.reason.length === 0)) return "fail";

    const computedHash = evidenceHash(evidence);
    if (!HASH_RE.test(computedHash)) return "error";

    const anchorPending = result.attestationRef === undefined && allowsCrossChainAnchorPending(result, evidence, paymentInput);
    if (result.attestationRef === undefined) {
      if (!anchorPending) return "fail";
    } else {
      // PC-3 (§9.5.1 L2559): the anchored reference MUST be labelled as DACS-4 evidence, not another artifact kind —
      // a consumer dispatching on AttestationRef.kind must not mistake a mislabelled ref for settlement evidence.
      if (result.attestationRef.kind !== DACS4_EVIDENCE_KIND) return "fail";
      if (isPayment) {
        const railId = paymentInput!.rail.railId;
        // §9.5.1 PC-2 (R5-3): CF-4 payment anchors are dacs4:payment:{jobId}:{railId}:{phaseIndex} with optional
        // trailing :resolved for the post-asymmetric record; phaseIndex/resolved are fixed structural segments.
        const baseId = paymentEvidenceAddress(evidence.jobId, railId, evidence.phaseIndex);
        const resolvedId = paymentEvidenceAddress(evidence.jobId, railId, evidence.phaseIndex, true);
        const isResolvedRecord = result.attestationRef.id === resolvedId;
        if (result.attestationRef.id !== baseId && !isResolvedRecord) return "fail";
        if (isResolvedRecord) {
          if (evidence.supersedesEvidenceRef === undefined) return "fail";
        } else if (evidence.supersedesEvidenceRef !== undefined) {
          return "fail";
        }
      } else if (evidence.phase === "deliver-entitlement") {
        // §9.6 (L2683): dacs4:entitlement:{jobId}:{renewalSeq} (renewalSeq a non-negative integer; 0 for the original grant).
        if (!new RegExp(`^dacs4:entitlement:${escapeRegExp(evidence.jobId)}:\\d+$`).test(result.attestationRef.id)) return "fail";
      } else {
        // §9.6 (L2647/L2689): deliver-storage-program / deliver-attested-payload anchor at dacs4:deliverable:{jobId}.
        if (result.attestationRef.id !== `dacs4:deliverable:${evidence.jobId}`) return "fail";
      }

      // PC-3 (§9.5.1 L2559): result.attestationRef MUST point to this exact signature-free evidence hash.
      if (result.attestationRef.contentHash !== computedHash) return "fail";
    }

    if (isPayment) {
      // PC-1/PC-3 (§9.5.1 L2559, §5 L228): the unsigned handler-return txRefs MUST match the signed evidence's
      // paymentTxRefs. The dacs-4-evidence signature covers paymentTxRefs only; a result advertising different
      // txRefs would let a consumer reading the handler return accept an uncovered settlement transaction.
      if (!txRefsEqual(result.txRefs, evidence.paymentTxRefs)) return "fail";

      // §9.5.1 (L2590) / PIPE-5 (L2837): PaymentPhaseInput.amount MUST equal agreement.terms.price — settling less
      // than the agreed price (underpayment) MUST NOT verify.
      const price = agreementPrice(paymentInput!.agreement);
      if (price === undefined || !priceEq(price, paymentInput!.amount)) return "fail";

      // PC-5 (§9.5.1 L2559): paymentAmount, when present, MUST equal paymentInput.amount.
      if (evidence.paymentAmount !== undefined && !priceEq(evidence.paymentAmount, paymentInput!.amount)) return "fail";

      // PC-5 (§9.5.1 L2559): handlers MUST NOT settle unresolved amount.currency.
      if (!currencyResolves(paymentInput!.amount, paymentInput!.rail.asset)) {
        if (!(result.ok === false && result.errorClass === "permanent")) return "fail";
      }
    }

    if (isPayment && evidence.outcome === "success") {
      // PC-6 (§9.7 L2724): success payment evidence MUST carry settlementFinality.
      if (evidence.settlementFinality === undefined) return "fail";
      if (!validPaymentFinality(evidence.settlementFinality, paymentInput!.rail)) return "fail";
    } else {
      // PC-6 (§9.7 L2724): delivery evidence and failure payment evidence MUST NOT carry settlementFinality.
      if (evidence.settlementFinality !== undefined) return "fail";
    }

    // §9.5.2-§9.6: the per-phase procedures populate phase-specific evidence on success — a success record that
    // omits it is not a valid settlement (defeats the audit value SettlementEvidence exists for).
    if (evidence.outcome === "success") {
      if (isPayment) {
        // §9.5.2-§9.5.7: EVERY payment success constructs a txRef of its kind (evm/solana/liquidity-tank/ap2/x402) —
        // incl. provider-receipt AP2 (L2630) and x402 even in the no-settlement-tx fallback (L2636). So a non-empty
        // paymentTxRefs requirement on payment success is correct for all rails, not over-constraining.
        if (evidence.paymentTxRefs === undefined || evidence.paymentTxRefs.length === 0) return "fail";
        if (!paymentTxRefsHaveCanonicalIds(evidence, paymentInput!.rail)) return "fail";
        if (evidence.paymentAmount === undefined) return "fail";
      } else {
        // §9.6 (L2647/L2689): storage-program & attested-payload deliveries produce a content hash + anchor;
        // attested-payload additionally carries the DACS-2 attestationRef. (deliver-entitlement anchors the
        // EntitlementRecord separately and is not required to carry a deliverableContentHash here.)
        if (evidence.phase === "deliver-storage-program" || evidence.phase === "deliver-attested-payload") {
          if (evidence.deliverableContentHash === undefined || evidence.deliverableAnchor === undefined) return "fail";
        }
        if (evidence.phase === "deliver-attested-payload" && evidence.attestationRef === undefined) return "fail";
        // SCOPE (open-world, SIG-5 §7.7 L290): §9.7 / PC-6 explicitly forbid only `settlementFinality` on delivery
        // evidence (enforced above). The spec does NOT forbid paymentTxRefs/paymentAmount/paymentFee on delivery, and
        // SIG-5 "preserve-unknown" mandates a verifier MAY ignore the meaning of inapplicable/unknown fields but MUST
        // NOT reject on their presence. So this §14 conformance verifier does not reject them — the consumer dispatches
        // on `phase`. Whether the spec should close delivery-evidence shape is a steward-facing question;
        // this verifier should not unilaterally out-strict the reference.
      }
    }

    // §9.7 (L2777): the evidence signer MUST be the authorized phase orchestrator — not merely a claim whose key
    // happens to resolve. (Mirrors §10.4.1 / bundle.ts binding each signature to a declared party.)
    if (evidence.signature.signer !== expectedOrchestrator) return "fail";

    if (evidence.signature.algorithm !== "ed25519") return "indeterminate";
    const publicKeyRaw = resolveKey(evidence.signature.signer);
    if (publicKeyRaw === null || publicKeyRaw === undefined) return "indeterminate";
    if (publicKeyRaw.length !== 32) return "error";

    const signatureRaw = new Uint8Array(Buffer.from(evidence.signature.value, "base64url"));
    const sigResult = verifyArtifactSignature({
      kind: "dacs-4-evidence",
      doc: evidence as unknown as Record<string, unknown>,
      publicKeyRaw,
      signatureRaw,
      signatureFields: ["signature"],
    });
    // §9.7 L2786: signature covers "dacs-evidence:v1:" || evidence_hash.
    if (sigResult.artifactHash !== computedHash) return "error";
    if (!sigResult.ok) return "fail";

    return "pass";
  } catch {
    return "error";
  }
}

function isStructurallySupported(result: PhaseHandlerResult, evidence: SettlementEvidence, paymentInput: PaymentPhaseInput | undefined): boolean {
  if (typeof result?.ok !== "boolean") return false;
  if (result.attestationRef !== undefined && !isAttestationRef(result.attestationRef)) return false;
  if (result.errorClass !== undefined && !ERROR_CLASSES.has(result.errorClass)) return false;
  if (result.txRefs !== undefined && (!Array.isArray(result.txRefs) || result.txRefs.some((tx) => !isChainTxRef(tx)))) return false;

  if (evidence?.evidenceVersion !== "1") return false;
  if (typeof evidence.jobId !== "string" || evidence.jobId.length === 0) return false;
  if (!PAYMENT_PHASE_TYPES.has(evidence.phase as PaymentPhaseType) && !DELIVERY_PHASE_TYPES.has(evidence.phase as DeliveryPhaseType)) return false;
  if (!Number.isSafeInteger(evidence.phaseIndex) || evidence.phaseIndex < 0) return false;
  if (evidence.outcome !== "success" && evidence.outcome !== "failure") return false;
  if (!Number.isSafeInteger(evidence.observedAt)) return false;
  if (!isComponentSignature(evidence.signature)) return false;
  if (evidence.paymentTxRefs !== undefined && (!Array.isArray(evidence.paymentTxRefs) || evidence.paymentTxRefs.some((tx) => !isChainTxRef(tx)))) return false;
  // §9.3 + CD-1: a settled paymentAmount MUST be canonical and positive; paymentFee MUST be canonical and non-negative.
  if (evidence.paymentAmount !== undefined && (!isPriceTerm(evidence.paymentAmount) || !isCanonicalPositiveAmount(evidence.paymentAmount.amount))) return false;
  if (evidence.paymentFee !== undefined && (!isPriceTerm(evidence.paymentFee) || !isCanonicalNonNegativeAmount(evidence.paymentFee.amount))) return false;
  if (evidence.attestationRef !== undefined && !isAttestationRef(evidence.attestationRef)) return false;
  if (evidence.supersedesEvidenceRef !== undefined && !isAttestationRef(evidence.supersedesEvidenceRef)) return false;
  if (evidence.amendmentRefs !== undefined && (!Array.isArray(evidence.amendmentRefs) || evidence.amendmentRefs.some((r) => !isAttestationRef(r)))) return false;
  if (evidence.deliverableAnchor !== undefined && (typeof evidence.deliverableAnchor.kind !== "string" || evidence.deliverableAnchor.kind.length === 0 || typeof evidence.deliverableAnchor.locator !== "string" || evidence.deliverableAnchor.locator.length === 0)) return false;
  // §9.6 (L2647): deliverableContentHash = sha256(canonical_payload) — MUST be a 64-char lowercase-hex hash, not arbitrary text.
  if (evidence.deliverableContentHash !== undefined && !HASH_RE.test(evidence.deliverableContentHash)) return false;
  if (evidence.settlementFinality !== undefined && !isSettlementFinality(evidence.settlementFinality)) return false;

  if (paymentInput !== undefined && !isPaymentPhaseInput(paymentInput)) return false;
  return true;
}

function isPaymentPhaseInput(input: PaymentPhaseInput): boolean {
  if (typeof input.jobId !== "string" || input.jobId.length === 0) return false;
  if (!input.agreement || typeof input.agreement !== "object" || Array.isArray(input.agreement)) return false;
  if (!isRailDefinition(input.rail)) return false;
  if (!isPartyInput(input.payer, "payingKey")) return false;
  if (!isPayeeInput(input.payee)) return false;
  // §9.3 + CD-1: the payment input amount (== agreement price) MUST be canonical and strictly positive.
  if (!isPriceTerm(input.amount) || !isCanonicalPositiveAmount(input.amount.amount)) return false;
  if (!input.sessionContext || typeof input.sessionContext !== "object" || Array.isArray(input.sessionContext)) return false;
  return true;
}

function isRailDefinition(rail: RailDefinition): boolean {
  if (!rail || typeof rail !== "object") return false;
  if (!Number.isSafeInteger(rail.railVersion)) return false;
  if (typeof rail.railId !== "string" || rail.railId.length === 0) return false;
  if (!["evm-erc20", "solana-spl", "cross-chain-htlc", "cross-chain-liquidity-tank", "ap2", "x402"].includes(rail.railType)) return false;
  if (!isAssetSpec(rail.asset)) return false;
  if (!rail.parameters || typeof rail.parameters !== "object" || Array.isArray(rail.parameters)) return false;
  // RD-5 (§9.4.3 L2534): railType ↔ phaseHandler is one-to-one — an incoherent pairing is rejected.
  if (RAIL_TYPE_TO_HANDLER[rail.railType] !== rail.phaseHandler) return false;
  // RD-5: railType MUST match the asset AND network kinds (e.g. an evm-erc20 rail with a Solana network is rejected).
  if (!isNetworkSpec(rail.network)) return false;
  if (!railTypeMatchesAssetAndNetwork(rail)) return false;
  if (rail.railType === "cross-chain-htlc" && !validHtlcRailParameters(rail)) return false;
  return true;
}

function isAssetSpec(asset: AssetSpec): boolean {
  if (!asset || typeof asset !== "object") return false;
  switch (asset.kind) {
    case "erc20":
      return Number.isSafeInteger(asset.chainId) && typeof asset.contract === "string" && asset.contract.length > 0 && isSymbolDecimals(asset);
    case "spl":
      return ["mainnet", "devnet", "testnet"].includes(asset.cluster) && typeof asset.mint === "string" && asset.mint.length > 0 && isSymbolDecimals(asset);
    case "native-evm":
      return Number.isSafeInteger(asset.chainId) && isSymbolDecimals(asset);
    case "native-solana":
      return ["mainnet", "devnet", "testnet"].includes(asset.cluster) && asset.symbol === "SOL" && asset.decimals === 9;
    case "fiat-via-ap2":
      return typeof asset.isoCurrency === "string" && asset.isoCurrency.length > 0 && typeof asset.provider === "string" && asset.provider.length > 0;
    case "stablecoin-cross-chain":
      return typeof asset.canonicalSymbol === "string" && asset.canonicalSymbol.length > 0 && Array.isArray(asset.routes);
  }
}

function isSymbolDecimals(asset: { symbol: string; decimals: number }): boolean {
  return typeof asset.symbol === "string" && asset.symbol.length > 0 && Number.isSafeInteger(asset.decimals);
}

function isNetworkSpec(network: NetworkSpec): boolean {
  if (!network || typeof network !== "object") return false;
  switch (network.kind) {
    case "evm":
      return Number.isSafeInteger(network.chainId) && (network.rpcAttestation === "consensus-backed-proxy" || network.rpcAttestation === "evm-rpc");
    case "solana":
      return ["mainnet", "devnet", "testnet"].includes(network.cluster);
    case "ap2-provider":
      return typeof network.providerEndpoint === "string" && network.providerEndpoint.length > 0;
    case "x402-resource":
      return typeof network.resourceBaseUrl === "string" && network.resourceBaseUrl.length > 0;
    case "cross-chain":
      return network.mechanism === "htlc" || network.mechanism === "liquidity-tank" || network.mechanism === "substrate-native";
    default:
      return false;
  }
}

// RD-5 (§9.4.3 L2534): railType MUST match both the asset kind and the network kind, per the §9.5.2-§9.5.7 procedures.
// (x402's procedure (L2636) pins only network.kind == "x402-resource", not a single asset kind, so asset is unconstrained there.)
// SCOPE: this checks asset/network KINDS — the spec's stated RD-5/§9.5.2 conformance bar. It deliberately does NOT
// require asset.chainId === network.chainId: that equality is not a spec MUST (RD-5 says "kinds"), and a §14 conformance
// verifier must not out-strict the spec and false-fail a spec-conformant rail.
function railTypeMatchesAssetAndNetwork(rail: RailDefinition): boolean {
  switch (rail.railType) {
    case "evm-erc20":
      return rail.asset.kind === "erc20" && rail.network.kind === "evm";
    case "solana-spl":
      return rail.asset.kind === "spl" && rail.network.kind === "solana";
    case "cross-chain-htlc":
      return rail.asset.kind === "stablecoin-cross-chain" && rail.network.kind === "cross-chain" && rail.network.mechanism === "htlc";
    case "cross-chain-liquidity-tank":
      return rail.asset.kind === "stablecoin-cross-chain" && rail.network.kind === "cross-chain" && rail.network.mechanism === "liquidity-tank";
    case "ap2":
      return rail.asset.kind === "fiat-via-ap2" && rail.network.kind === "ap2-provider";
    case "x402":
      return rail.network.kind === "x402-resource";
  }
}

function isPartyInput(value: { bundleHash: string; primaryClaim: ClaimReference; payingKey: ClaimReference }, key: "payingKey"): boolean {
  if (!value || typeof value !== "object") return false;
  if (!HASH_RE.test(value.bundleHash)) return false;
  if (!validClaim(value.primaryClaim)) return false;
  return key === "payingKey" && validClaim(value.payingKey);
}

function isPayeeInput(value: { bundleHash: string; primaryClaim: ClaimReference; payeeAddress: string }): boolean {
  if (!value || typeof value !== "object") return false;
  return HASH_RE.test(value.bundleHash) && validClaim(value.primaryClaim) && typeof value.payeeAddress === "string" && value.payeeAddress.length > 0;
}

function isPriceTerm(term: PriceTerm): boolean {
  return typeof term?.amount === "string" && term.amount.length > 0 && typeof term.currency === "string" && term.currency.length > 0;
}

function isComponentSignature(sig: ComponentSignature): boolean {
  return SIGNATURE_ALGORITHMS.has(sig?.algorithm) && validClaim(sig.signer) && typeof sig.value === "string" && sig.value.length > 0;
}

function isSettlementFinality(finality: SettlementFinalityRecord): boolean {
  if (!["block-depth", "commitment-level", "provider-receipt", "htlc-reveal", "liquidity-tank"].includes(finality?.model)) return false;
  if (!Number.isSafeInteger(finality.finalityObservedAt)) return false;
  if (finality.finalityBlocks !== undefined && !Number.isSafeInteger(finality.finalityBlocks)) return false;
  if (finality.finalityCommitmentLevel !== undefined && !FINALITY_COMMITMENTS.has(finality.finalityCommitmentLevel)) return false;
  return true;
}

function validPaymentFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  switch (rail.railType) {
    case "evm-erc20":
      return blockDepthFinality(finality, rail);
    case "solana-spl":
      return commitmentFinality(finality, rail);
    case "cross-chain-htlc":
      return finality.model === "htlc-reveal" && validHtlcRailParameters(rail);
    case "cross-chain-liquidity-tank":
      return finality.model === "liquidity-tank";
    case "ap2":
      return finality.model === "provider-receipt";
    case "x402":
      // PC-6 (§9.7 L2745): x402 normally has block-depth; provider-receipt is accepted for no-settlement-tx fallback.
      return finality.model === "provider-receipt" || blockDepthFinality(finality, rail);
  }
}

function allowsCrossChainAnchorPending(
  result: PhaseHandlerResult,
  evidence: SettlementEvidence,
  paymentInput: PaymentPhaseInput | undefined,
): boolean {
  if (paymentInput === undefined) return false;
  if (result.ok !== true || evidence.outcome !== "success") return false;
  if (evidence.settlementFinality === undefined) return false;
  return paymentInput.rail.railType === "cross-chain-htlc" || paymentInput.rail.railType === "cross-chain-liquidity-tank";
}

function validHtlcRailParameters(rail: RailDefinition): boolean {
  const timelockSourceSec = integerParameter(rail.parameters, "timelockSourceSec", 1);
  const timelockDestSec = integerParameter(rail.parameters, "timelockDestSec", 1);
  const sourceFinalitySec = integerParameter(rail.parameters, "sourceFinalitySec", 0);
  const safetyWindowSec = integerParameter(rail.parameters, "safetyWindowSec", 0);
  if (timelockSourceSec === undefined || timelockDestSec === undefined || sourceFinalitySec === undefined || safetyWindowSec === undefined) return false;
  // HTLC-7: expiry_source > expiry_dest + source_finality + safety, evaluated against pinned rail params.
  return timelockSourceSec > timelockDestSec + sourceFinalitySec + safetyWindowSec;
}

function integerParameter(parameters: Record<string, unknown>, key: string, min: number): number | undefined {
  const value = parameters[key];
  return Number.isSafeInteger(value) && typeof value === "number" && value >= min ? value : undefined;
}

function blockDepthFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  return finality.model === "block-depth"
    && Number.isSafeInteger(finality.finalityBlocks)
    && finality.finalityBlocks === rail.parameters.finalityBlocks;
}

function commitmentFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  return finality.model === "commitment-level"
    && typeof finality.finalityCommitmentLevel === "string"
    && finality.finalityCommitmentLevel === rail.parameters.commitmentLevel;
}

function isAttestationRef(ref: AttestationRef): boolean {
  return typeof ref?.kind === "string" && ref.kind.length > 0
    && typeof ref.id === "string" && ref.id.length > 0
    && HASH_RE.test(ref.contentHash);
}

function isChainTxRef(tx: ChainTxRef): boolean {
  const hasEvmCoordinates = tx?.chainId !== undefined || tx?.logIndex !== undefined;
  const hasSolanaCoordinates = tx?.cluster !== undefined || tx?.signature !== undefined || tx?.instructionIndex !== undefined;
  return typeof tx?.rail === "string" && tx.rail.length > 0
    && typeof tx.txHash === "string" && tx.txHash.length > 0
    && !(hasEvmCoordinates && hasSolanaCoordinates)
    && (tx.signature === undefined || tx.signature === tx.txHash)
    && optionalChainId(tx.chainId)
    && optionalNonEmptyString(tx.cluster)
    && optionalNonEmptyString(tx.signature)
    && optionalSafeNonNegativeInteger(tx.logIndex)
    && optionalSafeNonNegativeInteger(tx.instructionIndex);
}

function priceEq(a: PriceTerm, b: PriceTerm): boolean {
  return a.amount === b.amount && a.currency === b.currency;
}

// §8.5.2: AgreementDocument.terms.price is the agreed PriceTerm. Read it defensively from the opaque agreement.
function agreementPrice(agreement: Record<string, unknown>): PriceTerm | undefined {
  const terms = (agreement as { terms?: unknown }).terms;
  if (terms === null || typeof terms !== "object") return undefined;
  const price = (terms as { price?: unknown }).price;
  if (price === null || typeof price !== "object") return undefined;
  const p = price as { amount?: unknown; currency?: unknown };
  if (typeof p.amount !== "string" || typeof p.currency !== "string") return undefined;
  return { amount: p.amount, currency: p.currency };
}

// §9.4.2/§9.4.3 (RD-5): each railType has exactly one pay-* phase handler. An incoherent pairing MUST be rejected.
const RAIL_TYPE_TO_HANDLER: Record<RailDefinition["railType"], PaymentPhaseType> = {
  "evm-erc20": "pay-evm-erc20",
  "solana-spl": "pay-solana-spl",
  "cross-chain-htlc": "pay-cross-chain-htlc",
  "cross-chain-liquidity-tank": "pay-cross-chain-liquidity-tank",
  "ap2": "pay-ap2",
  "x402": "pay-x402",
};

// CD-1 (§7.1/§8.5.2 L2148): a PriceTerm.amount MUST be in minimal canonical decimal form (no leading/trailing
// zeros, no sign/exponent). canonicalDecimal throws on malformed input and normalises; equality with the input
// proves the input was already canonical.
function isCanonicalAmount(amount: string): boolean {
  try {
    return canonicalDecimal(amount) === amount;
  } catch {
    return false;
  }
}

// §9.3 + CD-1: a settled amount MUST be canonical AND strictly positive (> 0).
function isCanonicalPositiveAmount(amount: string): boolean {
  if (!isCanonicalAmount(amount)) return false;
  try {
    assertPositiveAmount(amount);
    return true;
  } catch {
    return false;
  }
}

// CD-1 + §9.7: a paymentFee MUST be canonical and non-negative — it may be "0" but never negative.
function isCanonicalNonNegativeAmount(amount: string): boolean {
  if (!isCanonicalAmount(amount)) return false;
  if (amount === "0") return true;
  try {
    assertPositiveAmount(amount);
    return true;
  } catch {
    return false;
  }
}

function txRefsEqual(a: ChainTxRef[] | undefined, b: ChainTxRef[] | undefined): boolean {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  if (a.length !== b.length) return false;
  return a.every((tx, i) => {
    const other = b[i]!;
    return tx.rail === other.rail
      && tx.txHash === other.txHash
      && tx.kind === other.kind
      && tx.chainId === other.chainId
      && tx.cluster === other.cluster
      && tx.signature === other.signature
      && tx.logIndex === other.logIndex
      && tx.instructionIndex === other.instructionIndex;
  });
}

function paymentTxRefsHaveCanonicalIds(evidence: SettlementEvidence, rail: RailDefinition): boolean {
  for (const tx of evidence.paymentTxRefs ?? []) {
    try {
      settlementTxId(tx, evidence.phase as PaymentPhaseType, evidence.settlementFinality);
    } catch {
      return false;
    }
    if (!txRefMatchesRail(tx, rail)) return false;
  }
  return true;
}

function txRefMatchesRail(tx: ChainTxRef, rail: RailDefinition): boolean {
  if (tx.rail !== rail.railId) return false;
  if (tx.chainId !== undefined || tx.logIndex !== undefined) {
    const expected = evmChainIdForRail(rail);
    return expected !== undefined && canonicalChainId(tx.chainId) === String(expected);
  }
  if (tx.cluster !== undefined || tx.signature !== undefined || tx.instructionIndex !== undefined) {
    const expected = solanaClusterForRail(rail);
    return expected !== undefined && canonicalCluster(tx.cluster) === expected;
  }
  return true;
}

function evmChainIdForRail(rail: RailDefinition): number | undefined {
  if (rail.network.kind === "evm") return rail.network.chainId;
  if (rail.asset.kind === "erc20" || rail.asset.kind === "native-evm") return rail.asset.chainId;
  return undefined;
}

function solanaClusterForRail(rail: RailDefinition): "mainnet" | "devnet" | "testnet" | undefined {
  if (rail.network.kind === "solana") return rail.network.cluster;
  if (rail.asset.kind === "spl" || rail.asset.kind === "native-solana") return rail.asset.cluster;
  return undefined;
}

function canonicalChainId(chainId: ChainTxRef["chainId"]): string {
  if (typeof chainId === "number" && Number.isSafeInteger(chainId) && chainId >= 0) return String(chainId);
  if (typeof chainId === "string" && /^[0-9]+$/.test(chainId)) {
    const parsed = Number(chainId);
    if (Number.isSafeInteger(parsed) && String(parsed) === chainId) return chainId;
  }
  throw new Error("invalid EVM settlement tx ref: chainId is required");
}

function canonicalEvmTxHash(txHash: string): string {
  const hex = txHash.startsWith("0x") || txHash.startsWith("0X") ? txHash.slice(2) : txHash;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("invalid EVM settlement tx ref: txHash must be 64 hex bytes");
  return hex.toLowerCase();
}

function canonicalCluster(cluster: ChainTxRef["cluster"]): string {
  if (cluster === "mainnet" || cluster === "devnet" || cluster === "testnet") return cluster;
  throw new Error("invalid Solana settlement tx ref: cluster is required");
}

function canonicalSolanaSignature(signature: string): string {
  if (signature.length === 0 || signature.length > SOLANA_SIGNATURE_MAX_BASE58_LENGTH) {
    throw new Error("invalid Solana settlement tx ref: signature must be base58 and decode to exactly 64 bytes");
  }
  const decoded = decodeBase58(signature);
  if (decoded?.length === 64) return signature;
  throw new Error("invalid Solana settlement tx ref: signature must be base58 and decode to exactly 64 bytes");
}

function canonicalIndex(index: number | undefined, label: "logIndex" | "instructionIndex"): number {
  if (Number.isSafeInteger(index) && typeof index === "number" && index >= 0) return index;
  throw new Error(`invalid settlement tx ref: ${label} is required`);
}

function decodeBase58(value: string): Uint8Array | undefined {
  if (value.length === 0) return undefined;
  const bytes = [0];
  for (const char of value) {
    const digit = BASE58_INDEX.get(char);
    if (digit === undefined) return undefined;
    let carry = digit;
    for (let i = 0; i < bytes.length; i += 1) {
      const next = bytes[i]! * 58 + carry;
      bytes[i] = next & 0xff;
      carry = next >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of value) {
    if (char !== "1") break;
    bytes.push(0);
  }
  const decoded = bytes.reverse();
  if (decoded.length > 1 && decoded.every((byte) => byte === 0)) decoded.shift();
  return Uint8Array.from(decoded);
}

function optionalChainId(chainId: ChainTxRef["chainId"]): boolean {
  return chainId === undefined
    || (typeof chainId === "number" && Number.isSafeInteger(chainId) && chainId >= 0)
    || (typeof chainId === "string" && /^[0-9]+$/.test(chainId) && String(Number(chainId)) === chainId);
}

function optionalNonEmptyString(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && value.length > 0);
}

function optionalSafeNonNegativeInteger(value: unknown): boolean {
  return value === undefined || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
}

function requiresEvmEventCoordinates(phase: PaymentPhaseType, finality?: SettlementFinalityRecord): boolean {
  if (phase === "pay-evm-erc20") return true;
  if (phase !== "pay-x402") return false;
  if (finality?.model === "provider-receipt") return false;
  return true;
}

function validateX402TxKindFinality(tx: ChainTxRef, finality?: SettlementFinalityRecord): void {
  const receiptKind = tx.kind === "provider-receipt";
  const receiptFinality = finality?.model === "provider-receipt";
  if (receiptKind !== receiptFinality) {
    throw new Error("invalid x402 settlement tx ref: provider-receipt kind requires provider-receipt finality");
  }
}

function isSolanaSettlementPhase(phase: PaymentPhaseType): boolean {
  return phase === "pay-solana-spl";
}

function validClaim(claim: ClaimReference): boolean {
  if (typeof claim !== "string" || claim.length === 0) return false;
  try {
    schemeOf(claim);
    return true;
  } catch {
    return false;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
