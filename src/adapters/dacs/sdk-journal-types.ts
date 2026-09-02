/** vendored from DACS-Agent-commerce/dacs-sdk @ 12c5ad3; replace with the package import when published */

/** Durable authority for Demos wallet nonce and write recovery. */

export const DEMOS_WRITE_JOURNAL_VERSION = 1;

export type DemosWriteKind = "mutable" | "immutable";
export type DemosWriteOperation = "create" | "update";

export type DemosWriteStage =
  | "prepared"
  | "signed"
  | "broadcast-intent"
  | "canonical-confirmed"
  | "canonical-failed"
  | "native-visible"
  | "index-visible";

export interface DemosWriteJournalKey {
  /** Hash of the chain's genesis block, obtained from the connected node. */
  chainIdentity: string;
  /** Lower-case Demos wallet address. */
  wallet: string;
}

export interface DemosNativeReadObservation {
  owner: string;
  programName: string;
  valueHash: string;
  metadataHash?: string;
  observedAt: number;
}

export interface DemosIndexObservation {
  address: string;
  observedAt: number;
}

export interface DemosWriteJournalRecord {
  writeId: string;
  generation: number;
  kind: DemosWriteKind;
  operation: DemosWriteOperation;
  stage: DemosWriteStage;
  logicalName: string;
  programName: string;
  owner: string;
  nativeAddress: string;
  valueHash: string;
  metadataHash?: string;
  nonce: number;
  txRef?: string;
  /** Canonical portable encoding of the signed Demos transaction envelope. */
  signedTransaction?: string;
  signedTransactionHash?: string;
  blockNumber?: number;
  blockHash?: string;
  blockTimestamp?: number;
  finalityProof?: string;
  finalityProofHash?: string;
  nativeRead?: DemosNativeReadObservation;
  indexRead?: DemosIndexObservation;
  updatedAt: number;
}

export interface DemosWriteJournalSnapshot extends DemosWriteJournalKey {
  version: typeof DEMOS_WRITE_JOURNAL_VERSION;
  generation: number;
  records: readonly DemosWriteJournalRecord[];
}

/**
 * Exclusive, generation-fenced wallet lease. Implementations must serialize
 * leases across processes that share the same journal backend.
 */
export interface DemosWriteJournalLease {
  readonly key: Readonly<DemosWriteJournalKey>;
  readonly generation: number;
  readonly snapshot: Readonly<DemosWriteJournalSnapshot>;
  /** Replace or append one record while retaining the wallet fence. */
  put(record: DemosWriteJournalRecord): Promise<void>;
  /** Fail if another generation has superseded this worker. */
  assertCurrent(): Promise<void>;
  /** Idempotently release the exclusive wallet lease. */
  release(): Promise<void>;
}

export interface DemosWriteJournal {
  acquire(key: DemosWriteJournalKey): Promise<DemosWriteJournalLease>;
}

/** §9.7 settlement finality models (PC-6 — the actual model applied). */
export type SettlementFinalityModel =
  | "block-depth"
  | "commitment-level"
  | "provider-receipt"
  | "htlc-reveal"
  | "liquidity-tank"
  | "bft-final";

/** Commitment levels permitted by the DACS-4 §9.7 commitment-level model. */
export type SettlementCommitmentLevel =
  | "processed"
  | "confirmed"
  | "finalized";

/**
 * Optional model-specific DACS-4 §9.7 echoes reported by a settlement rail.
 * Parameters belong only to their discriminated model; omission remains valid.
 */
export type SettlementFinalityParameters =
  | {
      model: "block-depth";
      finalityBlocks?: number;
      finalityCommitmentLevel?: never;
    }
  | {
      model: "commitment-level";
      finalityBlocks?: never;
      finalityCommitmentLevel?: SettlementCommitmentLevel;
    }
  | {
      model: Exclude<SettlementFinalityModel, "block-depth" | "commitment-level">;
      finalityBlocks?: never;
      finalityCommitmentLevel?: never;
    };

export interface SettleResult {
  ok: boolean;
  txHash: string;
  chainId: string;
  payer: string;
  payee: string;
  /**
   * Rail-specific finality (§9.5.x / PC-6). When a rail knows the finality model
   * it settled under, it reports it here and runSessionCore records it on the
   * evidence instead of the default provider-receipt. E.g. §9.5.9 pay-dem →
   * `{ model: "bft-final" }`. Omit for a receipt-confirmed rail.
   */
  finality?: SettlementFinalityParameters;
  /** Block/ledger height the settlement landed at, when the rail reports it (§9.5.9 `demos`). */
  blockNumber?: number;
  /** The txRef kind the rail's tx is (e.g. §9.5.9 `demos`); defaults to `payment`. */
  txRefKind?: string;
}

/**
 * Reconcile an unresolved settlement intent against the rail/chain. Returns the
 * definitive {@link SettleResult} if the prior payment provably LANDED; `null` if
 * it provably did NOT (so a resubmit is safe); and THROWS if it cannot tell — the
 * indeterminate case must fail closed rather than risk a double-pay.
 */
export type SettlementReconcile = (key: string) => Promise<SettleResult | null>;

/**
 * Durable-capable persistence for the write-ahead protocol: definitive outcomes
 * and in-flight intents. Every method is async so a real backend (fs, the #55
 * SessionStore, a KV) can implement it; the default is in-process.
 */
export interface SettlementLog {
  /** The recorded definitive outcome for `key`, if the payment landed. */
  getOutcome(key: string): Promise<SettleResult | undefined>;
  /** Record a definitive outcome — called only after value provably moved. */
  putOutcome(key: string, res: SettleResult): Promise<void>;
  /**
   * ATOMICALLY claim the intent to submit `key` (put-if-absent). Returns
   * `"claimed"` if this caller set the intent — it MUST proceed to submit — or
   * `"held"` if an intent already exists (a concurrent submit, or a crashed prior
   * attempt): the caller MUST NOT submit; it reconciles or fails closed.
   */
  claimIntent(key: string): Promise<"claimed" | "held">;
  /**
   * Release a claim ONLY when the rail RETURNED proof no value moved (a result
   * with no tx identity). A tx-bearing or thrown submit leaves the claim in place.
   */
  releaseIntent(key: string): Promise<void>;
}

export interface SettlementIdempotencyStore {
  /**
   * Run `submit` AT MOST ONCE for `key` under the write-ahead protocol above.
   * `reconcile`, when supplied, resolves an unresolved prior intent; without it
   * an unresolved intent fails closed rather than resubmitting.
   */
  once(
    key: string,
    submit: () => Promise<SettleResult>,
    reconcile?: SettlementReconcile,
  ): Promise<SettleResult>;
}
