/**
 * vendored from DACS-Agent-commerce/dacs-sdk @ 12c5ad3; replace with the package import when published
 *
 * TYPE shapes only. No SDK implementation is copied into this repository.
 */

export interface SettlementFinalityParameters {
  model: string;
  finalityBlocks?: number;
  finalityCommitmentLevel?: string;
}

export interface SettleResult {
  ok: boolean;
  txHash: string;
  chainId: string;
  payer: string;
  payee: string;
  finality?: SettlementFinalityParameters;
  blockNumber?: number;
  txRefKind?: string;
}

export interface PayDemSettleParams {
  recipient: string;
  /** Integer OS base units, as a canonical positive integer string. */
  amount: string;
  network?: string;
  recovery?: Readonly<PayDemSettlementRecoveryContext>;
}

export interface PayDemSettlementRecoveryContext {
  railId: string;
  jobId: string;
  phaseIndex: number;
  settlementKey: string;
  network: string;
  payer: string;
  payee: string;
  amountOs: string;
}

export interface DemosTransferResult {
  ok: boolean;
  hash: string;
  state?: string;
  blockNumber?: number;
  message?: string;
}

export interface DemosNativeClient {
  address: string;
  transfer(args: {
    to: string;
    amountOs: bigint;
    recovery?: Readonly<PayDemSettlementRecoveryContext>;
  }): Promise<DemosTransferResult>;
}

export interface PayDemPreparedTransfer {
  txHash: string;
  nonce: number;
  payer: string;
  payee: string;
  amountOs: string;
  network: string;
  maxTotalDebitOs?: string;
  recovery?: Readonly<PayDemSettlementRecoveryContext>;
}
