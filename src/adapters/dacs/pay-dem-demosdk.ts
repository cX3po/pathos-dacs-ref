/** Demos SDK wiring for the pure pay-DEM settlement core. */

import {
  BroadcastTimeoutError,
  DemosTransactions,
} from '@kynesyslabs/demosdk/websdk';
import type { DemosHandle } from '../../demos/connection.js';
import {
  settlePayDemCore,
  type PayDemSettleOutcome,
} from './pay-dem.js';
import type {
  DemosNativeClient,
  DemosTransferResult,
  PayDemPreparedTransfer,
  PayDemSettlementRecoveryContext,
} from './sdk-pay-dem-types.js';

export interface DemosBroadcastWaitPayload {
  broadcast?: {
    result?: number;
    response?: unknown;
    require_reply?: boolean;
    extra?: unknown;
  };
  status?: {
    state?: string;
    blockNumber?: unknown;
  };
}

function responseHash(payload: DemosBroadcastWaitPayload): string | undefined {
  const response = payload.broadcast?.response;
  if (response === null || typeof response !== 'object' || Array.isArray(response)) return undefined;
  const record = response as Record<string, unknown>;
  if (typeof record.hash === 'string' && record.hash.length > 0) return record.hash;
  if (typeof record.tx_hash === 'string' && record.tx_hash.length > 0) return record.tx_hash;
  return undefined;
}

/** Parse only the documented terminal status, retaining the signed hash as identity. */
export function parseBroadcastWaitResult(
  payload: DemosBroadcastWaitPayload,
  signedHash: string,
): DemosTransferResult {
  const payloadHash = responseHash(payload);
  if (payloadHash !== undefined && payloadHash !== signedHash) {
    return { ok: false, hash: signedHash, message: 'pay-dem broadcast hash mismatch' };
  }

  const state = typeof payload.status?.state === 'string' ? payload.status.state : undefined;
  const rawBlockNumber = payload.status?.blockNumber;
  const blockNumber = typeof rawBlockNumber === 'number' ? rawBlockNumber : undefined;
  return {
    ok: state === 'included',
    hash: signedHash,
    ...(state === undefined ? {} : { state }),
    ...(blockNumber === undefined ? {} : { blockNumber }),
    ...(state === 'included' ? {} : { message: 'pay-dem broadcast did not report included state' }),
  };
}

type DemosInstance = DemosHandle['demos'];

/** Injectable boundary used to test live ordering and error closure without a node. */
export interface DemosSdkFunctions {
  pay(to: string, amountOs: bigint, demos: DemosInstance): Promise<unknown>;
  sign(transaction: unknown, demos: DemosInstance): Promise<unknown>;
  confirm(signed: unknown, demos: DemosInstance): Promise<unknown>;
  broadcastAndWait(validity: unknown, demos: DemosInstance): Promise<DemosBroadcastWaitPayload>;
}

const DEFAULT_SDK_FUNCTIONS: DemosSdkFunctions = {
  pay: (to, amountOs, demos) => DemosTransactions.pay(to, amountOs, demos),
  sign: (transaction, demos) => demos.sign(
    transaction as Parameters<DemosInstance['sign']>[0],
  ),
  confirm: (signed, demos) => DemosTransactions.confirm(
    signed as Parameters<typeof DemosTransactions.confirm>[0],
    demos,
  ),
  broadcastAndWait: (validity, demos) => DemosTransactions.broadcastAndWait(
    validity as Parameters<typeof DemosTransactions.broadcastAndWait>[0],
    demos,
    { failFastOnBroadcastError: true },
  ),
};

export interface DemosNativeClientOptions {
  journalPreparedTransfer?: (prepared: Readonly<PayDemPreparedTransfer>) => Promise<void>;
  sdk?: DemosSdkFunctions;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.length > 0
    ? error.message
    : `pay-dem SDK failure: ${String(error)}`;
}

/** Thin demosdk wiring; all settlement acceptance policy remains in the pure core. */
export function createDemosNativeClient(
  handle: DemosHandle,
  opts: DemosNativeClientOptions = {},
): DemosNativeClient {
  const demos = handle.demos;
  const payer = handle.address;
  const journal = opts.journalPreparedTransfer;
  const sdk = opts.sdk ?? DEFAULT_SDK_FUNCTIONS;
  return {
    address: payer,
    async transfer({ to, amountOs, recovery }): Promise<DemosTransferResult> {
      let txHash = '';
      let lastSeenState: string | undefined;
      try {
        const tx = await sdk.pay(to, amountOs, demos);
        const signed = await sdk.sign(tx, demos);
        const signedRecord = signed as { hash?: unknown; content?: { nonce?: unknown } };
        txHash = typeof signedRecord.hash === 'string' ? signedRecord.hash : '';
        const nonce = signedRecord.content?.nonce;
        if (!txHash || !Number.isSafeInteger(nonce) || (nonce as number) < 0) {
          return { ok: false, hash: txHash, message: 'pay-dem signed transfer lacks hash or nonce' };
        }

        if (journal) {
          await journal(Object.freeze({
            txHash,
            nonce: nonce as number,
            payer,
            payee: to,
            amountOs: amountOs.toString(),
            network: recovery?.network ?? 'demos',
            ...(recovery === undefined ? {} : { recovery }),
          }));
        }

        const validity = await sdk.confirm(signed, demos);
        const payload = await sdk.broadcastAndWait(validity, demos);
        lastSeenState = payload.status?.state;
        return parseBroadcastWaitResult(payload, txHash);
      } catch (error) {
        if (error instanceof BroadcastTimeoutError) lastSeenState = error.lastSeenState;
        return {
          ok: false,
          hash: txHash,
          message: errorMessage(error),
          ...(lastSeenState === undefined ? {} : { state: lastSeenState }),
        };
      }
    },
  };
}

/** The public journal is signed-preparation-only and fires once, before confirmation. */
export type PayDemJournal =
  | ((prepared: Readonly<PayDemPreparedTransfer>) => Promise<void>)
  | { journalPreparedTransfer(prepared: Readonly<PayDemPreparedTransfer>): Promise<void> };

/** Gateway convenience wrapper retaining the former call shape. */
export async function settlePayDem(opts: {
  buyer: DemosHandle;
  sellerAddress: string;
  amountOs?: bigint;
  amountDemCanonical: string;
  jobId: string;
  phaseIndex: number;
  network?: string;
  journal?: PayDemJournal;
  sdk?: DemosSdkFunctions;
}): Promise<PayDemSettleOutcome> {
  const journalPreparedTransfer = typeof opts.journal === 'function'
    ? opts.journal
    : opts.journal?.journalPreparedTransfer.bind(opts.journal);
  let capturedRecovery: Readonly<PayDemSettlementRecoveryContext> | undefined;
  const signedPreparationJournal = journalPreparedTransfer === undefined
    ? undefined
    : async (prepared: Readonly<PayDemPreparedTransfer>) => {
        if (capturedRecovery === undefined || prepared.recovery !== capturedRecovery) {
          throw new Error('pay-dem signed preparation lost its captured recovery context');
        }
        await journalPreparedTransfer(prepared);
      };
  const client = createDemosNativeClient(opts.buyer, {
    journalPreparedTransfer: signedPreparationJournal,
    sdk: opts.sdk,
  });
  return settlePayDemCore({
    recipient: opts.sellerAddress,
    amountDemCanonical: opts.amountDemCanonical,
    currency: 'DEM',
    jobId: opts.jobId,
    phaseIndex: opts.phaseIndex,
    network: opts.network,
    amountOs: opts.amountOs,
  }, client, {
    async journalPreparedTransfer(recovery) {
      capturedRecovery = recovery;
    },
  });
}
