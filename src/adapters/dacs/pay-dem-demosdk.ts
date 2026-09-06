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
import { utcDateOrThrow } from '../../live/pay-policy.js';
import type { DemMeter } from '../demos/dem-meter.js';

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

/** A block number as the node reports it: a non-negative safe integer, as a JSON number or a decimal string. */
export function nodeBlockNumber(raw: unknown): number | undefined {
  if (typeof raw === 'number') return Number.isSafeInteger(raw) && raw >= 0 ? raw : undefined;
  if (typeof raw === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(raw)) {
    const n = Number(raw);
    return Number.isSafeInteger(n) ? n : undefined;
  }
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
  // The node has returned blockNumber both as a JSON number and as a decimal string (observed 2026-09-06);
  // both are the same finality witness. Anything else is treated as absent.
  const blockNumber = nodeBlockNumber(payload.status?.blockNumber);
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
  journalTransferOutcome?: (outcome: Readonly<{
    timestamp: string;
    amountOs: string;
    outcome: string;
    /** The pay-dem settlement key (`pay-dem:{jobId}:{phaseIndex}`) and the signed transaction hash, so a rerun can tell a durably aborted transfer from an unresolved one. */
    settlementKey?: string;
    txHash?: string;
  }>) => Promise<void>;
  beforeBroadcast?: (ctx: Readonly<{ authorizationNowIso: string }>) => Promise<void>;
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
  const journalOutcome = opts.journalTransferOutcome;
  const beforeBroadcast = opts.beforeBroadcast;
  const sdk = opts.sdk ?? DEFAULT_SDK_FUNCTIONS;
  return {
    address: payer,
    rpcUrl: handle.rpc,
    async transfer({ to, amountOs, authorizationNowIso, recovery }): Promise<DemosTransferResult> {
      let txHash = '';
      let lastSeenState: string | undefined;
      let broadcastAttempted = false;
      try {
        if (authorizationNowIso === undefined) {
          throw new Error('payment policy authorization timestamp is unavailable');
        }
        const authorizedUtcDate = utcDateOrThrow(authorizationNowIso);
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
        if (utcDateOrThrow(new Date().toISOString()) !== authorizedUtcDate) {
          throw new Error('payment policy authorization expired at UTC day boundary');
        }
        if (!journalOutcome) throw new Error('payment policy accounting journal is unavailable');
        await journalOutcome({
          timestamp: authorizationNowIso,
          amountOs: amountOs.toString(),
          outcome: 'broadcast-attempted',
          ...(recovery?.settlementKey === undefined ? {} : { settlementKey: recovery.settlementKey }),
          txHash,
        });
        if (utcDateOrThrow(new Date().toISOString()) !== authorizedUtcDate) {
          throw new Error('payment policy authorization expired at UTC day boundary');
        }
        await beforeBroadcast?.({ authorizationNowIso });
        broadcastAttempted = true;
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
      } finally {
        if (journalOutcome && !broadcastAttempted) {
          let abortTimestamp: string;
          try {
            utcDateOrThrow(authorizationNowIso);
            abortTimestamp = authorizationNowIso;
          } catch {
            abortTimestamp = new Date().toISOString();
          }
          await journalOutcome({
            timestamp: abortTimestamp,
            amountOs: amountOs.toString(),
            outcome: 'aborted-before-broadcast',
            ...(recovery?.settlementKey === undefined ? {} : { settlementKey: recovery.settlementKey }),
            ...(txHash ? { txHash } : {}),
          });
        }
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
  meter?: { record: DemMeter['record'] };
  sdk?: DemosSdkFunctions;
  authorizeTransfer: (ctx: { amountOs: bigint; rpcUrl: string }) => Promise<
    | { verdict: 'PROCEED'; nowIso: string }
    | { verdict: 'BLOCK'; reason: string; rule: string }
  >;
  journalTransferOutcome?: DemosNativeClientOptions['journalTransferOutcome'];
  beforeBroadcast?: DemosNativeClientOptions['beforeBroadcast'];
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
    journalTransferOutcome: opts.journalTransferOutcome,
    beforeBroadcast: opts.beforeBroadcast,
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
    rpcUrl: opts.buyer.rpc,
  }, client, {
    authorizeTransfer: opts.authorizeTransfer,
    meter: opts.meter,
    async journalPreparedTransfer(recovery) {
      capturedRecovery = recovery;
    },
  });
}
