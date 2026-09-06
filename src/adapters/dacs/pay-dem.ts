/** Pure included-only native DEM settlement policy and amount conversion. */

import { emitSettlementEvidenceV1 } from '../../lib/emit-settlement-evidence-v1.js';
import { utcDateOrThrow } from '../../live/pay-policy.js';
import type { SettlementEvidenceV1Payment } from '../../types/settle.js';
import type {
  DemosNativeClient,
  PayDemAuthorizationAbortContext,
  PayDemSettlementRecoveryContext,
  SettleResult,
} from './sdk-pay-dem-types.js';
import {
  meterErrorResult,
  type MeterErrorResult,
} from '../demos/dem-meter-errors.js';
import type { DemMeter } from '../demos/dem-meter.js';

export type {
  DemosNativeClient,
  DemosTransferResult,
  PayDemPreparedTransfer,
  PayDemAuthorizationAbortContext,
  PayDemSettleParams,
  PayDemSettlementRecoveryContext,
  SettleResult,
  SettlementFinalityParameters,
} from './sdk-pay-dem-types.js';

export const PAY_DEM_RAIL_ID = 'pay-dem';
const INCLUDED_STATE = 'included';

const OS_PER_DEM = 1_000_000_000n;
const CANONICAL_DEM_RE = /^(?:[1-9]\d*|(?:0|[1-9]\d*)\.\d*[1-9])$/;

/** Convert a positive canonical decimal DEM string without using floating point. */
export function demToOs(canonicalDem: string): bigint {
  if (typeof canonicalDem !== 'string') {
    throw new Error(`pay-dem: invalid canonical DEM amount "${String(canonicalDem)}"`);
  }
  const [, fractionCandidate = ''] = canonicalDem.split('.');
  if (fractionCandidate.length > 9) {
    throw new Error('pay-dem: DEM amount has more than 9 fractional digits');
  }
  if (!CANONICAL_DEM_RE.test(canonicalDem)) {
    throw new Error(`pay-dem: invalid canonical DEM amount "${canonicalDem}"`);
  }
  const [whole = '', fraction = ''] = canonicalDem.split('.');
  const amountOs = BigInt(whole) * OS_PER_DEM + BigInt(fraction.padEnd(9, '0') || '0');
  if (amountOs <= 0n) throw new Error('pay-dem: amount must be greater than zero');
  return amountOs;
}

/** Convert non-negative integer OS to the unique canonical decimal DEM string. */
export function osToDem(os: bigint): string {
  if (typeof os !== 'bigint' || os < 0n) {
    throw new Error('pay-dem: OS amount must be a non-negative bigint');
  }
  const whole = os / OS_PER_DEM;
  const fraction = (os % OS_PER_DEM).toString().padStart(9, '0').replace(/0+$/, '');
  return fraction.length === 0 ? whole.toString() : `${whole}.${fraction}`;
}

export interface PayDemCoreParams {
  recipient: string;
  amountDemCanonical: string;
  currency: string;
  jobId: string;
  phaseIndex: number;
  network?: string;
  /** Optional redundant binding; when supplied it must equal the decimal conversion. */
  amountOs?: bigint;
  /** RPC endpoint used by an optional operator-policy authorization hook. */
  rpcUrl?: string;
}

export interface PayDemCoreHooks {
  meter?: { record: DemMeter['record'] };
  authorizeTransfer?: (ctx: {
    amountOs: bigint;
    rpcUrl: string;
  }) => Promise<
    | { verdict: 'PROCEED'; nowIso: string }
    | { verdict: 'BLOCK'; reason: string; rule: string }
  >;
  /**
   * Records the immutable recovery intent before the injected transfer capability
   * is invoked. The demosdk client has a second, signed-preparation hook because
   * only that layer can know the signed hash and nonce before broadcast.
   */
  journalPreparedTransfer?: (
    prepared: Readonly<PayDemSettlementRecoveryContext>,
  ) => Promise<void>;
}

export type PayDemSettleOutcome =
  | (SettleResult & {
      ok: true;
      amountOs: bigint;
      finalityObservedAt: number;
      evidence: SettlementEvidenceV1Payment;
      blockNumber: number;
      finality: { model: 'bft-final' };
      meterError?: MeterErrorResult;
    })
  | { ok: false; reason: string; recovery?: Readonly<PayDemAuthorizationAbortContext>; witness?: Readonly<PayDemSettlementWitness> };

/**
 * A payment that reached the chain but could not be witnessed to inclusion (no included state, no usable block
 * number, a wait timeout). It is not a refusal: DEM may have moved. The transaction hash, the last observed state
 * and the raw node result are kept so the settlement can be resolved, and a rerun must not pay again blindly.
 */
export interface PayDemSettlementWitness {
  stage: 'post-broadcast';
  txHash: string;
  state?: string;
  blockNumber?: unknown;
  /** The node's transfer result reduced to its identity fields (ok, hash, state, blockNumber); never free text. */
  rawWitness: { ok: boolean; hash: string; state?: string; blockNumber?: unknown };
}

function requireCapturedInputs(params: PayDemCoreParams, client: DemosNativeClient) {
  const recipient = params.recipient;
  const canonicalDem = params.amountDemCanonical;
  const currency = params.currency;
  const jobId = params.jobId;
  const phaseIndex = params.phaseIndex;
  const network = params.network ?? 'demos';
  const suppliedAmountOs = params.amountOs;
  const payer = client.address;
  const transfer = client.transfer.bind(client);

  if (!recipient || recipient.trim() !== recipient) throw new Error('pay-dem: recipient must be a non-empty exact string');
  if (!payer || payer.trim() !== payer) throw new Error('pay-dem: payer must be a non-empty exact string');
  if (!jobId || jobId.includes(':') || jobId.normalize('NFC') !== jobId) {
    throw new Error('pay-dem: jobId must be non-empty NFC text without a colon');
  }
  if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0) {
    throw new Error('pay-dem: phaseIndex must be a non-negative safe integer');
  }
  if (!network || network.trim() !== network) throw new Error('pay-dem: network must be a non-empty exact string');
  if (currency !== 'DEM') throw new Error(`pay-dem: unsupported currency ${String(currency)}; expected DEM`);

  const amountOs = demToOs(canonicalDem);
  // Checking both directions prevents evidence from describing a different debit.
  if (osToDem(amountOs) !== canonicalDem || (suppliedAmountOs !== undefined && suppliedAmountOs !== amountOs)) {
    throw new Error('pay-dem: canonical DEM amount does not exactly match the OS amount');
  }
  return { recipient, canonicalDem, jobId, phaseIndex, network, payer, transfer, amountOs };
}

/** Pure settlement policy over an injected native-transfer capability. */
export async function settlePayDemCore(
  params: PayDemCoreParams,
  client: DemosNativeClient,
  hooks: PayDemCoreHooks = {},
): Promise<PayDemSettleOutcome> {
  // Everything controlled by the caller is captured before this function's first await.
  const captured = requireCapturedInputs(params, client);
  const journal = hooks.journalPreparedTransfer?.bind(hooks);
  const authorize = hooks.authorizeTransfer?.bind(hooks);
  const recovery = Object.freeze({
    railId: PAY_DEM_RAIL_ID,
    jobId: captured.jobId,
    phaseIndex: captured.phaseIndex,
    settlementKey: `${PAY_DEM_RAIL_ID}:${captured.jobId}:${captured.phaseIndex}`,
    network: captured.network,
    payer: captured.payer,
    payee: captured.recipient,
    amountOs: captured.amountOs.toString(),
  }) satisfies Readonly<PayDemSettlementRecoveryContext>;

  if (!authorize) {
    const reason = 'payment policy authorization is unavailable';
    return {
      ok: false,
      reason,
      recovery: Object.freeze({
        ...recovery,
        abort: Object.freeze({ rule: 'network', reason }),
      }),
    };
  }

  const authorization = await authorize({
      amountOs: captured.amountOs,
      rpcUrl: params.rpcUrl ?? client.rpcUrl ?? '',
  });
  if (authorization?.verdict !== 'PROCEED') {
    const blocked = authorization?.verdict === 'BLOCK' &&
      typeof authorization.reason === 'string' && authorization.reason.length > 0 &&
      typeof authorization.rule === 'string' && authorization.rule.length > 0;
    const reason = blocked ? authorization.reason : 'payment policy authorization is unavailable';
    const rule = blocked ? authorization.rule : 'network';
    return {
      ok: false,
      reason,
      recovery: Object.freeze({
        ...recovery,
        abort: Object.freeze({ rule, reason }),
      }),
    };
  }

  try {
    utcDateOrThrow(authorization.nowIso);
  } catch {
    const reason = 'payment policy authorization is unavailable';
    return {
      ok: false,
      reason,
      recovery: Object.freeze({
        ...recovery,
        abort: Object.freeze({ rule: 'network', reason }),
      }),
    };
  }

  if (journal) await journal(recovery);
  const result = await captured.transfer({
    to: captured.recipient,
    amountOs: captured.amountOs,
    authorizationNowIso: authorization.nowIso,
    recovery,
  });

  const blockNumber = result.blockNumber;
  // Once a transaction hash exists the transfer may be on the chain: every failure from here carries the witness.
  // Reasons are fixed strings authored here; node or SDK exception text never enters the witness or the run result.
  const witness = (reason: string): PayDemSettleOutcome => ({
    ok: false, reason,
    witness: Object.freeze({ stage: 'post-broadcast' as const, txHash: result.hash as string,
      ...(result.state === undefined ? {} : { state: String(result.state) }), ...(blockNumber === undefined ? {} : { blockNumber }),
      rawWitness: Object.freeze({ ok: result.ok === true, hash: result.hash as string, ...(result.state === undefined ? {} : { state: String(result.state) }), ...(blockNumber === undefined ? {} : { blockNumber }) }) }),
  });
  if (!result.ok) return result.hash ? witness('pay-dem transfer failed after broadcast') : { ok: false, reason: result.message ?? 'pay-dem transfer failed' };
  if (!result.hash) return { ok: false, reason: 'pay-dem transfer returned no transaction hash' };
  if (result.state !== INCLUDED_STATE) return witness(`pay-dem did not observe included state (state=${String(result.state)})`);
  if (!Number.isSafeInteger(blockNumber) || (blockNumber as number) < 0) return witness('pay-dem included result lacks a finality-witness block number');

  const finalityObservedAt = Date.now();
  const evidence = emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: captured.jobId,
    phase: PAY_DEM_RAIL_ID,
    outcome: 'success',
    paymentTxRefs: [{ kind: 'demos', txHash: result.hash, blockNumber: blockNumber as number }],
    paymentAmount: captured.canonicalDem,
    paymentCurrency: 'DEM',
    finalityModel: 'bft-final',
    finalityObservedAt,
    observedAt: finalityObservedAt,
  }) as SettlementEvidenceV1Payment;

  let meterError: MeterErrorResult | undefined;
  if (hooks.meter !== undefined) {
    try {
      hooks.meter.record({
        agent: captured.payer,
        kind: 'transfer',
        os: captured.amountOs.toString(),
        ref: result.hash,
      });
    } catch (error) {
      meterError = meterErrorResult(error);
    }
  }

  return {
    ok: true,
    txHash: result.hash,
    chainId: captured.network,
    payer: captured.payer,
    payee: captured.recipient,
    blockNumber: blockNumber as number,
    txRefKind: 'demos',
    finality: { model: 'bft-final' },
    amountOs: captured.amountOs,
    finalityObservedAt,
    evidence,
    ...(meterError === undefined ? {} : { meterError }),
  };
}
