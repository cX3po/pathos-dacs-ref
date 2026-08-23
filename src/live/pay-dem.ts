/**
 * pay-dem.ts — real §9.5.9 pay-dem settlement on the Demos devnet.
 *
 * The buyer pays the seller in native DEM over the Demos chain; the phase
 * orchestrator (here: the buyer, per the fixed-price happy path) emits the §9.7
 * SettlementEvidence with the REAL transaction reference and `bft-final`
 * finality — Demos has deterministic BFT finality, so the tx reaching the
 * terminal "included"/confirmed state IS the finality condition (§9.7 model
 * note; dacs-sdk #28 aligned).
 *
 * txHash format follows SB-1's settlement-tx-id discipline: the rail's canonical
 * reference, pinned as `demos:{txHash}` so a consumer keys the settlement on
 * (settlement-tx-id, jobId, phaseIndex) without ambiguity about which chain the
 * hash lives on.
 */

import { DemosTransactions } from '@kynesyslabs/demosdk/websdk';
import type { DemosHandle } from '../demos/connection.js';
import { emitSettlementEvidenceV1 } from '../lib/emit-settlement-evidence-v1.js';
import type { SettlementEvidenceV1 } from '../types/settle.js';

export const PAY_DEM_RAIL_ID = 'pay-dem';

export interface PayDemResult {
  txHash: string;
  /** OS actually transferred (1 DEM = 1e9 OS). */
  amountOs: bigint;
  /** unix ms at which the included/confirmed state was observed. */
  finalityObservedAt: number;
  evidence: SettlementEvidenceV1;
}

/**
 * Execute the pay-dem phase for a job: transfer `amountOs` from the buyer handle
 * to `sellerAddress`, wait for BFT-final inclusion, and emit the payment
 * SettlementEvidence. Throws on broadcast failure or timeout — the caller maps a
 * throw to a failure-outcome record / abort path; this function never fabricates
 * evidence for a payment it did not observe.
 */
export async function settlePayDem(opts: {
  buyer: DemosHandle;
  sellerAddress: string;
  amountOs: bigint;
  /** CD-1 canonical DEM amount for the evidence's paymentAmount (e.g. "1" | "0.25"). */
  amountDemCanonical: string;
  jobId: string;
  phaseIndex: number;
}): Promise<PayDemResult> {
  const { demos } = opts.buyer;

  // Codex-review guards (2026-07-07): amount must be positive, Number-safe (the SDK pay()
  // takes a number), and CONSISTENT with the CD-1 canonical DEM amount on the evidence —
  // an evidence record must never claim a different amount than the rail moved.
  if (opts.amountOs <= 0n) throw new Error('pay-dem: amountOs must be > 0');
  if (opts.amountOs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('pay-dem: amountOs exceeds Number.MAX_SAFE_INTEGER — SDK pay() would lose precision');
  }
  const [demInt = '0', demFrac = ''] = opts.amountDemCanonical.split('.');
  const expectedOs = BigInt(demInt) * 1_000_000_000n + BigInt(demFrac.padEnd(9, '0').slice(0, 9) || '0');
  if (demFrac.length > 9) throw new Error('pay-dem: DEM amount has more than 9 fractional digits (sub-OS precision)');
  if (expectedOs !== opts.amountOs) {
    throw new Error(`pay-dem: amountDemCanonical "${opts.amountDemCanonical}" (${expectedOs} OS) does not match amountOs ${opts.amountOs}`);
  }

  // Canonical SDK flow (same shape as src/demos/storage.ts anchor()):
  // pay(to, amount) → sign → confirm → broadcastAndWait (throws BroadcastTimeoutError on stall).
  const tx = await DemosTransactions.pay(opts.sellerAddress, Number(opts.amountOs), demos);
  const signed = await demos.sign(tx);
  const validity = await DemosTransactions.confirm(signed, demos);
  const result = await DemosTransactions.broadcastAndWait(validity, demos);

  const broadcastBody = (result.broadcast as { data?: { tx_hash?: string; hash?: string } })?.data ?? {};
  const txHash = broadcastBody.tx_hash ?? broadcastBody.hash ?? '';
  if (!txHash) {
    throw new Error('pay-dem broadcast returned no tx hash — cannot emit evidence for an unobserved payment');
  }
  // Codex-review guard: REQUIRE an explicit terminal state from the SDK — never default a
  // missing status to 'included' (evidence must not be emitted for a not-observed finality).
  const state = (result as { status?: { state?: string } }).status?.state;
  if (!state || !['included', 'confirmed', 'finalized'].includes(state)) {
    throw new Error(`pay-dem tx ${txHash} did not report a terminal included state (state=${String(state)}) — refusing to emit bft-final evidence`);
  }
  const finalityObservedAt = Date.now();

  const evidence = emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: opts.jobId,
    phase: 'pay-dem',
    phaseIndex: opts.phaseIndex,
    outcome: 'success',
    paymentTxRefs: [{ rail: PAY_DEM_RAIL_ID, txHash: `demos:${txHash}`, kind: 'payment' }],
    paymentAmount: opts.amountDemCanonical,
    paymentCurrency: 'DEM',
    finalityModel: 'bft-final',
    finalityObservedAt,
    observedAt: finalityObservedAt,
  });

  return { txHash, amountOs: opts.amountOs, finalityObservedAt, evidence };
}
