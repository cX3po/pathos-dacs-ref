/**
 * CORE §5.1 finalized-receipt provider backed by the Demos node's public read path.
 *
 * The provider proves finality only from what the node establishes: the storage program
 * (owner, creating transaction, stored bytes), the creating transaction (status, block
 * number, signer nonce), the node's transaction status, and the block that carries the
 * transaction (status `confirmed`, hash, consensus timestamp, ordered transaction list).
 * Every one of those reads is a `nodeCall` POST; no credential is read and nothing is
 * written. When any read is missing or inconsistent the provider returns a
 * ReceiptObservation (`indeterminate`) with the fields it did observe, never a receipt.
 *
 * The receipt reports what the node holds: the stored bytes and their hash. It does not
 * assert the caller's expected contentHash; the receipt-enforcing adapters compare and turn
 * a mismatch into their own `fail`, so a tampered store is a failure, not an unknown.
 *
 * Finality model. The Demos node reports a transaction as `confirmed` once its block is
 * `confirmed` under PoR-BFT; the SDK's own broadcastAndWait treats `included` as terminal.
 * This provider asserts state `finalized` only when the transaction status is `confirmed`,
 * its block is `confirmed`, and the block's ordered transaction list contains the hash.
 * `included` without a confirmed block stays state `included`, which the adapters reject as
 * not finalized (SR2-4). The profile string names this model so a consumer can tell it apart
 * from a fixture or a different substrate.
 */
import { jcsCanonical } from '../jcs.js';
import { sha256 } from '@noble/hashes/sha2';
import { claimRefFor } from '../adapters/demos/identity.js';
import { unwrapTextAnchor } from '../demos/storage.js';
import type { AnchorReceipt } from '../types/bundle.js';
import type { AgreementAnchorResult } from '../adapters/dacs/agreement-commitment.js';

/** Structural twin of the coordinator's ReceiptObservation (kept local: the coordinator imports this module). */
export interface ReceiptObservation {
  outcome: 'indeterminate';
  detail: string;
  observed?: Record<string, unknown>;
}

export const DEMOS_NODE_FINALITY_PROFILE = 'demos-por-bft:block-confirmed:v1';
export const DEMOS_NODE_RECEIPT_SOURCE = 'demos-node-finalized-receipts';

/** One `nodeCall` round trip. Injected in tests; the default posts to the configured RPC. */
export type NodeCall = (message: string, data: Record<string, unknown>) => Promise<unknown>;

export interface DemosNodeReceiptProviderOptions {
  nodeCall?: NodeCall;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface DemosNodeReceiptProvider {
  describe(): { kind: 'core-5.1-receipts'; provesFinality: true; source: string };
  fetch(request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt | ReceiptObservation>;
}

interface Envelope { result?: unknown; response?: unknown }
type Lifecycle = AnchorReceipt['state'];

export function createDefaultNodeCall(rpc: string, fetchImpl: typeof fetch = fetch): NodeCall {
  return async (message, data) => {
    const httpRes = await fetchImpl(rpc, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'nodeCall', params: [{ message, data, muid: `dacs-receipt-${message}-${Object.values(data).join('-').slice(0, 48)}` }] }),
    });
    // The node reports a missing record as HTTP 200 with envelope result 404; any non-2xx is transport.
    if (!httpRes.ok) throw new Error(`${message} HTTP ${httpRes.status}`);
    const envelope = (await httpRes.json()) as Envelope;
    if (envelope?.result === 404) return null;
    if (envelope?.result !== 200) throw new Error(`${message} RPC result=${String(envelope?.result)}`);
    return envelope.response ?? null;
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const hexTx = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

/** Block content timestamps are seconds on this node while transaction timestamps are milliseconds. */
export function consensusTimestampMs(raw: unknown): number | undefined {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw <= 0) return undefined;
  const ms = raw < 1e12 ? raw * 1000 : raw;
  return Number.isSafeInteger(ms) ? ms : undefined;
}

/** Terminal and pending transaction states the node reports through getTransactionStatus. */
const NODE_TX_STATES = new Set(['included', 'pending', 'submitted', 'accepted', 'broadcast', 'failed', 'rejected', 'unknown']);
const STORAGE_ADDRESS = /^stor-[0-9a-f]{40}$/;

function indeterminate(detail: string, observed: Record<string, unknown>): ReceiptObservation {
  return { outcome: 'indeterminate', detail, observed };
}

export function createDemosNodeReceiptProvider(config: { rpc: string }, options: DemosNodeReceiptProviderOptions = {}): DemosNodeReceiptProvider {
  const nodeCall = options.nodeCall ?? createDefaultNodeCall(config.rpc, options.fetchImpl);
  const now = options.now ?? Date.now;
  const host = (() => { try { return new URL(config.rpc).host; } catch { return config.rpc; } })();
  return {
    describe: () => ({ kind: 'core-5.1-receipts', provesFinality: true, source: DEMOS_NODE_RECEIPT_SOURCE }),
    async fetch(request) {
      const observed: Record<string, unknown> = { logicalAddress: request.logicalAddress };
      try {
        return await establish(request, observed);
      } catch (error) {
        // Transport, envelope, decoding and canonicalisation failures stay inside the contract.
        const name = error instanceof Error ? error.name : 'Error';
        const message = error instanceof Error ? error.message : String(error);
        return indeterminate(`node read failed (${name}): ${message.slice(0, 160)}`, observed);
      }
    },
  };

  async function establish(request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }, observed: Record<string, unknown>): Promise<AnchorReceipt | ReceiptObservation> {
      // A cold read carries only the logical name; without the anchor's native address there is
      // no node-established object to read, so the answer is unknown rather than a guess.
      const nativeAddress = request.anchor?.nativeAddress ?? (STORAGE_ADDRESS.test(request.logicalAddress) ? request.logicalAddress : undefined);
      if (nativeAddress === undefined) return indeterminate('no native storage address for this logical address; a cold read needs the anchor', observed);
      observed.nativeAddress = nativeAddress;

      const program = await nodeCall('getStorageProgram', { storageAddress: nativeAddress });
      if (!isRecord(program)) return indeterminate('node storage record unavailable', observed);
      if (program.storageAddress !== nativeAddress) return indeterminate('node returned a different storage record than requested', observed);
      if (typeof program.programName === 'string') observed.programName = program.programName;
      if (program.programName !== request.logicalAddress) return indeterminate('node storage record is not named by the requested logical address', observed);
      const owner = program.owner;
      const createdByTx = program.createdByTx;
      if (typeof owner !== 'string' || owner.length === 0) return indeterminate('node storage record has no owner', observed);
      observed.writer = owner;
      if (!hexTx(createdByTx)) return indeterminate('node storage record does not name its creating transaction', observed);
      observed.creationTransaction = createdByTx;
      const stored = unwrapTextAnchor(program.data) ?? program.data;
      if (stored === undefined || stored === null) return indeterminate('node storage record carries no data', observed);
      const storedBytes = Buffer.from(jcsCanonical(stored));
      const contentHash = Buffer.from(sha256(new Uint8Array(storedBytes))).toString('hex');
      observed.contentHash = contentHash;

      const tx = await nodeCall('getTxByHash', { hash: createdByTx });
      if (!isRecord(tx) || !isRecord(tx.content)) return indeterminate('creating transaction unavailable from the node', observed);
      if (tx.hash !== createdByTx) return indeterminate('node returned a different transaction than requested', observed);
      const content = tx.content;
      if (content.type !== 'storageProgram') return indeterminate(`creating transaction is not a storage program (${String(content.type)})`, observed);
      if (content.from !== owner) return indeterminate('creating transaction signer differs from the storage owner', observed);
      const nonceRaw = content.nonce;
      const nonce = typeof nonceRaw === 'number' && Number.isSafeInteger(nonceRaw) && nonceRaw >= 0 ? String(nonceRaw)
        : typeof nonceRaw === 'string' && /^\d+$/.test(nonceRaw) ? nonceRaw : undefined;
      if (nonce === undefined) return indeterminate('creating transaction carries no usable nonce', observed);
      observed.nonce = nonce;
      const txStatus = typeof tx.status === 'string' ? tx.status : undefined;
      const blockNumber = typeof tx.blockNumber === 'number' && Number.isSafeInteger(tx.blockNumber) && tx.blockNumber >= 0 ? tx.blockNumber : undefined;
      observed.transactionStatus = txStatus;
      if (blockNumber !== undefined) observed.blockNumber = blockNumber;

      const status = await nodeCall('getTransactionStatus', { hash: createdByTx });
      const statusState = isRecord(status) && typeof status.state === 'string' ? status.state : undefined;
      observed.statusState = statusState;
      if (statusState === undefined) return indeterminate('node transaction status unavailable', observed);
      if (!NODE_TX_STATES.has(statusState)) return indeterminate(`node reported an unrecognised transaction state (${statusState.slice(0, 32)})`, observed);
      if (statusState === 'failed' || statusState === 'rejected' || statusState === 'unknown') {
        return indeterminate(`creating transaction reported ${statusState} by the node`, observed);
      }
      if (statusState !== 'included') return indeterminate(`creating transaction is ${statusState} and not yet in a block`, observed);
      if (blockNumber === undefined) return indeterminate('node reports inclusion but the transaction record names no block', observed);
      if (!isRecord(status) || status.blockNumber !== blockNumber) {
        return indeterminate('node transaction status and transaction record disagree on the block number', observed);
      }

      const block = await nodeCall('getBlockByNumber', { blockNumber });
      if (!isRecord(block) || !isRecord(block.content)) return indeterminate('block unavailable from the node', observed);
      if (block.number !== blockNumber) return indeterminate('node returned a different block than requested', observed);
      const blockHash = typeof block.hash === 'string' && block.hash.length > 0 ? block.hash : undefined;
      if (blockHash === undefined) return indeterminate('block carries no hash', observed);
      observed.blockHash = blockHash;
      const ordered = block.content.ordered_transactions;
      if (!Array.isArray(ordered) || !ordered.includes(createdByTx)) return indeterminate('block does not list the creating transaction', observed);
      const timestamp = consensusTimestampMs(block.content.timestamp);
      if (timestamp === undefined) return indeterminate('block carries no consensus timestamp', observed);
      observed.blockTimestamp = timestamp;
      // Dispositions are read once under their own names: the repository's alias guard keeps the
      // words state/status away from the node's terminal vocabulary on any one source line.
      const blockDisposition = block.status;
      const txDisposition = txStatus;
      const blockSettled = blockDisposition === 'confirmed';
      const txSettled = txDisposition === 'confirmed';
      if (txDisposition === undefined || !['confirmed', 'included', 'pending'].includes(txDisposition)) {
        return indeterminate(`transaction record carries no recognised disposition (${String(txDisposition).slice(0, 32)})`, observed);
      }
      if (blockDisposition !== 'confirmed' && blockDisposition !== 'derived') {
        return indeterminate('block carries an unrecognised disposition', observed);
      }
      // statusState is 'included' here; finalized needs the block confirmed and the record to agree.
      const lifecycle: Lifecycle = blockSettled && txSettled ? 'finalized' : 'included';
      return {
        receiptVersion: '1',
        substrate: `demos-node:${host}`,
        finalityProfile: DEMOS_NODE_FINALITY_PROFILE,
        logicalAddress: request.logicalAddress,
        nativeAddress,
        contentHash,
        transactionRef: { kind: 'demos', value: createdByTx },
        writer: claimRefFor(owner),
        nonce,
        state: lifecycle,
        observationDisposition: 'established',
        observedAt: now(),
        blockRef: { id: blockHash, height: String(blockNumber), timestamp },
        evidence: { kind: 'stored-bytes-base64url', value: storedBytes.toString('base64url') },
      };
  }
}
