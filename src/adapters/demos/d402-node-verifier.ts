/**
 * d402-node-verifier — a D402Verifier that confirms a payment through the node's `getTxByHash`.
 *
 * The SDK's own D402Server.verify (demosdk 4.0.16) calls `POST <rpc>/getTransaction` and
 * `POST <rpc>/d402/verify`, routes the testnet node does not serve, so it answers `valid:false`
 * for every real payment. The same SDK's websdk exposes `demos.getTxByHash()`, which the node
 * does answer with the full transaction (status, blockNumber, content.type, the d402 payload).
 * This verifier reads that and applies the d402 checks itself: type `d402_payment`, inclusion
 * in a block (a positive blockNumber; the node's own alias words are not read as a state),
 * hash echo, and (in validatePayment) recipient, amount floor, and the `resourceId:` memo prefix. Anything else is `valid:false`; a node error is `valid:false` too,
 * so the gate answers 402 `unverifiable` rather than crashing.
 *
 * Trust model: the configured node is trusted for inclusion. The verifier does not check the
 * transaction signature itself and does not wait for confirmation depth: inclusion in a block
 * (a positive blockNumber) with no negative status word from the node is taken as settled, which
 * is the testnet posture. A payer equal to the recipient (a self-payment) is accepted: the gate
 * prices the work, not the counterparty. An absent payer address is rejected.
 */
import { Demos } from '@kynesyslabs/demosdk/websdk';
import { amountToOs, type D402PaymentRequirement, type D402VerificationResult, type D402Verifier } from './d402-service.js';

export interface TxReader {
  getTxByHash(hash: string): Promise<unknown>;
}

export interface NodeD402VerifierOptions {
  rpcUrl: string;
  /** Inject a reader (tests); default connects a read-only websdk client lazily. */
  reader?: TxReader;
  /** Result cache lifetime in seconds (default 300). */
  cacheTTL?: number;
}

const NEGATIVE_STATUS = new Set(['reverted', 'rolled_back', 'rolledback', 'failed', 'rejected', 'invalid', 'dropped']);

function canonicalHash(h: string): string {
  return h.replace(/^0x/i, '').toLowerCase();
}

/** Pull the d402 payment fields out of a node transaction; null unless it is a d402 payment included in a block. */
export function paymentFromTransaction(tx: unknown, expectedHash: string): { from: string; to: string; amount: string; memo: string; timestamp: number } | null {
  if (!tx || typeof tx !== 'object') return null;
  const t = tx as { hash?: unknown; blockNumber?: unknown; status?: unknown; content?: { type?: unknown; from?: unknown; timestamp?: unknown; data?: unknown } };
  if (typeof t.hash !== 'string' || canonicalHash(t.hash) !== canonicalHash(expectedHash)) return null;
  const blockNumber = typeof t.blockNumber === 'number' ? t.blockNumber : (typeof t.blockNumber === 'string' && /^\d{1,15}$/.test(t.blockNumber) ? Number(t.blockNumber) : NaN);
  if (!Number.isInteger(blockNumber) || blockNumber <= 0) return null;
  // the node's positive alias words are not read as a state, but a negative word is a refusal
  if (typeof t.status === 'string' && NEGATIVE_STATUS.has(t.status.toLowerCase())) return null;
  const c = t.content;
  if (!c || c.type !== 'd402_payment' || !Array.isArray(c.data) || c.data[0] !== 'd402_payment') return null;
  const p = c.data[1] as { to?: unknown; amount?: unknown; memo?: unknown } | undefined;
  if (!p || typeof p.to !== 'string' || (typeof p.amount !== 'string' && typeof p.amount !== 'number')) return null;
  const timestamp = Number(c.timestamp);
  if (typeof c.from !== 'string' || !c.from) return null;
  return { from: c.from, to: p.to, amount: String(p.amount), memo: typeof p.memo === 'string' ? p.memo : '', timestamp: Number.isFinite(timestamp) ? timestamp : 0 };
}

export function createNodeD402Verifier(opts: NodeD402VerifierOptions): D402Verifier {
  const ttlMs = (opts.cacheTTL ?? 300) * 1000;
  const cache = new Map<string, { result: D402VerificationResult; expiresAt: number }>();
  let reader: TxReader | undefined = opts.reader;
  let connecting: Promise<TxReader> | undefined;
  const getReader = (): Promise<TxReader> => {
    if (reader) return Promise.resolve(reader);
    if (!connecting) {
      connecting = (async () => {
        const demos = new Demos();
        await demos.connect(opts.rpcUrl);
        reader = { getTxByHash: (hash) => demos.getTxByHash(hash) };
        return reader;
      })();
    }
    return connecting;
  };
  return {
    async verify(txHash: string): Promise<D402VerificationResult> {
      const key = canonicalHash(txHash);
      const hit = cache.get(key);
      if (hit && Date.now() < hit.expiresAt) return hit.result;
      let tx: unknown;
      try {
        tx = await (await getReader()).getTxByHash(key);
      } catch {
        return { valid: false, timestamp: Date.now() } as D402VerificationResult;
      }
      const payment = paymentFromTransaction(tx, key);
      if (!payment) return { valid: false, timestamp: Date.now() } as D402VerificationResult;
      const result = { valid: true, verified_from: payment.from, verified_to: payment.to, verified_amount: payment.amount, verified_memo: payment.memo, timestamp: payment.timestamp } as D402VerificationResult;
      if (cache.size >= 10_000) cache.delete(cache.keys().next().value as string);
      cache.set(key, { result, expiresAt: Date.now() + ttlMs });
      return result;
    },
    validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean {
      if (!v || v.valid !== true || v.verified_to !== r.recipient || v.verified_amount === undefined) return false;
      try {
        if (amountToOs(v.verified_amount) < amountToOs(r.amount)) return false;
      } catch {
        return false;
      }
      return (v.verified_memo ?? '').startsWith(`resourceId:${r.resourceId}`);
    },
  };
}
