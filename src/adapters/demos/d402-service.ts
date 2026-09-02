import { D402Server } from '@kynesyslabs/demosdk/d402/server';
import type {
  D402PaymentRequirement,
  D402VerificationResult,
} from '@kynesyslabs/demosdk/d402/server';

export type { D402PaymentRequirement, D402VerificationResult };

export interface D402Verifier {
  verify(txHash: string): Promise<D402VerificationResult>;
  validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean;
}

export interface D402Payment {
  from: string;
  to: string;
  amount: string;
  txHash: string;
}

export type D402FailureReason =
  | 'missing-proof'
  | 'malformed-proof'
  | 'unverifiable'
  | 'mismatch'
  | 'replayed';

export interface D402Resource {
  resourceId: string;
  amount: number | string;
  description?: string;
}

export interface D402UsedProofs {
  has(key: string): boolean;
  add(key: string): boolean | void;
}

const TX_HASH_RE = /^(?:0x)?[0-9a-fA-F]{32,128}$/;
const OS_PER_DEM = 1_000_000_000n;
const MAX_PROOFS = 100_000;
const VERIFY_TIMEOUT_MS = 15_000;

// Mirrors the SDK's dual-shape conversion: numbers are DEM; strings are OS.
export function amountToOs(value: number | string): bigint {
  if (typeof value === 'string') return BigInt(value);
  if (!Number.isFinite(value) || value < 0) throw new Error('invalid D402 amount');
  const [whole = '', fraction = ''] = value.toString().split('.');
  if (fraction.length > 9) throw new Error('invalid D402 amount');
  return BigInt(whole) * OS_PER_DEM + BigInt(fraction.padEnd(9, '0') || '0');
}

function proofHeader(headers: Record<string, string | string[] | undefined>): string | string[] | undefined {
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === 'x-payment-proof') return value;
  }
  return undefined;
}

function replayKey(txHash: string, resourceId: string): string {
  return JSON.stringify([txHash, resourceId]);
}

function canonicalTxHash(txHash: string): string {
  return txHash.replace(/^0x/i, '').toLowerCase();
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('D402 verification timed out')), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function createD402Service(opts: {
  recipient: string;
  rpcUrl: string;
  verifier?: D402Verifier;
  cacheTTL?: number;
  usedProofs?: D402UsedProofs;
}) {
  const verifier: D402Verifier = opts.verifier ?? new D402Server({
    rpcUrl: opts.rpcUrl,
    cacheTTL: opts.cacheTTL,
  });
  const defaultUsedProofs = new Set<string>();
  const usedProofs: D402UsedProofs = opts.usedProofs ?? {
    has(key) { return defaultUsedProofs.has(key); },
    add(key) {
      if (defaultUsedProofs.size >= MAX_PROOFS) return false;
      defaultUsedProofs.add(key);
      return true;
    },
  };
  const pendingProofs = new Set<string>();

  function challenge(resource: D402Resource): { status: 402; body: D402PaymentRequirement } {
    return {
      status: 402,
      body: {
        amount: resource.amount,
        recipient: opts.recipient,
        resourceId: resource.resourceId,
        ...(resource.description === undefined ? {} : { description: resource.description }),
      },
    };
  }

  async function verifyPaymentProof(
    txHash: string,
    requirement: D402PaymentRequirement,
  ): Promise<{ ok: true; payment: D402Payment } | { ok: false; reason: D402FailureReason }> {
    if (!txHash) return { ok: false, reason: 'missing-proof' };
    if (typeof txHash !== 'string' || !TX_HASH_RE.test(txHash)) {
      return { ok: false, reason: 'malformed-proof' };
    }

    const canonicalHash = canonicalTxHash(txHash);
    const key = replayKey(canonicalHash, requirement.resourceId);
    if (usedProofs.has(key) || pendingProofs.has(key)) return { ok: false, reason: 'replayed' };
    if (pendingProofs.size >= MAX_PROOFS) return { ok: false, reason: 'replayed' };
    pendingProofs.add(key);

    try {
      const verification = await withTimeout(verifier.verify(txHash), VERIFY_TIMEOUT_MS);
      if (!verification || typeof verification !== 'object' || verification.valid !== true) {
        return { ok: false, reason: 'unverifiable' };
      }

      if (!verifier.validatePayment(verification, requirement)) {
        return { ok: false, reason: 'mismatch' };
      }
      if (
        typeof verification.verified_from !== 'string'
        || typeof verification.verified_to !== 'string'
        || verification.verified_amount === undefined
      ) {
        return { ok: false, reason: 'mismatch' };
      }
      const amount = amountToOs(verification.verified_amount).toString();
      if (usedProofs.add(key) === false) return { ok: false, reason: 'replayed' };
      return {
        ok: true,
        payment: {
          from: verification.verified_from,
          to: verification.verified_to,
          amount,
          txHash: canonicalHash,
        },
      };
    } catch {
      return { ok: false, reason: 'unverifiable' };
    } finally {
      pendingProofs.delete(key);
    }
  }

  async function gate(req: {
    headers: Record<string, string | string[] | undefined>;
    resource: D402Resource;
  }): Promise<
    | { status: 200; payment: D402Payment }
    | { status: 402; body: D402PaymentRequirement; reason: D402FailureReason }
  > {
    const challenged = challenge(req.resource);
    const header = proofHeader(req.headers);
    if (header === undefined || header === '') {
      return { ...challenged, reason: 'missing-proof' };
    }
    if (Array.isArray(header) || typeof header !== 'string') {
      return { ...challenged, reason: 'malformed-proof' };
    }
    const result = await verifyPaymentProof(header, challenged.body);
    return result.ok
      ? { status: 200, payment: result.payment }
      : { ...challenged, reason: result.reason };
  }

  return { challenge, verifyPaymentProof, gate };
}
