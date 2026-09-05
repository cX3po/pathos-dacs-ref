/**
 * Delivery receipt — one signed shape for every PATH-OS service delivery (commerce/offers.json).
 *
 * A receipt binds the quote, the buyer, the network, the payment, an idempotency key, the input
 * hash, the implementation version, the result hash, the issue time and where the deliverable
 * can be fetched. It is signed by the seller under `PATHOS_EXTENSION_SEPARATORS.DELIVERY_RECEIPT`:
 *
 *   signed_bytes := DELIVERY_RECEIPT || utf8( sha256-hex( JCS(receipt without `signature`) ) )
 *
 * Verification recomputes the JCS hash and checks the Ed25519 signature against the seller key
 * named in the receipt. Structural checks are done here by hand (the schema in
 * commerce/receipt.schema.json documents the same shape; no JSON Schema engine is a dependency).
 * The receipt attests delivery. It does not verify the payment: the buyer checks the named
 * transaction on chain (recipient, network, amount) as a separate step. Nothing here is put on
 * chain. Pass the seller key you already trust as `expectedSellerPubKeyHex`; without it the
 * signature check only proves the receipt is self-consistent with the key it names.
 */
import { PATHOS_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { bytesToHex, hexToBytes } from './verify-bundle.js';

export const DELIVERY_RECEIPT_VERSION = 'pathos-delivery-receipt:0.1';

export const DELIVERY_SKUS = ['verify-bundle', 'interop-run', 'verifier-package', 'pr-review'] as const;
export type DeliverySku = (typeof DELIVERY_SKUS)[number];

export interface DeliveryReceiptBody {
  v: typeof DELIVERY_RECEIPT_VERSION;
  sku: DeliverySku;
  /** Quote or order reference: the 402 resourceId for verify-bundle, the quote id for manual orders. */
  quoteRef: string;
  /** Buyer identity: Demos address for verify-bundle, claim or handle for manual orders. */
  buyer: string;
  seller: { name: string; pubKeyHex: string };
  network: { id: string; mode: 'rehearsal' | 'live' };
  payment: { txHash: string; from: string; amountOs: string };
  /** Repeating a delivery with this key is, by the seller's stated policy, not billed twice; only verify-bundle enforces it in code (src/live/verify-endpoint.mts). */
  idempotencyKey: string;
  /** sha256 hex of the exact input bytes (the request body, the adapter commit, the version, the PR head). */
  inputHash: string;
  implementationVersion: string;
  /** sha256 hex of the delivered result bytes. */
  resultHash: string;
  issuedAt: string;
  /** Where the deliverable is fetched: an HTTP response, a thread comment, an issue attachment, a review id. */
  retrieval: { kind: 'http-response' | 'thread-comment' | 'issue-attachment' | 'pr-review'; ref: string };
  /** Present only for verify-bundle, mirroring the endpoint's own receipt. resourceId is `verify:` + the first 16 hex of sha256(request bytes), as src/live/verify-endpoint.mts derives it. */
  endpoint?: { resourceId: string; redelivered?: boolean; reverified?: boolean };
}

export interface DeliveryReceipt extends DeliveryReceiptBody {
  signature: { algorithm: 'ed25519'; hex: string };
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const NON_EMPTY = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

/** RFC 3339 date-time with real calendar fields: 2026-02-30T14:00:00Z and 24:00:00 are refused. */
export function isRfc3339DateTime(value: unknown): boolean {
  if (typeof value !== 'string' || !DATE_TIME.test(value)) return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m) return false;
  const year = Number(m[1]), month = Number(m[2]), day = Number(m[3]);
  const hour = Number(m[4]), minute = Number(m[5]), second = Number(m[6]);
  const offset = m[7] ?? 'Z';
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) return false;
  if (offset !== 'Z') {
    const oh = Number(offset.slice(1, 3)), om = Number(offset.slice(4, 6));
    if (oh > 23 || om > 59) return false;
  }
  return !Number.isNaN(Date.parse(value));
}

export type ReceiptCheck =
  | { ok: true; commitmentHex: string }
  | { ok: false; reason: string };

/** Structural validation: every required field present with the right shape. Returns the first defect. */
export function checkReceiptShape(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'receipt is not an object';
  const r = value as Record<string, unknown>;
  if (r.v !== DELIVERY_RECEIPT_VERSION) return `v must be ${DELIVERY_RECEIPT_VERSION}`;
  if (!DELIVERY_SKUS.includes(r.sku as DeliverySku)) return 'sku unknown';
  for (const key of ['quoteRef', 'buyer', 'idempotencyKey', 'implementationVersion', 'issuedAt'] as const) {
    if (!NON_EMPTY(r[key])) return `${key} missing`;
  }
  for (const key of ['inputHash', 'resultHash'] as const) {
    if (!NON_EMPTY(r[key]) || !HEX64.test(r[key] as string)) return `${key} must be 64 lowercase hex`;
  }
  if (!isRfc3339DateTime(r.issuedAt)) return 'issuedAt must be an RFC 3339 date-time with real calendar fields';
  const seller = r.seller as Record<string, unknown> | undefined;
  if (!seller || !NON_EMPTY(seller.name) || !NON_EMPTY(seller.pubKeyHex) || !HEX64.test(seller.pubKeyHex as string)) return 'seller.name and seller.pubKeyHex (64 hex) required';
  const network = r.network as Record<string, unknown> | undefined;
  if (!network || !NON_EMPTY(network.id) || (network.mode !== 'rehearsal' && network.mode !== 'live')) return 'network.id and network.mode (rehearsal|live) required';
  const payment = r.payment as Record<string, unknown> | undefined;
  if (!payment || !NON_EMPTY(payment.txHash) || !NON_EMPTY(payment.from) || !NON_EMPTY(payment.amountOs) || !/^[1-9][0-9]*$/.test(payment.amountOs as string)) return 'payment.txHash, payment.from and integer payment.amountOs required';
  const retrieval = r.retrieval as Record<string, unknown> | undefined;
  const kinds = ['http-response', 'thread-comment', 'issue-attachment', 'pr-review'];
  if (!retrieval || !kinds.includes(retrieval.kind as string) || !NON_EMPTY(retrieval.ref)) return 'retrieval.kind and retrieval.ref required';
  const endpoint = r.endpoint as Record<string, unknown> | undefined;
  if (r.sku === 'verify-bundle') {
    if (!endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint)) return 'verify-bundle receipts carry an endpoint block';
    const resourceId = endpoint.resourceId;
    if (!NON_EMPTY(resourceId) || !/^verify:[0-9a-f]{16}$/.test(resourceId)) return 'endpoint.resourceId must be verify:<first 16 hex of sha256(request)>';
    if (resourceId !== r.quoteRef || resourceId !== r.idempotencyKey) return 'endpoint.resourceId must equal quoteRef and idempotencyKey';
    if (!(r.inputHash as string).startsWith(resourceId.slice(7))) return 'endpoint.resourceId must be the prefix of inputHash';
    for (const flag of ['redelivered', 'reverified'] as const) {
      if (flag in endpoint && typeof endpoint[flag] !== 'boolean') return `endpoint.${flag} must be boolean`;
    }
    const extra = Object.keys(endpoint).filter((k) => !['resourceId', 'redelivered', 'reverified'].includes(k));
    if (extra.length) return `endpoint has unknown members: ${extra.join(',')}`;
  } else if (endpoint !== undefined) {
    return 'only verify-bundle receipts carry an endpoint block';
  }
  const signature = r.signature as Record<string, unknown> | undefined;
  if (!signature || signature.algorithm !== 'ed25519' || !NON_EMPTY(signature.hex) || !HEX128.test(signature.hex as string)) return 'signature.algorithm ed25519 and signature.hex (128 hex) required';
  return null;
}

/** The signed commitment: sha256-hex of the JCS form of the receipt without its signature. */
export function receiptCommitmentHex(body: DeliveryReceiptBody): string {
  const { signature: _drop, ...rest } = body as DeliveryReceiptBody & { signature?: unknown };
  return jcsHashHex(rest);
}

export function signDeliveryReceipt(body: DeliveryReceiptBody, sellerPrivKey: Uint8Array): DeliveryReceipt {
  const commitment = receiptCommitmentHex(body);
  const sig = edSign(PATHOS_EXTENSION_SEPARATORS.DELIVERY_RECEIPT, new TextEncoder().encode(commitment), sellerPrivKey);
  return { ...body, signature: { algorithm: 'ed25519', hex: bytesToHex(sig) } };
}

/**
 * Shape, then signature. With `expectedSellerPubKeyHex` the receipt must name that key (the key the
 * buyer already trusts from the manifest or the quote); without it the check is self-consistency
 * only, since a forger can name any key it holds. Never throws.
 */
export function verifyDeliveryReceipt(value: unknown, expectedSellerPubKeyHex?: string): ReceiptCheck {
  const defect = checkReceiptShape(value);
  if (defect) return { ok: false, reason: defect };
  const receipt = value as DeliveryReceipt;
  if (expectedSellerPubKeyHex !== undefined && receipt.seller.pubKeyHex !== expectedSellerPubKeyHex.toLowerCase()) {
    return { ok: false, reason: 'seller.pubKeyHex is not the expected seller key' };
  }
  let commitment: string;
  try {
    commitment = receiptCommitmentHex(receipt);
  } catch {
    return { ok: false, reason: 'receipt cannot be canonicalised' };
  }
  let ok = false;
  try {
    ok = edVerify(
      PATHOS_EXTENSION_SEPARATORS.DELIVERY_RECEIPT,
      hexToBytes(receipt.signature.hex),
      new TextEncoder().encode(commitment),
      hexToBytes(receipt.seller.pubKeyHex),
    );
  } catch {
    ok = false;
  }
  return ok ? { ok: true, commitmentHex: commitment } : { ok: false, reason: 'signature does not verify against seller.pubKeyHex' };
}
