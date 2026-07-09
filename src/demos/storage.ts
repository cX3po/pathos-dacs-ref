/**
 * SR-2 Storage Program — anchor write + read
 *
 * Spec context: DACS §5 SR-2 ("anchored storage") — bytes anchored at a content-derived
 * locator, retrievable by any verifier. Used by:
 *   - DACS-1 Listings (§6.3.4 LP-1: MUST anchor via SR-2 before indexing)
 *   - DACS-5 AttestationBundle two-sided anchoring (§10.4.2)
 *   - DACS-2 attestation refs (§7.5.2 — anchor.locator is the SR-2 address)
 *
 * Demos substrate provides this via the StorageProgram primitive.
 * The wrapper here keeps the SDK call shape out of the CLIs.
 */

import { StorageProgram } from '@kynesyslabs/demosdk/storage';
import type { DemosHandle } from './connection.js';

export interface AnchorResult {
  /** stor- prefixed storage address (the SR-2 locator) */
  storageAddress: string;
  /** Transaction hash that created the storage program */
  txHash: string;
  /** Bytes anchored */
  sizeBytes: number;
  /** When anchored (ISO 8601) */
  anchoredAt: string;
}

export interface FetchResult {
  /** stor- prefixed storage address */
  storageAddress: string;
  /** Owner address (the publisher) */
  owner: string;
  /** Raw data field — JSON object or string depending on encoding */
  data: unknown;
  /** Bytes size */
  sizeBytes: number;
  /** Transaction that created this storage */
  createdByTx?: string;
  /** When created (ISO 8601 per SDK) */
  createdAt: string;
}

/**
 * Anchor `data` to SR-2 (Demos Storage Program).
 *
 * @param handle Connected Demos handle
 * @param programName Human-readable identifier (used in deterministic address derivation)
 * @param data JSON-encodable object or raw string. JCS canonical form recommended for hash-stable artifacts.
 * @param options Optional ACL (defaults to public-read) + nonce (defaults to wallet's next nonce)
 *
 * Returns the storage address (`stor-...`) — this becomes the `AttestationRef.anchor.locator`
 * in §7.5.2 / §10.4.2.
 *
 * Throws on broadcast failure, insufficient DEM balance, or RPC error.
 */
export async function anchor(
  handle: DemosHandle,
  programName: string,
  data: Record<string, unknown> | string,
  options: { acl?: 'public' | 'private'; salt?: string } = {}
): Promise<AnchorResult> {
  const { demos, address } = handle;

  // Get current nonce — required for deterministic address derivation + as `options.nonce`
  // for createStorageProgram (the SDK's create-payload helper)
  const nonceInfo = await demos.getAddressNonce(address);
  const nonce = typeof nonceInfo === 'number' ? nonceInfo : (typeof nonceInfo === 'object' && nonceInfo !== null && 'nonce' in nonceInfo ? Number((nonceInfo as { nonce: number }).nonce) : 0);

  // Derive the deterministic storage address — this is what the spec calls the SR-2 locator
  const storageAddress = StorageProgram.deriveStorageAddress(
    address,
    programName,
    nonce,
    options.salt ?? ''
  );

  // Build ACL (default: public read)
  const acl = options.acl === 'private'
    ? StorageProgram.privateACL()
    : StorageProgram.publicACL();

  // Pick encoding based on input shape
  const encoding: 'json' | 'binary' = typeof data === 'string' ? 'binary' : 'json';
  if (!StorageProgram.validateSize(data, encoding)) {
    throw new Error(`Data exceeds StorageProgram size limit (encoding=${encoding})`);
  }

  // Build the storage-program-create payload — returns a StorageProgramPayload object
  // that the SDK's prepare() wraps into a Transaction
  const payload = StorageProgram.createStorageProgram(
    address,
    programName,
    data,
    encoding,
    acl,
    { nonce, salt: options.salt }
  );

  // Sign + broadcast via the DEDICATED storage-program flow (not DemosTransactions.prepare +
  // demos.sign — that validates a `to` address the storage-program payload doesn't carry, and
  // fails live with "Invalid To address: 0x"). This is the exact path the receipt-anchor proved
  // live: storagePrograms.sign(payload) → demos.confirm(tx) → demos.broadcastAndWait(validity).
  const demosAny = demos as unknown as {
    storagePrograms: { sign: (p: unknown) => Promise<unknown> };
    confirm: (tx: unknown) => Promise<unknown>;
    broadcastAndWait: (v: unknown, o?: { timeoutMs?: number }) => Promise<unknown>;
  };
  const tx = await demosAny.storagePrograms.sign(payload);
  const validity = await demosAny.confirm(tx);
  const result = await demosAny.broadcastAndWait(validity, { timeoutMs: 90_000 }) as {
    broadcast?: { response?: { hash?: string }; data?: { tx_hash?: string; hash?: string } };
    status?: { state?: string };
  };

  // Tx hash from the broadcast response (storage-program flow puts it under broadcast.response.hash).
  const txHash = result.broadcast?.response?.hash
    ?? result.broadcast?.data?.tx_hash ?? result.broadcast?.data?.hash ?? '';
  // Require an explicit terminal `included` — a missing/other state is NOT success (matches the
  // receipt-anchor's positive check; never treat an unobserved anchor as confirmed).
  if (result.status?.state !== 'included') {
    throw new Error(`SR-2 anchor of "${programName}" not included (state=${result.status?.state ?? 'missing'})`);
  }

  const sizeBytes = StorageProgram.getDataSize(data, encoding);

  return {
    storageAddress,
    txHash,
    sizeBytes,
    anchoredAt: new Date().toISOString(),
  };
}

/**
 * Fetch a previously anchored Storage Program by its address.
 *
 * @param rpc Demos node RPC URL
 * @param storageAddress stor- prefixed address
 * @returns FetchResult, or null if not found
 */
export async function fetchAnchored(
  rpc: string,
  storageAddress: string
): Promise<FetchResult | null> {
  const data = await StorageProgram.getByAddress(rpc, storageAddress);
  if (!data) return null;
  return {
    storageAddress: data.storageAddress,
    owner: data.owner,
    data: data.data ?? null,
    sizeBytes: data.sizeBytes,
    createdByTx: data.createdByTx,
    createdAt: data.createdAt,
  };
}

/**
 * Verify that the bytes anchored at `storageAddress` match an expected SHA-256.
 *
 * Used by DACS §7.5.2: "consumer MUST hash the fetched bytes and compare to AttestationRef.contentHash"
 *
 * Returns:
 *   - 'pass'          — fetched + hash matched
 *   - 'fail'          — fetched but hash mismatched
 *   - 'indeterminate' — anchor unreachable / not found
 */
export async function verifyAnchor(
  rpc: string,
  storageAddress: string,
  expectedContentHashHex: string
): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string; actualHashHex?: string }> {
  try {
    const result = await fetchAnchored(rpc, storageAddress);
    if (!result) {
      return { outcome: 'indeterminate', detail: `anchor ${storageAddress} not found at ${rpc}` };
    }
    const { sha256 } = await import('@noble/hashes/sha2');
    // Re-serialize as the SDK would have stored it
    const bytes = typeof result.data === 'string'
      ? new TextEncoder().encode(result.data)
      : new TextEncoder().encode(JSON.stringify(result.data));
    const actualHash = sha256(bytes);
    const actualHashHex = Array.from(actualHash, (b) => b.toString(16).padStart(2, '0')).join('');
    if (actualHashHex === expectedContentHashHex.toLowerCase()) {
      return { outcome: 'pass', detail: `content hash matches`, actualHashHex };
    }
    return {
      outcome: 'fail',
      detail: `content hash mismatch: expected ${expectedContentHashHex}, got ${actualHashHex}`,
      actualHashHex,
    };
  } catch (e) {
    return { outcome: 'indeterminate', detail: `fetch error: ${(e as Error).message}` };
  }
}
