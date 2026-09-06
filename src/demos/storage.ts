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

import { StorageProgram, type StorageProgramData } from '@kynesyslabs/demosdk/storage';
import type { DemosHandle } from './connection.js';

export interface AnchorResult {
  /** stor- prefixed storage address (the SR-2 locator) */
  storageAddress: string;
  /** Transaction hash that created the storage program */
  txHash: string;
  /** Stored byte length, including the JSON text-envelope overhead when present */
  sizeBytes: number;
  /** Original content byte length before adding a text envelope */
  contentBytes: number;
  /** When anchored (ISO 8601) */
  anchoredAt: string;
  /** Wallet nonce bound into the create transaction, when available. */
  nonce?: string;
}

export interface FetchResult {
  /** stor- prefixed storage address */
  storageAddress: string;
  /** Owner address (the publisher) */
  owner: string;
  /** Raw data field — JSON object or string depending on encoding */
  data: unknown;
  /** True when a wrapped-text JSON anchor was transparently unwrapped */
  wrapped?: true;
  /** Bytes size */
  sizeBytes: number;
  /** Transaction that created this storage */
  createdByTx?: string;
  /** When created (ISO 8601 per SDK) */
  createdAt: string;
}

export interface FetchAnchoredOptions {
  /** Test/substrate seam for the raw nodeCall transport. */
  fetchImpl?: typeof fetch;
}

export function wrapTextAnchor(text: string): { v: 'dacs-ref-text:1'; text: string } {
  return { v: 'dacs-ref-text:1', text };
}

export function unwrapTextAnchor(data: unknown): string | null {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return null;
  const keys = Reflect.ownKeys(data);
  if (keys.length !== 2 || !keys.includes('v') || !keys.includes('text')) return null;
  const candidate = data as { v?: unknown; text?: unknown };
  return candidate.v === 'dacs-ref-text:1' && typeof candidate.text === 'string'
    ? candidate.text
    : null;
}

export function storedAnchorPayload(
  data: Record<string, unknown> | string,
  encoding: 'json' | 'binary',
): Record<string, unknown> | string {
  return typeof data === 'string' && encoding === 'json' ? wrapTextAnchor(data) : data;
}

/**
 * Read a Storage Program without the SDK's error-to-null conversion.
 * Only a dedicated not-found response or an empty successful response is absence.
 */
export async function getStorageProgram(
  rpc: string,
  storageAddress: string,
  options: FetchAnchoredOptions = {},
): Promise<StorageProgramData | null> {
  const httpRes = await (options.fetchImpl ?? fetch)(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'nodeCall',
      params: [{
        message: 'getStorageProgram',
        data: { storageAddress },
        muid: `dacs-anchor-address-${storageAddress.length}-${storageAddress.slice(0, 24)}`,
      }],
    }),
  });
  // Every non-2xx, including 404, is a transport or routing error on this POST wire: the node
  // reports a missing program as HTTP 200 with envelope result 404, never as an HTTP status.
  if (!httpRes.ok) throw new Error(`getStorageProgram HTTP ${httpRes.status} for "${storageAddress}"`);
  const envelope = (await httpRes.json()) as { result?: number; response?: unknown };
  if (envelope?.result === 404) return null;
  if (envelope?.result !== 200) {
    throw new Error(
      `getStorageProgram RPC returned result=${String(envelope?.result)} for "${storageAddress}"`,
    );
  }
  if (envelope.response == null) return null;
  return envelope.response as StorageProgramData;
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
  options: { acl?: 'public' | 'private'; salt?: string; encoding?: 'binary'; fetchImpl?: typeof fetch; readBackAttempts?: number; readBackDelayMs?: number } = {}
): Promise<AnchorResult> {
  const { demos, address } = handle;

  // Get current nonce — required for deterministic address derivation + as `options.nonce`
  // for createStorageProgram (the SDK's create-payload helper)
  const nonceInfo = await demos.getAddressNonce(address);
  const nonce = typeof nonceInfo === 'number' ? nonceInfo : (typeof nonceInfo === 'object' && nonceInfo !== null && 'nonce' in nonceInfo ? Number((nonceInfo as { nonce: number }).nonce) : Number.NaN);
  if (!Number.isSafeInteger(nonce) || nonce < 0) throw new Error('SR-2 anchor nonce is unavailable');

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

  if (options.encoding === 'binary' && typeof data !== 'string') {
    throw new Error('Binary encoding is only supported for string anchors');
  }

  // Demos node 0.9.8 (stabilisation) was observed on 2026-09-02 accepting binary
  // storage writes for propagation but never including them. Keep binary opt-in for future nodes.
  const encoding: 'json' | 'binary' = options.encoding === 'binary' ? 'binary' : 'json';
  const storedData = storedAnchorPayload(data, encoding);
  if (!StorageProgram.validateSize(storedData, encoding)) {
    throw new Error(`Data exceeds StorageProgram size limit (encoding=${encoding})`);
  }

  // Build the storage-program-create payload — returns a StorageProgramPayload object
  // that the SDK's prepare() wraps into a Transaction
  const payload = StorageProgram.createStorageProgram(
    address,
    programName,
    storedData,
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
  // The locally signed transaction is the authority for what this wallet sent: pin its hash, signer and nonce
  // now, and require every fact read back from the node to match them.
  const signed = tx as { hash?: unknown; content?: { from?: unknown; nonce?: unknown } };
  const signedHash = typeof signed.hash === 'string' && /^[0-9a-f]{64}$/.test(signed.hash) ? signed.hash : undefined;
  const signedFrom = typeof signed.content?.from === 'string' ? signed.content.from : undefined;
  const signedNonce = typeof signed.content?.nonce === 'number' && Number.isSafeInteger(signed.content.nonce) ? String(signed.content.nonce)
    : typeof signed.content?.nonce === 'string' && /^\d+$/.test(signed.content.nonce) ? signed.content.nonce : undefined;
  if (signedFrom !== undefined && signedFrom !== address) throw new Error(`SR-2 anchor of "${programName}": signed transaction is from ${String(signedFrom).slice(0, 12)}, not this wallet`);
  const validity = await demosAny.confirm(tx);
  // Broadcast wait window. A slow devnet node can take >90s to CONFIRM a tx it already accepted for
  // propagation (the 2026-07-11 + 2026-07-23 BroadcastTimeoutError). Raise the default and make it tunable.
  // Clamp to a finite, positive, capped value so a bad/Infinity env can't make the wait loops unbounded.
  const clampMs = (v: number, def: number, max: number): number =>
    Number.isFinite(v) && v > 0 ? Math.min(v, max) : def;
  const broadcastTimeoutMs = clampMs(Number(process.env.GATEWAY_BROADCAST_TIMEOUT_MS), 240_000, 600_000);
  type BroadcastResult = {
    broadcast?: { response?: { hash?: string }; data?: { tx_hash?: string; hash?: string } };
    status?: { state?: string };
  };
  let result: BroadcastResult;
  try {
    result = await demosAny.broadcastAndWait(validity, { timeoutMs: broadcastTimeoutMs }) as BroadcastResult;
  } catch (err) {
    // A broadcast TIMEOUT means the tx was accepted for propagation but not confirmed within the wait
    // window — it may STILL land. We MUST NOT re-broadcast (a second tx = double-anchor / double-spend).
    // Instead poll getTransactionStatus for the SAME txHash over a bounded grace window; recover iff it
    // reaches `included`, else fail closed (safe to re-run the deal after balance reconciliation).
    const to = err as { name?: string; txHash?: string };
    const timedOutHash = typeof to?.txHash === 'string' ? to.txHash : '';
    if (to?.name !== 'BroadcastTimeoutError' || !timedOutHash) throw err;
    const demosPoll = demos as unknown as { call: (m: string, a: string, p: unknown) => Promise<unknown> };
    const graceMs = clampMs(Number(process.env.GATEWAY_BROADCAST_GRACE_MS), 180_000, 600_000);
    const stepMs = 15_000;
    const deadline = Date.now() + graceMs;
    let landed = false;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, stepMs));
      let statusRes: unknown;
      try { statusRes = await demosPoll.call('nodeCall', 'getTransactionStatus', { hash: timedOutHash }); }
      catch { continue; }   // transient transport blip — keep polling the same tx, never re-broadcast
      const st = statusRes && typeof statusRes === 'object' ? (statusRes as { state?: unknown }).state : undefined;
      if (st === 'included') { landed = true; break; }
      if (st === 'failed') throw new Error(`SR-2 anchor of "${programName}" tx ${timedOutHash} FAILED on chain (not re-broadcast)`);
    }
    if (!landed) {
      throw new Error(`SR-2 anchor of "${programName}" not confirmed within ${broadcastTimeoutMs + graceMs}ms ` +
        `(tx ${timedOutHash}; never re-broadcast — reconcile balance, then re-run the deal)`);
    }
    result = { broadcast: { response: { hash: timedOutHash } }, status: { state: 'included' } };
  }

  // Tx hash from the broadcast response (storage-program flow puts it under broadcast.response.hash).
  const broadcastHash = result.broadcast?.response?.hash
    ?? result.broadcast?.data?.tx_hash ?? result.broadcast?.data?.hash ?? '';
  // Require an explicit terminal `included` — a missing/other state is NOT success (matches the
  // receipt-anchor's positive check; never treat an unobserved anchor as confirmed).
  if (result.status?.state !== 'included') {
    throw new Error(`SR-2 anchor of "${programName}" not included (state=${result.status?.state ?? 'missing'})`);
  }
  // The anchor result must state the facts a CORE §5.1 receipt will be checked against: the creating
  // transaction and the nonce that transaction carries. The broadcast payload's hash field varies by SDK
  // version (observed empty on 4.0.16) and the wallet nonce read before signing is not the nonce the SDK
  // places in the transaction (observed off by one). The signed transaction is the authority; the node is
  // read back (briefly retried while the record propagates) to confirm the write, and every fact must agree
  // with what this wallet signed. Contradiction or an unreadable record fails closed: no result the receipt
  // provider will contradict is ever returned.
  const attempts = Math.max(1, Math.min(options.readBackAttempts ?? 5, 20));
  const delayMs = Math.max(0, Math.min(options.readBackDelayMs ?? 3_000, 60_000));
  let facts: Awaited<ReturnType<typeof anchorFactsFromNode>> = null;
  for (let attempt = 0; attempt < attempts && !facts; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, delayMs));
    facts = await anchorFactsFromNode(handle.rpc, storageAddress, { fetchImpl: options.fetchImpl });
  }
  if (!facts) {
    throw new Error(`SR-2 anchor of "${programName}" was included but its creating transaction and nonce could not be read back from the node after ${attempts} attempt(s)`);
  }
  if (facts.owner !== address) throw new Error(`SR-2 anchor of "${programName}": node records owner ${facts.owner.slice(0, 12)}, not this wallet`);
  if (signedHash !== undefined && facts.txHash !== signedHash) throw new Error(`SR-2 anchor of "${programName}": node's creating transaction ${facts.txHash.slice(0, 12)} is not the transaction this wallet signed ${signedHash.slice(0, 12)}`);
  if (signedNonce !== undefined && facts.nonce !== signedNonce) throw new Error(`SR-2 anchor of "${programName}": node records nonce ${facts.nonce}, the signed transaction carried ${signedNonce}`);
  if (broadcastHash && broadcastHash !== facts.txHash) {
    throw new Error(`SR-2 anchor of "${programName}": broadcast hash ${broadcastHash.slice(0, 12)} differs from the node's creating transaction ${facts.txHash.slice(0, 12)}`);
  }
  const txHash = facts.txHash;

  const sizeBytes = StorageProgram.getDataSize(storedData, encoding);
  const contentBytes = typeof data === 'string'
    ? new TextEncoder().encode(data).byteLength
    : sizeBytes;

  return {
    storageAddress,
    txHash,
    sizeBytes,
    contentBytes,
    anchoredAt: new Date().toISOString(),
    nonce: facts.nonce,
  };
}

/** One `nodeCall` POST; the node reports a missing record as HTTP 200 with envelope result 404. */
async function nodeCallJson(rpc: string, message: string, data: Record<string, unknown>, fetchImpl: typeof fetch = fetch): Promise<unknown> {
  const httpRes = await fetchImpl(rpc, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method: 'nodeCall', params: [{ message, data, muid: `dacs-anchor-facts-${message}-${String(Object.values(data)[0] ?? '').slice(0, 24)}` }] }),
  });
  if (!httpRes.ok) throw new Error(`${message} HTTP ${httpRes.status}`);
  const envelope = (await httpRes.json()) as { result?: unknown; response?: unknown };
  if (envelope?.result === 404) return null;
  if (envelope?.result !== 200) throw new Error(`${message} RPC result=${String(envelope?.result)}`);
  return envelope.response ?? null;
}

/**
 * The facts a receipt is checked against, read from the node after inclusion: the storage program's
 * creating transaction and the nonce that transaction carries. Returns null when either cannot be
 * established (missing record, missing or malformed transaction, signer not the program owner).
 */
export async function anchorFactsFromNode(
  rpc: string,
  storageAddress: string,
  options: { fetchImpl?: typeof fetch } = {},
): Promise<{ txHash: string; nonce: string; owner: string } | null> {
  const program = await nodeCallJson(rpc, 'getStorageProgram', { storageAddress }, options.fetchImpl) as { storageAddress?: unknown; owner?: unknown; createdByTx?: unknown } | null;
  if (!program || program.storageAddress !== storageAddress) return null;
  const txHash = program.createdByTx;
  if (typeof txHash !== 'string' || !/^[0-9a-f]{64}$/.test(txHash) || typeof program.owner !== 'string' || !program.owner) return null;
  const tx = await nodeCallJson(rpc, 'getTxByHash', { hash: txHash }, options.fetchImpl) as { hash?: unknown; content?: { type?: unknown; from?: unknown; nonce?: unknown } } | null;
  if (!tx || tx.hash !== txHash || !tx.content || tx.content.type !== 'storageProgram' || tx.content.from !== program.owner) return null;
  const nonce = tx.content.nonce;
  if (typeof nonce === 'number' && Number.isSafeInteger(nonce) && nonce >= 0) return { txHash, nonce: String(nonce), owner: program.owner };
  if (typeof nonce === 'string' && /^\d+$/.test(nonce)) return { txHash, nonce, owner: program.owner };
  return null;
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
  storageAddress: string,
  options: FetchAnchoredOptions = {},
): Promise<FetchResult | null> {
  const data = await getStorageProgram(rpc, storageAddress, options);
  if (!data) return null;
  const unwrapped = unwrapTextAnchor(data.data);
  return {
    storageAddress: data.storageAddress,
    owner: data.owner,
    data: unwrapped ?? data.data ?? null,
    ...(unwrapped !== null ? { wrapped: true as const } : {}),
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
  expectedContentHashHex: string,
  options: { fetchAnchoredImpl?: typeof fetchAnchored } = {}
): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string; actualHashHex?: string }> {
  try {
    const result = await (options.fetchAnchoredImpl ?? fetchAnchored)(rpc, storageAddress);
    if (!result) {
      return { outcome: 'indeterminate', detail: `anchor ${storageAddress} not found at ${rpc}` };
    }
    const { sha256 } = await import('@noble/hashes/sha2');
    const payload = unwrapTextAnchor(result.data) ?? result.data;
    // Re-serialize as the SDK would have stored it
    const bytes = typeof payload === 'string'
      ? new TextEncoder().encode(payload)
      : new TextEncoder().encode(JSON.stringify(payload));
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
