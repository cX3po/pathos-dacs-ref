/**
 * Local (non-Demos) SR-2 substrate — write-once (immutable) file store.
 *
 * Spec context: DACS §11.3 asks for a second independent reference implementation on a
 * NON-Demos substrate, to prove the spec is genuinely substrate-agnostic (SR-2 is an
 * abstract requirement — "anchored, immutable storage" — not "the Demos StorageProgram").
 *
 * This implements the SAME SR-2 contract as `src/demos/storage.ts` (anchor / fetchAnchored
 * / verifyAnchor) against the local filesystem. Because `verifyBundle` already accepts a
 * `fetchAnchoredImpl` (the substrate seam), the UNMODIFIED DACS-5 verifier runs against
 * this backend with no Demos dependency — see `examples/local-substrate/run.mts`.
 *
 * `localFetchAnchored` matches `typeof fetchAnchored` from ../demos/storage.js: its first
 * arg ("rpc" on the Demos side) is the local store directory here, so it drops straight
 * into `verifyBundle({ fetchAnchoredImpl, rpc: storeDir })`.
 */
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import type { FetchResult, AnchorResult } from '../demos/storage.js';

function recordPath(storeDir: string, storageAddress: string): string {
  // storageAddress is a `stor-<hex>` locator; encode to a safe filename (no traversal).
  return path.join(storeDir, encodeURIComponent(storageAddress) + '.json');
}

function dataBytes(data: unknown): Uint8Array {
  return typeof data === 'string'
    ? new TextEncoder().encode(data)
    : new TextEncoder().encode(JSON.stringify(data));
}

/**
 * Anchor `data` at an explicit `storageAddress` on the local substrate.
 * (Demos derives the address from owner+program+nonce; here the caller passes the
 * content-derived locator — e.g. `computeAnchorPair(jobId).buyer` — so the verifier,
 * which recomputes the same address, finds it.)
 *
 * SR-2 requires IMMUTABLE storage: anchoring is write-once. Re-anchoring the SAME bytes
 * at the same address is idempotent; anchoring DIFFERENT bytes there throws, so a locator
 * can never be mutated after the fact (no "anchor, then swap the content" attack).
 * Note: the read-then-write check is not atomic across concurrent writers — acceptable for
 * this single-process reference substrate; a production store would anchor transactionally.
 */
export async function localAnchor(
  storeDir: string,
  storageAddress: string,
  data: object | string,
  owner = 'local',
): Promise<AnchorResult> {
  await fs.mkdir(storeDir, { recursive: true });
  const bytes = dataBytes(data);
  const existing = await localFetchAnchored(storeDir, storageAddress);
  if (existing) {
    // Immutable: identical re-anchor is a no-op; a differing one is rejected.
    if (bytesToHex(sha256(dataBytes(existing.data))) !== bytesToHex(sha256(bytes))) {
      throw new Error(`SR-2 immutability: ${storageAddress} already anchored with different content`);
    }
    return { storageAddress, txHash: 'local', sizeBytes: existing.sizeBytes, anchoredAt: existing.createdAt ?? '' };
  }
  const record: FetchResult = {
    storageAddress,
    owner,
    data,
    sizeBytes: bytes.length,
    createdByTx: 'local',
    createdAt: new Date().toISOString(),
  };
  await fs.writeFile(recordPath(storeDir, storageAddress), JSON.stringify(record));
  return { storageAddress, txHash: 'local', sizeBytes: bytes.length, anchoredAt: record.createdAt };
}

/** Fetch a previously anchored record. Signature matches `typeof fetchAnchored`. */
export async function localFetchAnchored(
  storeDir: string,
  storageAddress: string,
): Promise<FetchResult | null> {
  try {
    const raw = await fs.readFile(recordPath(storeDir, storageAddress), 'utf8');
    const record = JSON.parse(raw) as FetchResult;
    // Fetch-by-anchor must bind: a record whose own locator differs from what was
    // requested is treated as absent (guards a corrupted/miswritten store).
    if (record.storageAddress !== storageAddress) return null;
    return record;
  } catch {
    return null; // not found / unreadable — the SR-2 "absent" case
  }
}

/**
 * Verify anchored bytes match an expected SHA-256 (DACS §7.5.2 contract).
 * Identical pass / fail / indeterminate semantics to `src/demos/storage.ts::verifyAnchor`.
 */
export async function localVerifyAnchor(
  storeDir: string,
  storageAddress: string,
  expectedContentHashHex: string,
): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string; actualHashHex?: string }> {
  const result = await localFetchAnchored(storeDir, storageAddress);
  if (!result) {
    return { outcome: 'indeterminate', detail: `anchor ${storageAddress} not found in ${storeDir}` };
  }
  const actualHashHex = bytesToHex(sha256(dataBytes(result.data)));
  return actualHashHex === expectedContentHashHex
    ? { outcome: 'pass', detail: 'fetched + hash matched', actualHashHex }
    : { outcome: 'fail', detail: 'fetched but hash mismatched', actualHashHex };
}
