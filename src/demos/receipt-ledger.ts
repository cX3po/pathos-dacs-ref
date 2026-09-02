/**
 * PATH-OS Receipt Ledger — append-only, third-party-anchored audit trail on Demos SR-2.
 *
 * Apprenticed from the 2026-06-05 Demos SDK audit (opportunity #2 — the only one giving PATH-OS
 * a capability it can't do locally): a tamper-evident, ACL'd, deterministically-addressed ledger
 * of PATH-OS receipts (DACS-5 envelope receipts, Gate verdicts, capture milestones). The receipts
 * our verifier checks come to LIVE on the chain whose standard they implement.
 *
 * Built ON src/demos/storage.ts (reuse, not rebuild). This module adds only the append-only LEDGER
 * pattern. In demosdk v4.0.0 there is no static `appendItem`, so append = read-modify-write:
 * fetch the current ledger -> append the entry -> writeStorage with the full updated object.
 *
 * ⚠️ DRY-RUN ONLY (2026-06-05, owner-away build mandate). This module builds payloads and computes
 * cost/size from on-chain READS, but DELIBERATELY does not broadcast — `createStorageProgram`/
 * `writeStorage` writes cost DEM and are PERMANENT. The broadcast path (DemosTransactions.confirm
 * + broadcastAndWait, as in storage.ts::anchor) is the owner-gated step and is intentionally absent
 * here. `planAppend()` returns everything needed to ship that write once approved.
 */

import { StorageProgram } from '@kynesyslabs/demosdk/storage';
import type { DemosHandle } from './connection.js';
import { fetchAnchored, type FetchResult } from './storage.js';

/** One receipt anchored to the ledger. Kept small + hash-stable. */
export interface ReceiptEntry {
  /** what this receipt is: dacs5-bundle | gate-verdict | capture-milestone | … */
  kind: string;
  /** stable id for the thing receipted (jobId, commit hash, gate id) */
  ref: string;
  /** sha-256 hex of the receipted artifact (the tamper-evident anchor) */
  contentHash: string;
  /** terminal outcome / verdict, if any (pass|fail|APPROVED|…) */
  outcome?: string;
  /** ISO-8601 capture time */
  at: string;
  /** optional free-form structured detail (kept minimal — storage is 1 DEM/10 KB) */
  detail?: Record<string, unknown>;
}

/** The full ledger object stored at the SR-2 address (an append-only array of entries). */
export interface LedgerData {
  ledgerVersion: '1';
  name: string;
  entries: ReceiptEntry[];
}

/** What a dry-run append produces — everything needed to broadcast later, but nothing sent. */
export interface AppendPlan {
  /** the deterministic SR-2 address this ledger lives at */
  storageAddress: string;
  /** true if the ledger already exists on-chain (→ writeStorage), false if it'd be created */
  exists: boolean;
  /** entry count after the append */
  entryCount: number;
  /** the StorageProgramPayload that WOULD be broadcast (create or write) — NOT sent */
  payload: unknown;
  /** which SDK call builds it: 'create' (first entry) | 'write' (append) */
  op: 'create' | 'write';
  /** serialized size + the storage fee the write would cost, in OS (the SDK's raw denomination —
   *  calculateStorageFee returns OS, NOT DEM; DEM = feeOS / 1e9). Deterministic. */
  sizeBytes: number;
  feeOS: string;
  /** false if the post-append ledger would exceed the StorageProgram size cap */
  withinSizeLimit: boolean;
}

const ENCODING = 'json' as const;

/** Derive the deterministic SR-2 address for a named ledger owned by `handle`'s wallet. */
export async function deriveLedgerAddress(
  handle: DemosHandle,
  ledgerName: string,
  salt = ''
): Promise<{ storageAddress: string; nonce: number }> {
  const { demos, address } = handle;
  const nonceInfo = await demos.getAddressNonce(address);
  const nonce =
    typeof nonceInfo === 'number'
      ? nonceInfo
      : typeof nonceInfo === 'object' && nonceInfo !== null && 'nonce' in nonceInfo
        ? Number((nonceInfo as { nonce: number }).nonce)
        : 0;
  const storageAddress = StorageProgram.deriveStorageAddress(address, ledgerName, nonce, salt);
  return { storageAddress, nonce };
}

/** Parse an already-fetched anchor into LedgerData without converting malformed data to absence. */
function parseLedger(
  fetched: FetchResult | null,
  name: string,
  knownAddress?: string,
): LedgerData {
  if (fetched === null) {
    if (knownAddress !== undefined) {
      throw new Error(`receipt-ledger: ledger ${knownAddress} is not readable`);
    }
    return { ledgerVersion: '1', name, entries: [] };
  }
  if (typeof fetched.data !== 'object' || fetched.data === null || Array.isArray(fetched.data)) {
    throw new Error('receipt-ledger: fetched ledger data must be a JSON object');
  }
  const data = fetched.data as Partial<LedgerData>;
  if (data.ledgerVersion !== '1') {
    throw new Error('receipt-ledger: fetched ledger ledgerVersion must be "1"');
  }
  if (!Array.isArray(data.entries)) {
    throw new Error('receipt-ledger: fetched ledger entries must be an array');
  }
  return {
    ledgerVersion: '1',
    name: data.name ?? name,
    entries: data.entries,
  };
}

export async function readLedger(rpc: string, storageAddress: string, name = ''): Promise<LedgerData> {
  return parseLedger(await fetchAnchored(rpc, storageAddress), name, storageAddress);
}

const UNSAFE_DETAIL_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Copy only the public receipt-ledger schema; never retain caller/fetched extra own properties. */
function pickEntry(source: ReceiptEntry, detailKeys?: readonly string[]): ReceiptEntry {
  const picked: ReceiptEntry = {
    kind: source.kind,
    ref: source.ref,
    contentHash: source.contentHash,
    ...(source.outcome === undefined ? {} : { outcome: source.outcome }),
    at: source.at,
  };
  if (source.detail !== undefined) {
    const detail: Record<string, unknown> = {};
    const keys = detailKeys ?? Object.keys(source.detail);
    for (const key of keys) {
      if (
        !UNSAFE_DETAIL_KEYS.has(key)
        && Object.prototype.hasOwnProperty.call(source.detail, key)
      ) {
        detail[key] = source.detail[key];
      }
    }
    picked.detail = detail;
  }
  return picked;
}

/**
 * Plan an append WITHOUT broadcasting. Reads the current ledger, appends `entry`, and builds the
 * exact payload + cost that a real write would use. The caller (once the operator approves) signs +
 * broadcasts it via the storage.ts::anchor pipeline. Returns everything needed for that step.
 *
 * STABLE LOCATOR (Codex HIGH 2026-06-05): a StorageProgram address embeds the creation nonce, so
 * re-deriving from the wallet's CURRENT nonce drifts after the create tx advances it. Therefore:
 *   - FIRST entry (no `knownAddress`): derive from current nonce. op='create' if the derived address
 *     is empty, else 'write'. The caller MUST persist the returned `storageAddress` (and salt) —
 *     that is the ledger's permanent locator.
 *   - EVERY later append: pass that persisted `knownAddress`. The append is ALWAYS a write to that
 *     exact address — never re-derived, never a create. If the known ledger cannot be read, we FAIL
 *     LOUDLY rather than risk a wrong-address create or clobbering prior entries (Codex HIGH 2026-06-05).
 *
 * Pure reads + deterministic payload construction, no DEM spent, nothing permanent.
 */
export async function planAppend(
  handle: DemosHandle,
  rpc: string,
  ledgerName: string,
  entry: ReceiptEntry,
  options: {
    salt?: string;
    acl?: 'public' | 'private';
    knownAddress?: string;
    /** Read an immutable prior version, but create this append under `ledgerName`. */
    baseAddress?: string;
    /** Test seam; production callers use the fail-closed SR-2 fetcher. */
    fetchAnchoredImpl?: typeof fetchAnchored;
    /** When supplied, retain only these safe own keys from each entry's detail object. */
    detailKeys?: readonly string[];
  } = {}
): Promise<AppendPlan> {
  const { address } = handle;
  const fetchImpl = options.fetchAnchoredImpl ?? fetchAnchored;
  if (options.knownAddress && options.baseAddress) {
    throw new Error('receipt-ledger: knownAddress and baseAddress are mutually exclusive');
  }

  // Resolve the locator + decide create-vs-write from ONE read, reusing that same fetch for the
  // ledger contents (no second read → no clobber risk, no op/payload race). (Codex HIGH 2026-06-05)
  let storageAddress: string;
  let nonce = 0;
  let op: 'create' | 'write';
  let fetched: FetchResult | null;

  if (options.knownAddress) {
    // Append to an existing ledger: ALWAYS a write to this exact address. If it can't be read,
    // refuse — a fallback create would fork a new program at a different address, and a blind
    // write would clobber prior entries with an empty base.
    storageAddress = options.knownAddress;
    fetched = await fetchImpl(rpc, storageAddress);
    if (fetched == null) {
      throw new Error(
        `receipt-ledger: knownAddress ${storageAddress} is not readable — refusing to plan an append ` +
        `(a create would use the wrong address; a write would clobber prior entries). Retry when the RPC/ledger is reachable.`
      );
    }
    op = 'write';
  } else {
    // First-time path: derive from current nonce. Append if it already exists, else create.
    const derived = await deriveLedgerAddress(handle, ledgerName, options.salt ?? '');
    storageAddress = derived.storageAddress;
    nonce = derived.nonce;
    fetched = await fetchImpl(rpc, storageAddress);
    op = fetched != null ? 'write' : 'create';
  }

  // A versioned append creates a new program but copies the complete prior immutable ledger.
  // The prior version must be readable: absence is never interpreted as an empty ledger.
  let baseFetched: FetchResult | null = fetched;
  if (options.baseAddress) {
    if (op !== 'create') {
      throw new Error(
        `receipt-ledger: version destination ${storageAddress} already exists — refusing to overwrite it`,
      );
    }
    baseFetched = await fetchImpl(rpc, options.baseAddress);
    if (baseFetched == null) {
      throw new Error(
        `receipt-ledger: baseAddress ${options.baseAddress} is not readable — refusing to fork an empty ledger`,
      );
    }
  }

  // Contents come from the fetches used to decide the operation/base.
  const current = parseLedger(
    baseFetched,
    ledgerName,
    options.baseAddress ?? options.knownAddress,
  );
  const exists = op === 'write';
  const next: LedgerData = {
    ledgerVersion: '1',
    name: ledgerName,
    entries: [
      ...current.entries.map((currentEntry) => pickEntry(currentEntry, options.detailKeys)),
      pickEntry(entry, options.detailKeys),
    ],
  };

  const withinSizeLimit = StorageProgram.validateSize(next, ENCODING);
  const sizeBytes = StorageProgram.getDataSize(next, ENCODING);
  // calculateStorageFee returns OS (raw denomination), NOT DEM — expose it as feeOS (DEM = /1e9).
  const feeOS = StorageProgram.calculateStorageFee(next, ENCODING).toString();

  // Build the payload that WOULD be sent (op decided above from a single read). Not broadcast.
  let payload: unknown;
  if (op === 'write') {
    payload = StorageProgram.writeStorage(storageAddress, next, ENCODING);
  } else {
    const acl = options.acl === 'private' ? StorageProgram.privateACL() : StorageProgram.publicACL();
    payload = StorageProgram.createStorageProgram(address, ledgerName, next, ENCODING, acl, {
      nonce,
      salt: options.salt,
    });
  }

  return {
    storageAddress,
    exists,
    entryCount: next.entries.length,
    payload,
    op,
    sizeBytes,
    feeOS,
    withinSizeLimit,
  };
}
