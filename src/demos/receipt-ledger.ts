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

/**
 * Read the current ledger from chain (READ-ONLY, safe). Returns its entries, or an empty ledger
 * if it doesn't exist yet.
 */
/** Parse an already-fetched anchor into a LedgerData (PURE — no network). Empty ledger if absent. */
function parseLedger(fetched: FetchResult | null, name: string): LedgerData {
  if (!fetched || fetched.data == null) {
    return { ledgerVersion: '1', name, entries: [] };
  }
  const data = fetched.data as Partial<LedgerData>;
  return {
    ledgerVersion: '1',
    name: data.name ?? name,
    entries: Array.isArray(data.entries) ? data.entries : [],
  };
}

export async function readLedger(rpc: string, storageAddress: string, name = ''): Promise<LedgerData> {
  return parseLedger(await fetchAnchored(rpc, storageAddress), name);
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
  options: { salt?: string; acl?: 'public' | 'private'; knownAddress?: string } = {}
): Promise<AppendPlan> {
  const { address } = handle;

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
    fetched = await fetchAnchored(rpc, storageAddress);
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
    fetched = await fetchAnchored(rpc, storageAddress);
    op = fetched != null ? 'write' : 'create';
  }

  // Contents come from the SAME fetch used to decide op — never re-read.
  const current = parseLedger(fetched, ledgerName);
  const exists = op === 'write';
  const next: LedgerData = {
    ledgerVersion: '1',
    name: ledgerName,
    entries: [...current.entries, entry],
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
