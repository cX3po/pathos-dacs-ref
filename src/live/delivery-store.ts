/**
 * delivery-store.ts — durable record of paid deliveries for the verify endpoint.
 *
 * One JSONL file per deployment scope. Line 1 is the scope header `{ v, scope }`; every later line is
 * `{ key, payload, at }` for one delivered verification, where `key` is the endpoint's proof key (JSON of
 * [txHash, resourceId]) and `payload` is the exact JSON body the response finished writing. The endpoint appends
 * after the response finishes writing to the local transport. A record preserves the original result for retry; it
 * does not prove buyer receipt. Payloads stay on disk: `load()` builds a key → (offset, length) index and `get()`
 * reads one payload back, so retained memory is bounded by the index, not by payload bytes.
 *
 * Scope: a store written by one deployment (recipient, seller key, network, price, verification mode, implementation
 * revision) is refused by a differently configured one; redelivering an old signed result under a new seller key,
 * price or implementation is a policy decision that must be explicit, so startup refuses instead of guessing.
 * Appends are newline-safe (a torn tail from a crash is separated from the next record) and fsynced.
 */
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, writeSync, fsyncSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export const DELIVERY_STORE_VERSION = 'delivery-store:1';
export const SCOPE_MISMATCH = 'Delivery store deployment scope mismatch; explicit migration is required.';

export interface DeliveryScope {
  recipient: string;
  sellerPubKeyHex: string | null;
  networkId: string | null;
  amountOs: string;
  offline: boolean;
  implementationVersion: string;
}

export interface DeliveryStore {
  /** Index every durable record (payload bytes stay on disk); a corrupt or torn line is skipped and counted. Throws SCOPE_MISMATCH. */
  load(): { keys: string[]; corrupt: number };
  /** One payload back from disk, or undefined. */
  get(key: string): string | undefined;
  /** Append one delivered payload; call only after the response finished writing. Newline-safe, fsynced. */
  append(key: string, payload: string): void;
}

function scopeEqual(a: DeliveryScope, b: DeliveryScope): boolean {
  return JSON.stringify(a, Object.keys(a).sort()) === JSON.stringify(b, Object.keys(b).sort());
}

export function createFileDeliveryStore(path: string, scope: DeliveryScope): DeliveryStore {
  const index = new Map<string, { offset: number; length: number }>();
  let loaded = false;
  const readAll = (): Buffer => {
    if (!existsSync(path)) return Buffer.alloc(0);
    const fd = openSync(path, 'r');
    try { const size = fstatSync(fd).size; const buf = Buffer.alloc(size); if (size) readSync(fd, buf, 0, size, 0); return buf; }
    finally { closeSync(fd); }
  };
  return {
    load() {
      index.clear();
      let corrupt = 0;
      const buf = readAll();
      let offset = 0, first = true;
      while (offset < buf.length) {
        const nl = buf.indexOf(0x0a, offset);
        if (nl === -1) { corrupt += 1; break; }  // torn tail: no newline, skipped; append() separates it
        const line = buf.subarray(offset, nl).toString('utf8');
        const lineOffset = offset; offset = nl + 1;
        if (!line.trim()) continue;
        let row: { v?: unknown; scope?: unknown; key?: unknown; payload?: unknown };
        try { row = JSON.parse(line); } catch { corrupt += 1; continue; }
        if (first) {
          first = false;
          if (row.v !== DELIVERY_STORE_VERSION || typeof row.scope !== 'object' || row.scope === null || !scopeEqual(row.scope as DeliveryScope, scope)) throw new Error(SCOPE_MISMATCH);
          continue;
        }
        if (typeof row.key !== 'string' || typeof row.payload !== 'string') { corrupt += 1; continue; }
        index.set(row.key, { offset: lineOffset, length: nl - lineOffset });
      }
      loaded = true;
      return { keys: [...index.keys()], corrupt };
    },
    get(key) {
      const at = index.get(key);
      if (!at) return undefined;
      const fd = openSync(path, 'r');
      try {
        const buf = Buffer.alloc(at.length); readSync(fd, buf, 0, at.length, at.offset);
        const row = JSON.parse(buf.toString('utf8')) as { payload?: unknown };
        return typeof row.payload === 'string' ? row.payload : undefined;
      } catch { return undefined; } finally { closeSync(fd); }
    },
    append(key, payload) {
      mkdirSync(dirname(path), { recursive: true });
      const fresh = !existsSync(path) || statSync(path).size === 0;
      const fd = openSync(path, 'a');
      try {
        let position = fstatSync(fd).size;
        if (fresh) { const header = JSON.stringify({ v: DELIVERY_STORE_VERSION, scope }) + '\n'; writeSync(fd, header); position += Buffer.byteLength(header); }
        else {
          // newline-safe: a torn tail from an interrupted append is terminated before the new record
          const tail = Buffer.alloc(1); const rfd = openSync(path, 'r');
          try { readSync(rfd, tail, 0, 1, position - 1); } finally { closeSync(rfd); }
          if (tail[0] !== 0x0a) { writeSync(fd, '\n'); position += 1; }
        }
        const line = JSON.stringify({ key, payload, at: new Date().toISOString() }) + '\n';
        writeSync(fd, line); fsyncSync(fd);
        if (loaded) index.set(key, { offset: position, length: Buffer.byteLength(line) - 1 });
      } finally { closeSync(fd); }
    },
  };
}
