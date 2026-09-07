/**
 * delivery-store.ts — durable record of paid deliveries for the verify endpoint.
 *
 * One JSONL file, append-only: `{ key, payload, at }` per delivered verification, where `key` is the endpoint's
 * proof key (JSON of [txHash, resourceId]) and `payload` is the exact JSON body that was sent (verdict, receipt,
 * deliveryReceipt). The endpoint appends only after the bytes were sent, so a record means the buyer received it.
 * On startup the endpoint loads the file to rebuild its committed set and its redelivery map: after a restart or a
 * cache eviction, the same proof for the same bytes is answered with the original signed payload, never re-verified
 * and never billed again. The file holds no key material and no buyer beyond what the receipt already names.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface DeliveryStore {
  /** Every durable record, in append order; a corrupt line is skipped and counted. */
  load(): { records: Map<string, string>; corrupt: number };
  /** Append one delivered payload; must be called only after the bytes were sent. */
  append(key: string, payload: string): void;
}

export function createFileDeliveryStore(path: string): DeliveryStore {
  return {
    load() {
      const records = new Map<string, string>();
      let corrupt = 0;
      if (!existsSync(path)) return { records, corrupt };
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const row = JSON.parse(line) as { key?: unknown; payload?: unknown };
          if (typeof row.key !== 'string' || typeof row.payload !== 'string') { corrupt += 1; continue; }
          records.set(row.key, row.payload);
        } catch { corrupt += 1; }
      }
      return { records, corrupt };
    },
    append(key, payload) {
      mkdirSync(dirname(path), { recursive: true });
      appendFileSync(path, JSON.stringify({ key, payload, at: new Date().toISOString() }) + '\n', 'utf8');
    },
  };
}

export function createMemoryDeliveryStore(): DeliveryStore & { rows: Array<{ key: string; payload: string }> } {
  const rows: Array<{ key: string; payload: string }> = [];
  return {
    rows,
    load() { return { records: new Map(rows.map((r) => [r.key, r.payload])), corrupt: 0 }; },
    append(key, payload) { rows.push({ key, payload }); },
  };
}
