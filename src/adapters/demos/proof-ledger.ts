/**
 * PATH-OS SR-2 proof ledger.
 *
 * Demos SDK storage programs are create-only through the repository's live `anchor()` API. To
 * preserve append-only history, append n creates an immutable program named `<ledgerName>#<n>`
 * containing the complete ledger through n. From version 2 onward the new entry records the
 * preceding program's address in `detail.prev`. The returned ledger object retains the current
 * locator; callers must persist the latest append result when continuing in another process.
 */

import type { DemosHandle } from '../../demos/connection.js';
import {
  planAppend,
  type AppendPlan,
  type LedgerData,
  type ReceiptEntry,
} from '../../demos/receipt-ledger.js';
import {
  fetchAnchored,
  type FetchResult,
} from '../../demos/storage.js';
import { jcsHashHex } from '../../jcs.js';

export type { AppendPlan, LedgerData, ReceiptEntry } from '../../demos/receipt-ledger.js';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function isoTimestamp(value: unknown, label: string): string {
  const timestamp = nonEmptyString(value, label);
  if (!Number.isFinite(Date.parse(timestamp))) throw new Error(`${label} must be an ISO timestamp`);
  return timestamp;
}

/** Project an outbound-gate receipt onto the only fields permitted on SR-2. */
export function receiptEntryFromOutboundReceipt(receipt: unknown): ReceiptEntry {
  const source = record(receipt, 'outbound receipt');
  const action = nonEmptyString(source.action, 'outbound receipt.action');
  const target = nonEmptyString(source.target, 'outbound receipt.target');
  const contentHash = nonEmptyString(source.content_sha256, 'outbound receipt.content_sha256');
  if (!SHA256_HEX.test(contentHash)) {
    throw new Error('outbound receipt.content_sha256 must be 64 lowercase hexadecimal characters');
  }
  const outcome = nonEmptyString(source.verdict, 'outbound receipt.verdict');
  const tier = nonEmptyString(source.tier, 'outbound receipt.tier');
  const verdictCode = nonEmptyString(source.verdict_code, 'outbound receipt.verdict_code');
  if (typeof source.ts !== 'number' || !Number.isFinite(source.ts) || source.ts < 0) {
    throw new Error('outbound receipt.ts must be a non-negative numeric Unix timestamp in seconds');
  }
  const at = new Date(source.ts * 1_000).toISOString();

  return {
    kind: 'outbound-receipt',
    ref: `${action}:${target}`,
    contentHash,
    outcome,
    at,
    detail: { tier, verdictCode },
  };
}

/** Project one Case history event; excluded event fields never enter the hash or ledger entry. */
export function gateVerdictEntryFromCase(caseJson: unknown, historyIndex: number): ReceiptEntry {
  const source = record(caseJson, 'Case');
  const id = nonEmptyString(source.id, 'Case.id');
  nonEmptyString(source.stage, 'Case.stage');
  if (!Number.isInteger(historyIndex) || historyIndex < 0) {
    throw new Error('historyIndex must be a non-negative integer');
  }
  if (!Array.isArray(source.history)) throw new Error('Case.history must be an array');
  if (historyIndex >= source.history.length) throw new Error(`Case.history[${historyIndex}] is missing`);
  const event = record(source.history[historyIndex], `Case.history[${historyIndex}]`);
  if (!('passed' in event) && !('from' in event)) {
    throw new Error(
      `Case.history[${historyIndex}] is not a gate-verdict event (open and annotation events carry no from or passed field); pick an event that records a gate verdict`,
    );
  }
  const from = nonEmptyString(event.from, `Case.history[${historyIndex}].from`);
  const to = nonEmptyString(event.to, `Case.history[${historyIndex}].to`);
  const by = nonEmptyString(event.by, `Case.history[${historyIndex}].by`);
  const gate = nonEmptyString(event.gate, `Case.history[${historyIndex}].gate`);
  if (typeof event.passed !== 'boolean') {
    throw new Error(`Case.history[${historyIndex}].passed must be boolean`);
  }
  const ts = isoTimestamp(event.ts, `Case.history[${historyIndex}].ts`);
  const hashProjection = { id, from, to, by, gate, passed: event.passed, ts };

  return {
    kind: 'gate-verdict',
    ref: `${id}:${to}`,
    contentHash: jcsHashHex(hashProjection),
    outcome: event.passed ? 'PASS' : 'FAIL',
    at: ts,
    detail: { from, to, gate },
  };
}

function ledgerFromPlan(plan: AppendPlan): LedgerData {
  const payload = record(plan.payload, 'append plan payload');
  return parseLedger(payload.data, 'append plan payload.data');
}

type BroadcastPlanResult = { txHash: string };
type BroadcastPlan = (handle: DemosHandle, payload: unknown) => Promise<BroadcastPlanResult>;

/** Sign and broadcast the exact payload whose address and bytes were checked by planAppend(). */
async function broadcastPlan(handle: DemosHandle, payload: unknown): Promise<BroadcastPlanResult> {
  const demos = handle.demos as unknown as {
    storagePrograms: { sign: (value: unknown) => Promise<unknown> };
    confirm: (tx: unknown) => Promise<unknown>;
    broadcastAndWait: (
      validity: unknown,
      options?: { timeoutMs?: number },
    ) => Promise<{
      broadcast?: { response?: { hash?: string }; data?: { tx_hash?: string; hash?: string } };
      status?: { state?: string };
    }>;
  };
  const tx = await demos.storagePrograms.sign(payload);
  const validity = await demos.confirm(tx);
  const result = await demos.broadcastAndWait(validity, { timeoutMs: 240_000 });
  if (result.status?.state !== 'included') {
    throw new Error(`proof-ledger: append was not included (state=${result.status?.state ?? 'missing'})`);
  }
  const txHash = result.broadcast?.response?.hash
    ?? result.broadcast?.data?.tx_hash
    ?? result.broadcast?.data?.hash;
  // The storage-program broadcast response has carried no transaction hash on the current
  // testnet node (observed 2026-09-02 on every anchor); the included state and the planned
  // storage address are the success criteria, and the hash is reported when present.
  return { txHash: typeof txHash === 'string' ? txHash : '' };
}

function parseLedger(value: unknown, label: string): LedgerData {
  const data = record(value, label);
  if (data.ledgerVersion !== '1') throw new Error(`${label}.ledgerVersion must be "1"`);
  const name = nonEmptyString(data.name, `${label}.name`);
  if (!Array.isArray(data.entries)) throw new Error(`${label}.entries must be an array`);
  for (const [index, rawEntry] of data.entries.entries()) {
    const entry = record(rawEntry, `${label}.entries[${index}]`);
    nonEmptyString(entry.kind, `${label}.entries[${index}].kind`);
    nonEmptyString(entry.ref, `${label}.entries[${index}].ref`);
    const hash = nonEmptyString(entry.contentHash, `${label}.entries[${index}].contentHash`);
    if (!SHA256_HEX.test(hash)) throw new Error(`${label}.entries[${index}].contentHash is malformed`);
    isoTimestamp(entry.at, `${label}.entries[${index}].at`);
  }
  return data as unknown as LedgerData;
}

function fetchedLedger(fetched: FetchResult | null, address: string): LedgerData {
  if (fetched === null) throw new Error(`proof-ledger: known ledger ${address} is not readable`);
  return parseLedger(fetched.data, `anchor ${address}`);
}

export async function createProofLedger(opts: {
  handle: DemosHandle;
  rpc: string;
  ledgerName: string;
  acl?: 'public' | 'private';
  head?: { storageAddress: string };
  broadcastImpl?: BroadcastPlan;
  fetchAnchoredImpl?: typeof fetchAnchored;
}): Promise<{
  plan(entry: ReceiptEntry): Promise<AppendPlan>;
  append(entry: ReceiptEntry): Promise<{
    storageAddress: string;
    entryCount: number;
    contentHash: string;
    txHash: string;
  }>;
  read(): Promise<LedgerData>;
  verify(): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string }>;
}> {
  const broadcastImpl = opts.broadcastImpl ?? broadcastPlan;
  const fetchImpl = opts.fetchAnchoredImpl ?? fetchAnchored;
  let latestAddress: string | undefined;
  let latestEntryCount = 0;
  let expectedContentHash: string | undefined;

  if (opts.head !== undefined) {
    const address = nonEmptyString(opts.head.storageAddress, 'proof-ledger head.storageAddress');
    const fetched = await fetchImpl(opts.rpc, address);
    const parsed = fetchedLedger(fetched, address);
    if (fetched!.owner !== opts.handle.address) {
      throw new Error(
        `proof-ledger: head ${address} owner ${fetched!.owner} is not ${opts.handle.address}`,
      );
    }
    if (
      parsed.entries.length < 1
      || parsed.name !== `${opts.ledgerName}#${parsed.entries.length}`
    ) {
      throw new Error(
        `proof-ledger: head ${address} is ${parsed.name}, not ${opts.ledgerName}#${parsed.entries.length}`,
      );
    }
    latestAddress = fetched!.storageAddress;
    latestEntryCount = parsed.entries.length;
    expectedContentHash = jcsHashHex(parsed);
  }

  const versionName = () => `${opts.ledgerName}#${latestEntryCount + 1}`;
  const linkedEntry = (entry: ReceiptEntry): ReceiptEntry => latestAddress === undefined
    ? { ...entry, detail: entry.detail === undefined ? undefined : { ...entry.detail } }
    : { ...entry, detail: { ...(entry.detail ?? {}), prev: latestAddress } };

  async function plan(entry: ReceiptEntry): Promise<AppendPlan> {
    return planAppend(opts.handle, opts.rpc, versionName(), linkedEntry(entry), {
      acl: opts.acl,
      baseAddress: latestAddress,
      fetchAnchoredImpl: fetchImpl,
      detailKeys: ['tier', 'verdictCode', 'from', 'to', 'gate', 'prev'],
    });
  }

  async function append(entry: ReceiptEntry) {
    const appendPlan = await plan(entry);
    if (!appendPlan.withinSizeLimit) {
      throw new Error(
        `proof-ledger: append refused because ${appendPlan.sizeBytes} bytes exceed the SR-2 size limit`,
      );
    }
    if (appendPlan.op !== 'create') {
      throw new Error('proof-ledger: immutable version destination already exists');
    }
    const ledger = ledgerFromPlan(appendPlan);
    const contentHash = jcsHashHex(record(appendPlan.payload, 'append plan payload').data);
    const broadcast = await broadcastImpl(opts.handle, appendPlan.payload);
    latestAddress = appendPlan.storageAddress;
    latestEntryCount = ledger.entries.length;
    expectedContentHash = contentHash;
    return {
      storageAddress: appendPlan.storageAddress,
      entryCount: ledger.entries.length,
      contentHash,
      txHash: broadcast.txHash,
    };
  }

  async function read(): Promise<LedgerData> {
    if (latestAddress === undefined) {
      return { ledgerVersion: '1', name: opts.ledgerName, entries: [] };
    }
    return fetchedLedger(await fetchImpl(opts.rpc, latestAddress), latestAddress);
  }

  async function verify(): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string }> {
    if (latestAddress === undefined || expectedContentHash === undefined) {
      return { outcome: 'indeterminate', detail: 'no anchored ledger version is known' };
    }
    const fetched = await fetchImpl(opts.rpc, latestAddress);
    if (fetched === null) {
      return { outcome: 'indeterminate', detail: `anchor ${latestAddress} was not found` };
    }
    let actual: string;
    try {
      actual = jcsHashHex(parseLedger(fetched.data, `anchor ${latestAddress}`));
    } catch (error) {
      return { outcome: 'fail', detail: `anchored ledger is malformed: ${(error as Error).message}` };
    }
    return actual === expectedContentHash
      ? { outcome: 'pass', detail: `anchor ${latestAddress} matches ${expectedContentHash}` }
      : {
          outcome: 'fail',
          detail: `anchor ${latestAddress} hash mismatch: expected ${expectedContentHash}, got ${actual}`,
        };
  }

  return { plan, append, read, verify };
}
