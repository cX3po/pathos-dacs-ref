/**
 * Local DEM-denominated internal metering for PATH-OS.
 *
 * This is an internal accounting document surface. It is not a DACS artifact and an
 * invoice produced here is not a payment request. The meter performs no on-chain writes.
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { dirname } from 'node:path';

import { demToOs, osToDem } from '../dacs/pay-dem.js';
import { jcsCanonical, jcsHashHex } from '../../jcs.js';
import { resolvePayDemJournalPath } from '../../live/pay-dem-journal.js';
import { DemMeterError, type MeterErrorCode } from './dem-meter-errors.js';

export {
  DemMeterError,
  meterErrorResult,
  type MeterErrorCode,
  type MeterErrorResult,
} from './dem-meter-errors.js';

export const DEM_METER_KINDS = [
  'seat-call',
  'tool-call',
  'anchor',
  'transfer',
  'receipt-read',
  'verify-call',
] as const;

export type MeterKind = typeof DEM_METER_KINDS[number];

export type MeterEntry = {
  /** May be omitted only when createDemMeter was given a default agent. */
  agent?: string;
  kind: MeterKind;
  receiptHash?: string;
  ref?: string;
  at?: string;
} & ({ os: string; dem?: never } | { dem: string; os?: never });

export interface MeterRow {
  agent: string;
  kind: MeterKind;
  os: string;
  at: string;
  receiptHash?: string;
  ref?: string;
  prevRowHash?: string;
  rowHash: string;
}

export interface MeterTotal {
  count: number;
  os: string;
  dem: string;
}

export interface MeterSummary {
  rowCount: number;
  totalOs: string;
  totalDem: string;
  byAgent: Record<string, MeterTotal>;
  byKind: Partial<Record<MeterKind, MeterTotal>>;
  lastRowHash: string | null;
}

export interface InvoiceDocument {
  v: 'pathos-dem-invoice:0.1';
  issuer: string;
  payer: string;
  period: { since: string; until: string };
  lines: Array<{ kind: MeterKind; count: number; os: string; dem: string }>;
  totalOs: string;
  totalDem: string;
  meterHead: string | null;
  meteredReceiptHashes: string[];
  notice: 'unsigned internal accounting; not a DACS artifact, not settlement proof, not a payment request';
  contentHash: string;
}

export interface DemMeter {
  record(entry: MeterEntry): MeterRow;
  summarize(opts?: { since?: string; until?: string; agent?: string }): MeterSummary;
  invoice(opts: {
    from: string;
    to: string;
    issuer?: string;
    payer?: string;
    since: string;
    until: string;
  }): InvoiceDocument;
  read(): MeterRow[];
  repair(): { rowCount: number; meterHead: string | null };
}

const OS_RE = /^(?:0|[1-9]\d*)$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const SEAT_RE = /^[a-z0-9._-]+$/;
const CCI_RE = /^cci:(?:0x)?[0-9a-fA-F]{64}$/;
const CANONICAL_CCI_RE = /^cci:(?:0x)?[0-9a-f]{64}$/;
const LOCK_WAIT_MS = 2_000;
const LOCK_RETRY_MS = 20;

type MeterHead = { rowCount: number; meterHead: string | null };

function fail(code: MeterErrorCode, message: string): never {
  throw new DemMeterError(code, message);
}

function requireAgent(value: unknown): string {
  if (typeof value !== 'string' || (!SEAT_RE.test(value) && !CCI_RE.test(value))) {
    throw new Error('dem meter agent must be a CCI claim or a lowercase seat name');
  }
  return value.startsWith('cci:') ? value.toLowerCase() : value;
}

function requireStoredAgent(value: unknown): string {
  const agent = requireAgent(value);
  if (typeof value === 'string' && value.startsWith('cci:') && !CANONICAL_CCI_RE.test(value)) {
    throw new Error('dem meter stored CCI agent must use lowercase hexadecimal');
  }
  return agent;
}

function requireIso(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/i.test(value)) {
    throw new Error(`dem meter ${label} must be an ISO timestamp with a timezone`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error(`dem meter ${label} must be a valid ISO timestamp`);
  return value;
}

function requireKind(value: unknown): MeterKind {
  if (!(DEM_METER_KINDS as readonly unknown[]).includes(value)) {
    throw new Error('dem meter kind is unknown');
  }
  return value as MeterKind;
}

function requireOs(value: unknown): string {
  if (typeof value !== 'string' || !OS_RE.test(value)) {
    throw new Error('dem meter OS amount must be a canonical non-negative integer string');
  }
  return value;
}

function osFromEntry(entry: MeterEntry): string {
  const raw = entry as MeterEntry & { os?: unknown; dem?: unknown };
  const hasOs = Object.hasOwn(raw, 'os');
  const hasDem = Object.hasOwn(raw, 'dem');
  if (hasOs === hasDem) throw new Error('dem meter entry must contain exactly one of os or dem');
  if (hasOs) return requireOs(raw.os);
  if (raw.dem === '0') return '0';
  if (typeof raw.dem !== 'string') throw new Error('dem meter DEM amount must be a canonical decimal string');
  try {
    const os = demToOs(raw.dem);
    if (osToDem(os) !== raw.dem) throw new Error('non-canonical');
    return os.toString();
  } catch {
    throw new Error('dem meter DEM amount must be a canonical non-negative decimal string');
  }
}

function optionalFields(value: { receiptHash?: unknown; ref?: unknown }): {
  receiptHash?: string;
  ref?: string;
} {
  if (value.receiptHash !== undefined &&
    (typeof value.receiptHash !== 'string' || !SHA256_HEX_RE.test(value.receiptHash))) {
    throw new Error('dem meter receiptHash must be 64 lowercase hexadecimal characters');
  }
  if (value.ref !== undefined && typeof value.ref !== 'string') {
    throw new Error('dem meter ref must be a string');
  }
  return {
    ...(value.receiptHash === undefined ? {} : { receiptHash: value.receiptHash }),
    ...(value.ref === undefined ? {} : { ref: value.ref }),
  };
}

function rowBody(row: Omit<MeterRow, 'rowHash'>): Omit<MeterRow, 'rowHash'> {
  return row;
}

function chainedHash(body: Omit<MeterRow, 'rowHash'>): string {
  const previous = body.prevRowHash ?? '';
  return createHash('sha256').update(jcsCanonical(body)).update(previous, 'utf8').digest('hex');
}

function readMeterBytes(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return Buffer.alloc(0);
    throw error;
  }
}

function jsonLines(bytes: Buffer, allowPartialTail = false): { values: unknown[]; prefixBytes: number } {
  if (bytes.length === 0) return { values: [], prefixBytes: 0 };
  const lastNewline = bytes.lastIndexOf(0x0a);
  if (lastNewline !== bytes.length - 1 && !allowPartialTail) {
    fail('partial-tail', 'dem meter has a partial trailing line');
  }
  const prefixBytes = lastNewline + 1;
  const text = bytes.subarray(0, prefixBytes).toString('utf8');
  const lines = text.slice(0, -1).split('\n');
  return { prefixBytes, values: lines.map((line, index) => {
    if (line.length === 0) throw new Error(`dem meter line ${index + 1} is blank`);
    try { return JSON.parse(line) as unknown; } catch {
      throw new Error(`dem meter line ${index + 1} is not valid JSON`);
    }
  }) };
}

function parseRow(value: unknown, previous: string | undefined, index: number): MeterRow {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`dem meter line ${index + 1} must be a JSON object`);
  }
  const raw = value as Record<string, unknown>;
  const permitted = new Set(['agent', 'kind', 'os', 'at', 'receiptHash', 'ref', 'prevRowHash', 'rowHash']);
  if (Object.keys(raw).some((key) => !permitted.has(key))) {
    throw new Error(`dem meter line ${index + 1} contains an unknown field`);
  }
  if (raw.prevRowHash !== undefined &&
    (typeof raw.prevRowHash !== 'string' || !SHA256_HEX_RE.test(raw.prevRowHash))) {
    throw new Error(`dem meter chain is broken at line ${index + 1}`);
  }
  const body: Omit<MeterRow, 'rowHash'> = rowBody({
    agent: requireStoredAgent(raw.agent),
    kind: requireKind(raw.kind),
    os: requireOs(raw.os),
    at: requireIso(raw.at, 'row at'),
    ...optionalFields(raw),
    ...(raw.prevRowHash === undefined ? {} : { prevRowHash: raw.prevRowHash }),
  });
  if (body.prevRowHash !== previous) throw new Error(`dem meter chain is broken at line ${index + 1}`);
  if (typeof raw.rowHash !== 'string' || !SHA256_HEX_RE.test(raw.rowHash) ||
    chainedHash(body) !== raw.rowHash) {
    throw new Error(`dem meter chain is broken at line ${index + 1}`);
  }
  return { ...body, rowHash: raw.rowHash };
}

function parseRows(values: unknown[]): MeterRow[] {
  const rows: MeterRow[] = [];
  let previous: string | undefined;
  for (const [index, value] of values.entries()) {
    const row = parseRow(value, previous, index);
    rows.push(row);
    previous = row.rowHash;
  }
  return rows;
}

function parseHead(path: string): MeterHead | undefined {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    fail('head-mismatch', 'dem meter head file is invalid');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail('head-mismatch', 'dem meter head file is invalid');
  }
  const raw = value as Record<string, unknown>;
  if (!Number.isSafeInteger(raw.rowCount) || (raw.rowCount as number) < 0 ||
    !(raw.meterHead === null || (typeof raw.meterHead === 'string' && SHA256_HEX_RE.test(raw.meterHead))) ||
    Object.keys(raw).some((key) => key !== 'rowCount' && key !== 'meterHead')) {
    fail('head-mismatch', 'dem meter head file is invalid');
  }
  return { rowCount: raw.rowCount as number, meterHead: raw.meterHead as string | null };
}

function verifyHead(rows: MeterRow[], head: MeterHead | undefined): MeterHead {
  const actual = { rowCount: rows.length, meterHead: rows.at(-1)?.rowHash ?? null };
  if (rows.length > 0 && head === undefined) {
    fail('head-missing', 'dem meter head file is missing for a non-empty log');
  }
  if (head !== undefined && (head.rowCount !== actual.rowCount || head.meterHead !== actual.meterHead)) {
    fail('head-mismatch', 'dem meter head does not match the log');
  }
  return actual;
}

function sleep(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function acquireMeterLock(path: string): { release(): void } {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd: number | undefined;
  while (fd === undefined) {
    try {
      fd = openSync(lockPath, 'wx', 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (Date.now() >= deadline) fail('meter-busy', 'dem meter lock could not be acquired');
      sleep(Math.min(LOCK_RETRY_MS, Math.max(1, deadline - Date.now())));
    }
  }
  try {
    const token = Buffer.from(randomUUID(), 'utf8');
    if (writeSync(fd, token, 0, token.length, null) !== token.length) {
      fail('meter-io', 'dem meter lock write was incomplete');
    }
    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(lockPath); } catch { /* best-effort cleanup */ }
    throw error;
  }
  closeSync(fd);
  let released = false;
  return { release() {
    if (released) return;
    released = true;
    try { unlinkSync(lockPath); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  } };
}

function writeAll(fd: number, bytes: Buffer): void {
  const written = writeSync(fd, bytes, 0, bytes.length, null);
  if (written !== bytes.length) fail('meter-io', 'dem meter write was incomplete');
}

function writeHeadAtomically(path: string, head: MeterHead): void {
  const headPath = `${path}.head`;
  const tempPath = `${headPath}.${process.pid}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeAll(fd, Buffer.from(JSON.stringify(head), 'utf8'));
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tempPath, headPath);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
    throw error;
  }
}

function filtered(rows: MeterRow[], opts: { since?: string; until?: string; agent?: string }): MeterRow[] {
  const since = opts.since === undefined ? undefined : requireIso(opts.since, 'since');
  const until = opts.until === undefined ? undefined : requireIso(opts.until, 'until');
  if (since !== undefined && until !== undefined && Date.parse(since) > Date.parse(until)) {
    throw new Error('dem meter since must not be after until');
  }
  const agent = opts.agent === undefined ? undefined : requireAgent(opts.agent);
  const sinceMs = since === undefined ? undefined : Date.parse(since);
  const untilMs = until === undefined ? undefined : Date.parse(until);
  return rows.filter((row) => {
    const at = Date.parse(row.at);
    return (agent === undefined || row.agent === agent)
      && (sinceMs === undefined || at >= sinceMs)
      && (untilMs === undefined || at < untilMs);
  });
}

function addTotal(target: Record<string, { count: number; os: bigint }>, key: string, os: bigint): void {
  const current = target[key] ?? { count: 0, os: 0n };
  current.count += 1;
  current.os += os;
  target[key] = current;
}

function publicTotals(source: Record<string, { count: number; os: bigint }>): Record<string, MeterTotal> {
  return Object.fromEntries(Object.entries(source).map(([key, value]) => [key, {
    count: value.count,
    os: value.os.toString(),
    dem: osToDem(value.os),
  }]));
}

function summarizeRows(rows: MeterRow[]): MeterSummary {
  const agents: Record<string, { count: number; os: bigint }> = Object.create(null);
  const kinds: Record<string, { count: number; os: bigint }> = Object.create(null);
  let total = 0n;
  for (const row of rows) {
    const amount = BigInt(row.os);
    total += amount;
    addTotal(agents, row.agent, amount);
    addTotal(kinds, row.kind, amount);
  }
  return {
    rowCount: rows.length,
    totalOs: total.toString(),
    totalDem: osToDem(total),
    byAgent: publicTotals(agents),
    byKind: publicTotals(kinds) as Partial<Record<MeterKind, MeterTotal>>,
    lastRowHash: rows.at(-1)?.rowHash ?? null,
  };
}

/** Create a synchronous, append-only local DEM meter. */
export function createDemMeter(opts: {
  path: string;
  now?: () => string;
  agent?: string;
}): DemMeter {
  const path = resolvePayDemJournalPath(opts.path);
  const defaultAgent = opts.agent === undefined ? undefined : requireAgent(opts.agent);
  const now = opts.now ?? (() => new Date().toISOString());
  const headPath = `${path}.head`;

  function readUnlocked(): MeterRow[] {
    const rows = parseRows(jsonLines(readMeterBytes(path)).values);
    verifyHead(rows, parseHead(headPath));
    return rows;
  }

  function read(): MeterRow[] {
    const lease = acquireMeterLock(path);
    try { return readUnlocked(); } finally { lease.release(); }
  }

  function record(entry: MeterEntry): MeterRow {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error('dem meter entry must be an object');
    }
    const lease = acquireMeterLock(path);
    try {
      const rows = readUnlocked();
      const previous = rows.at(-1)?.rowHash;
      const body: Omit<MeterRow, 'rowHash'> = rowBody({
        agent: requireAgent(entry.agent ?? defaultAgent),
        kind: requireKind(entry.kind),
        os: osFromEntry(entry),
        at: requireIso(entry.at ?? now(), 'entry at'),
        ...optionalFields(entry),
        ...(previous === undefined ? {} : { prevRowHash: previous }),
      });
      const row: MeterRow = { ...body, rowHash: chainedHash(body) };
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const fd = openSync(path, 'a', 0o600);
      try {
        const line = Buffer.from(`${new TextDecoder().decode(jcsCanonical(row))}\n`, 'utf8');
        writeAll(fd, line);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      writeHeadAtomically(path, { rowCount: rows.length + 1, meterHead: row.rowHash });
      return row;
    } finally {
      lease.release();
    }
  }

  function summarize(summaryOpts: { since?: string; until?: string; agent?: string } = {}): MeterSummary {
    const rows = filtered(read(), summaryOpts);
    return summarizeRows(rows);
  }

  function invoice(invoiceOpts: Parameters<DemMeter['invoice']>[0]): InvoiceDocument {
    const issuer = requireAgent(invoiceOpts.issuer ?? invoiceOpts.from);
    const payer = requireAgent(invoiceOpts.payer ?? invoiceOpts.to);
    requireAgent(invoiceOpts.from);
    requireAgent(invoiceOpts.to);
    const since = requireIso(invoiceOpts.since, 'invoice since');
    const until = requireIso(invoiceOpts.until, 'invoice until');
    const lease = acquireMeterLock(path);
    try {
      const rows = filtered(readUnlocked(), { since, until });
      const summary = summarizeRows(rows);
      const lines = DEM_METER_KINDS.flatMap((kind) => {
        const kindRows = rows.filter((row) => row.kind === kind);
        if (kindRows.length === 0) return [];
        const os = kindRows.reduce((sum, row) => sum + BigInt(row.os), 0n);
        return [{ kind, count: kindRows.length, os: os.toString(), dem: osToDem(os) }];
      });
      const unsigned = {
        v: 'pathos-dem-invoice:0.1' as const,
        issuer,
        payer,
        period: { since, until },
        lines,
        totalOs: summary.totalOs,
        totalDem: summary.totalDem,
        meterHead: summary.lastRowHash,
        meteredReceiptHashes: [...new Set(rows.flatMap((row) =>
          row.receiptHash === undefined ? [] : [row.receiptHash]))],
        notice: 'unsigned internal accounting; not a DACS artifact, not settlement proof, not a payment request' as const,
      };
      return { ...unsigned, contentHash: jcsHashHex(unsigned) };
    } finally {
      lease.release();
    }
  }

  function repair(): { rowCount: number; meterHead: string | null } {
    const lease = acquireMeterLock(path);
    try {
      const bytes = readMeterBytes(path);
      if (bytes.length === 0 || bytes.at(-1) === 0x0a) {
        fail('meter-invalid', 'dem meter repair requires a partial trailing line');
      }
      const parsed = jsonLines(bytes, true);
      const rows = parseRows(parsed.values);
      const head = parseHead(headPath);
      if (head === undefined || head.rowCount !== rows.length ||
        head.meterHead !== (rows.at(-1)?.rowHash ?? null)) {
        fail('head-mismatch', 'dem meter intact prefix does not match the head file');
      }
      const fd = openSync(path, 'r+');
      try {
        ftruncateSync(fd, parsed.prefixBytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return head;
    } finally {
      lease.release();
    }
  }

  return { record, summarize, invoice, read, repair };
}
