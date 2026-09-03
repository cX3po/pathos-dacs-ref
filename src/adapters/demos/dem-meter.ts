/**
 * Local DEM-denominated internal metering for PATH-OS.
 *
 * This is an internal accounting document surface. It is not a DACS artifact and an
 * invoice produced here is not a payment request. The meter performs no on-chain writes.
 */

import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

import { demToOs, osToDem } from '../dacs/pay-dem.js';
import { jcsCanonical, jcsHashHex } from '../../jcs.js';
import {
  acquirePayDemJournalLock,
  resolvePayDemJournalPath,
} from '../../live/pay-dem-journal.js';

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
  receiptRefs: string[];
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
}

const OS_RE = /^(?:0|[1-9]\d*)$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const SEAT_RE = /^[a-z0-9._-]+$/;
const CCI_RE = /^cci:(?:0x)?[0-9a-fA-F]{64}$/;

function requireAgent(value: unknown): string {
  if (typeof value !== 'string' || (!SEAT_RE.test(value) && !CCI_RE.test(value))) {
    throw new Error('dem meter agent must be a CCI claim or a lowercase seat name');
  }
  return value;
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

function readJsonl(path: string): unknown[] {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  return text.split('\n').filter((line) => line.length > 0).map((line, index) => {
    try { return JSON.parse(line) as unknown; } catch {
      throw new Error(`dem meter line ${index + 1} is not valid JSON`);
    }
  });
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
    agent: requireAgent(raw.agent),
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

/** Create a synchronous, append-only local DEM meter. */
export function createDemMeter(opts: {
  path: string;
  now?: () => string;
  agent?: string;
}): DemMeter {
  const path = resolvePayDemJournalPath(opts.path);
  const defaultAgent = opts.agent === undefined ? undefined : requireAgent(opts.agent);
  const now = opts.now ?? (() => new Date().toISOString());

  function read(): MeterRow[] {
    const values = readJsonl(path);
    const rows: MeterRow[] = [];
    let previous: string | undefined;
    for (const [index, value] of values.entries()) {
      const row = parseRow(value, previous, index);
      rows.push(row);
      previous = row.rowHash;
    }
    return rows;
  }

  function record(entry: MeterEntry): MeterRow {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error('dem meter entry must be an object');
    }
    const lease = acquirePayDemJournalLock(path);
    try {
      const rows = read();
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
        writeSync(fd, `${new TextDecoder().decode(jcsCanonical(row))}\n`, null, 'utf8');
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return row;
    } finally {
      lease.release();
    }
  }

  function summarize(summaryOpts: { since?: string; until?: string; agent?: string } = {}): MeterSummary {
    const rows = filtered(read(), summaryOpts);
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

  function invoice(invoiceOpts: Parameters<DemMeter['invoice']>[0]): InvoiceDocument {
    const issuer = requireAgent(invoiceOpts.issuer ?? invoiceOpts.from);
    const payer = requireAgent(invoiceOpts.payer ?? invoiceOpts.to);
    requireAgent(invoiceOpts.from);
    requireAgent(invoiceOpts.to);
    const since = requireIso(invoiceOpts.since, 'invoice since');
    const until = requireIso(invoiceOpts.until, 'invoice until');
    const rows = filtered(read(), { since, until });
    const summary = summarize({ since, until });
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
      receiptRefs: [...new Set(rows.flatMap((row) => row.receiptHash === undefined ? [] : [row.receiptHash]))],
    };
    return { ...unsigned, contentHash: jcsHashHex(unsigned) };
  }

  return { record, summarize, invoice, read };
}
