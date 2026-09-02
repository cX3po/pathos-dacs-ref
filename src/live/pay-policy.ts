import { demToOs } from '../adapters/dacs/pay-dem.js';

export interface PayPolicy {
  network: 'testnet';
  rpcHosts: string[];
  perTransactionCapDem: string;
  dailyCapDem: string;
  killSwitchFile: string;
}

export type PayPolicyLoadResult =
  | PayPolicy
  | { verdict: 'BLOCK'; reason: string };

export type TransferAuthorization =
  | { verdict: 'PROCEED'; nowIso: string }
  | {
      verdict: 'BLOCK';
      reason: string;
      rule: 'kill-switch' | 'network' | 'per-transaction-cap' | 'daily-cap' | 'journal-unreadable' | 'journal-lock';
    };

const POLICY_KEYS = [
  'network',
  'rpcHosts',
  'perTransactionCapDem',
  'dailyCapDem',
  'killSwitchFile',
] as const;

function requireRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('pay policy must be a JSON object');
  }
  return value as Record<string, unknown>;
}

function requireCanonicalCap(record: Record<string, unknown>, key: 'perTransactionCapDem' | 'dailyCapDem'): string {
  const value = record[key];
  if (typeof value !== 'string') throw new Error(`pay policy ${key} must be a canonical DEM string`);
  try {
    demToOs(value);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`pay policy ${key} must be a canonical DEM string: ${detail}`);
  }
  return value;
}

function requireRpcHost(value: unknown, index: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`pay policy rpcHosts[${index}] must be a non-empty exact hostname`);
  }
  let parsed: URL;
  try {
    parsed = new URL(`https://${value}`);
  } catch {
    throw new Error(`pay policy rpcHosts[${index}] must be a valid hostname`);
  }
  if (parsed.hostname !== value || parsed.host !== value || parsed.pathname !== '/' || parsed.username || parsed.password) {
    throw new Error(`pay policy rpcHosts[${index}] must be a hostname without a scheme, port, or path`);
  }
  return value;
}

/** Parse an exact, testnet-only payment policy. Unknown fields are rejected. */
export function parsePayPolicy(json: unknown): PayPolicy {
  const record = requireRecord(json);
  const keys = Object.keys(record);
  const unknown = keys.filter((key) => !(POLICY_KEYS as readonly string[]).includes(key));
  const missing = POLICY_KEYS.filter((key) => !Object.hasOwn(record, key));
  if (unknown.length > 0) throw new Error(`pay policy contains unknown field: ${unknown[0]}`);
  if (missing.length > 0) throw new Error(`pay policy is missing required field: ${missing[0]}`);
  if (keys.length !== POLICY_KEYS.length) throw new Error('pay policy fields must appear exactly once');

  if (record.network !== 'testnet') throw new Error('pay policy network must be "testnet"');
  if (!Array.isArray(record.rpcHosts) || record.rpcHosts.length === 0) {
    throw new Error('pay policy rpcHosts must be a non-empty array');
  }
  const rpcHosts = record.rpcHosts.map(requireRpcHost);
  if (new Set(rpcHosts).size !== rpcHosts.length) throw new Error('pay policy rpcHosts must not contain duplicates');
  const perTransactionCapDem = requireCanonicalCap(record, 'perTransactionCapDem');
  const dailyCapDem = requireCanonicalCap(record, 'dailyCapDem');
  if (typeof record.killSwitchFile !== 'string' || record.killSwitchFile.length === 0 || record.killSwitchFile.trim() !== record.killSwitchFile) {
    throw new Error('pay policy killSwitchFile must be a non-empty exact string');
  }

  return {
    network: 'testnet',
    rpcHosts,
    perTransactionCapDem,
    dailyCapDem,
    killSwitchFile: record.killSwitchFile,
  };
}

/** Load the configured policy through an injected synchronous text reader. */
export function loadPayPolicy(
  env: Readonly<Record<string, string | undefined>>,
  readFile: (path: string) => string,
): PayPolicyLoadResult {
  const path = env.DACS_PAY_POLICY;
  if (path === undefined || path.length === 0) return { verdict: 'BLOCK', reason: 'no policy configured' };
  try {
    return parsePayPolicy(JSON.parse(readFile(path)) as unknown);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { verdict: 'BLOCK', reason: `payment policy could not be loaded: ${detail}` };
  }
}

/** Apply the policy in kill-switch, network, per-transaction, then daily-cap order. */
export function authorizeTransfer(policy: PayPolicy, input: {
  amountOs: bigint;
  rpcUrl: string;
  spentTodayOs: bigint;
  killSwitchPresent: boolean;
  nowIso: string;
}): TransferAuthorization {
  utcDateOrThrow(input.nowIso);
  if (input.killSwitchPresent) {
    return { verdict: 'BLOCK', rule: 'kill-switch', reason: `kill switch is present at ${policy.killSwitchFile}` };
  }

  let rpcHost = '';
  try {
    rpcHost = new URL(input.rpcUrl).hostname;
  } catch {
    // An invalid URL is not an authorized testnet endpoint.
  }
  if (!policy.rpcHosts.includes(rpcHost)) {
    return { verdict: 'BLOCK', rule: 'network', reason: `RPC host "${rpcHost || '(invalid URL)'}" is not allowed by the testnet policy` };
  }

  const perTransactionCapOs = demToOs(policy.perTransactionCapDem);
  if (input.amountOs > perTransactionCapOs) {
    return { verdict: 'BLOCK', rule: 'per-transaction-cap', reason: `transfer amount ${input.amountOs} OS exceeds cap ${perTransactionCapOs} OS` };
  }

  const dailyCapOs = demToOs(policy.dailyCapDem);
  if (input.spentTodayOs + input.amountOs > dailyCapOs) {
    return { verdict: 'BLOCK', rule: 'daily-cap', reason: `daily total ${input.spentTodayOs + input.amountOs} OS exceeds cap ${dailyCapOs} OS` };
  }
  return { verdict: 'PROCEED', nowIso: input.nowIso };
}

/** Return the UTC date only for an ISO timestamp with an explicit timezone. */
export function utcDateOrThrow(iso: string): string {
  if (typeof iso !== 'string' || !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/i.test(iso)) {
    throw new Error('pay policy timestamp must include a timezone');
  }
  const timestamp = new Date(iso);
  if (!Number.isFinite(timestamp.getTime())) throw new Error('pay policy timestamp must be valid');
  return timestamp.toISOString().slice(0, 10);
}

/**
 * Sum same-UTC-date broadcast outcomes. Each entry reads only `timestamp` (an ISO timestamp),
 * `amountOs` (a canonical non-negative integer string), and `outcome` (a non-empty string).
 * The pre-broadcast outcomes `aborted-before-broadcast` and `pre-broadcast-abort` are excluded;
 * every other recorded outcome represents a broadcast state and is counted. Entries without an outcome are preparation records and are
 * ignored. Malformed outcome records throw so callers can fail closed instead of undercounting.
 */
export function spentTodayFromJournal(entries: readonly unknown[], nowIso: string): bigint {
  const utcDate = utcDateOrThrow(nowIso);
  let total = 0n;

  for (const entry of entries) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    if (!Object.hasOwn(record, 'outcome')) continue;
    if (typeof record.outcome !== 'string' || record.outcome.length === 0) {
      throw new Error('pay policy journal outcome must be a non-empty string');
    }
    if (record.outcome === 'aborted-before-broadcast' || record.outcome === 'pre-broadcast-abort') continue;
    if (typeof record.timestamp !== 'string') throw new Error('pay policy journal timestamp must be an ISO string');
    if (utcDateOrThrow(record.timestamp) !== utcDate) continue;
    if (typeof record.amountOs !== 'string' || !/^(?:0|[1-9]\d*)$/.test(record.amountOs)) {
      throw new Error('pay policy journal amountOs must be a canonical non-negative integer string');
    }
    total += BigInt(record.amountOs);
  }
  return total;
}
