import { BUYER_MNEMONIC_ENV, sellerMnemonicEnvs } from './organ-profiles.js';

/**
 * When a testnet wallet already holds enough DEM, the daily faucet cron
 * skips the request. The public faucet has been returning HTTP 500 since
 * 2026-09-27. Wallets above this line are not a failed job.
 *
 * 1000 DEM is ten times the pay-policy daily cap (config/demos_pay_policy.json
 * daily_cap_dem = 100). Override with DEMOS_FAUCET_MIN_DEM.
 */
export const FAUCET_AMPLE_DEM = 1000;
export const AMPLE_MESSAGE = "balance ample, faucet skipped";

export type WalletClass = "ample" | "needs-faucet" | "unreadable";
export type WalletResult = "ample" | "requested" | "faucet-failed" | "unreadable";

export function ampleThreshold(raw: string | undefined = process.env.DEMOS_FAUCET_MIN_DEM): number {
  if (raw === undefined || raw === "") return FAUCET_AMPLE_DEM;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return FAUCET_AMPLE_DEM;
  return parsed;
}

/** At or above the threshold the faucet is not called. */
export function classifyBalance(balance: number | null, threshold: number): WalletClass {
  if (balance === null || !Number.isFinite(balance)) return "unreadable";
  if (balance >= threshold) return "ample";
  return "needs-faucet";
}

/** Non-zero only when a wallet is unreadable, or low and the faucet failed. */
export function jobExitCode(results: WalletResult[]): number {
  return results.length === 0 || results.some((row) => row === "faucet-failed" || row === "unreadable") ? 1 : 0;
}


export interface FaucetWallet {
  balance(): Promise<number | null>;
  request(): Promise<boolean>;
}
export interface TopupReport {
  label: string;
  outcome: WalletResult;
  before?: number;
  after?: number;
}
export interface TopupDependencies {
  connect(env: string): Promise<FaucetWallet>;
  settle(): Promise<void>;
  report(row: TopupReport): void;
}

/** The live entry point and offline tests use the same registered-wallet loop. */
export async function runFaucetTopup(
  deps: TopupDependencies, threshold = ampleThreshold(), timeoutMs = 30_000,
): Promise<WalletResult[]> {
  const results: WalletResult[] = [];
  for (const env of [BUYER_MNEMONIC_ENV, ...sellerMnemonicEnvs()]) {
    const label = env === BUYER_MNEMONIC_ENV ? 'buyer' : `seller (${env})`;
    let row: TopupReport = { label, outcome: 'unreadable' };
    try {
      const wallet = await withDeadline(() => deps.connect(env), timeoutMs);
      const before = await withDeadline(() => wallet.balance(), timeoutMs);
      const kind = classifyBalance(before, threshold);
      if (kind === 'ample') {
        row = { label, outcome: 'ample', before: before! };
      } else if (kind === 'needs-faucet') {
        let requested = false;
        try { requested = await withDeadline(() => wallet.request(), timeoutMs); } catch { /* failed request remains failure */ }
        await withDeadline(() => deps.settle(), timeoutMs);
        const after = await withDeadline(() => wallet.balance(), timeoutMs);
        row = classifyBalance(after, threshold) === 'unreadable'
          ? { label, outcome: 'unreadable', before: before! }
          : { label, outcome: requested ? 'requested' : 'faucet-failed', before: before!, after: after! };
      }
    } catch { /* Connection/read/settle faults are conservatively unreadable; continue other wallets. */ }
    results.push(row.outcome);
    deps.report(row);
  }
  return results;
}

/** Bound SDK/HTTP stages without leaving an active timeout after completion. */
async function withDeadline<T>(action: () => Promise<T>, ms: number, abort?: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(action),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => { abort?.(); reject(new Error('faucet stage timed out')); }, ms);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

/** No response body or error text escapes this HTTP boundary. */
export async function requestFaucet(
  fetchImpl: typeof fetch, url: string, address: string, timeoutMs = 30_000,
): Promise<boolean> {
  const controller = new AbortController();
  try {
    return await withDeadline(async () => {
      const res = await fetchImpl(`${url}/api/request`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address }), signal: controller.signal,
      });
      const json = await res.json() as { error?: unknown } | null;
      return res.ok && json !== null && typeof json === 'object' && !Array.isArray(json) && !json.error;
    }, timeoutMs, () => controller.abort());
  } catch { return false; }
}

/**
 * Raw getAddressInfo payload → DEM balance, or null when unreadable. Validates the
 * node's response BEFORE SDK normalization: the SDK's `call` turns transport errors
 * into `{result: 500, response: <error>}` and `getAddressInfo` coalesces a missing
 * balance to 0n, which would otherwise authorize a faucet request.
 */
export function balanceFromAddressInfo(raw: unknown): number | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const info = raw as Record<string, unknown>;
  if ('result' in info && 'response' in info) return null; // SDK error envelope
  const b = info.balance;
  let units: bigint;
  if (typeof b === 'bigint') units = b;
  else if (typeof b === 'number' && Number.isSafeInteger(b)) units = BigInt(b);
  else if (typeof b === 'string' && /^[0-9]{1,40}$/.test(b)) units = BigInt(b);
  else return null; // missing, null, fractional or malformed balance
  if (units < 0n) return null;
  return Number(units) / 1e9;
}

/** Read the balance through the raw nodeCall so error envelopes stay unreadable. */
export async function readBalanceDem(
  nodeCall: (message: string, args: Record<string, unknown>) => Promise<unknown>, address: string,
): Promise<number | null> {
  try { return balanceFromAddressInfo(await nodeCall('getAddressInfo', { address })); }
  catch { return null; }
}
