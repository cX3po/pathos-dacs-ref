/**
 * faucet-topup.mts — request devnet DEM from the faucet for the gateway's buyer + seller wallets.
 *
 * Zero-token, fully deterministic (HTTP POST + SDK balance read — no LLM). Devnet DEM is
 * re-faucetable / low-value, so this is safe to run unattended on a daily cron to keep a working
 * buffer for the DACS build/broadcast work. The faucet enforces its OWN per-address rate limit;
 * a rate-limited / already-funded response is logged as a non-fatal skip, never a crash — so a
 * daily run that's over the faucet's cap just no-ops.
 *
 *   npx tsx src/live/faucet-topup.mts        # fund buyer + seller, print before/after balances
 */
import { connectDemos, mnemonicFromEnv } from '../demos/connection.js';
import { config } from 'dotenv';

config({ path: '/home/eric/axiom/.env' });

const FAUCET = process.env.DEMOS_FAUCET ?? 'https://faucetbackend.demos.sh';
const ts = () => new Date().toISOString();

async function balanceDem(h: Awaited<ReturnType<typeof connectDemos>>): Promise<number> {
  const info = await (h.demos as unknown as { getAddressInfo: (a: string) => Promise<{ balance?: bigint }> })
    .getAddressInfo(h.address);
  return Number(info?.balance ?? 0n) / 1e9;
}

let ok = 0;
for (const env of ['DEMOS_MNEMONIC', 'DEMOS_SELLER_MNEMONIC']) {
  const label = env === 'DEMOS_MNEMONIC' ? 'buyer' : 'seller';
  try {
    const h = await connectDemos(mnemonicFromEnv(env));
    const before = await balanceDem(h);
    let status: string;
    let amount: unknown = null;
    try {
      const res = await fetch(`${FAUCET}/api/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: h.address }),
      });
      const json = await res.json().catch(() => ({} as Record<string, unknown>));
      if (!res.ok || (json as { error?: unknown }).error) {
        status = `skip (${res.status}: ${JSON.stringify((json as { error?: unknown }).error ?? json).slice(0, 120)})`;
      } else {
        amount = (json as { body?: { amount?: unknown } }).body?.amount ?? 'unknown';
        status = 'requested';
        ok += 1;
      }
    } catch (e) {
      status = `faucet-error (${(e as Error).message.slice(0, 100)})`;
    }
    // brief settle, then re-read so the log shows whether it actually landed
    await new Promise((r) => setTimeout(r, 5000));
    const after = await balanceDem(h);
    console.log(`[${ts()}] ${label} ${h.address.slice(0, 10)}… ${status} | amount=${amount} | ${before} -> ${after} DEM`);
  } catch (e) {
    console.log(`[${ts()}] ${label} FAILED: ${(e as Error).message.slice(0, 140)}`);
  }
}
process.exit(ok > 0 ? 0 : 1);
