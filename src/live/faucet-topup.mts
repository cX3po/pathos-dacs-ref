/** Daily testnet top-up: keep upstream's buyer + every registered organ seller.
 * Ample wallets skip the faucet and succeed; any unreadable/failed wallet fails
 * the job. This is a live entry point, never an offline health-check command.
 * Usage: npx tsx src/live/faucet-topup.mts
 */
import { connectDemos, mnemonicFromEnv } from '../demos/connection.js';
import { config } from 'dotenv';
import { AMPLE_MESSAGE, jobExitCode, readBalanceDem, runFaucetTopup, requestFaucet } from './faucet-ample.js';

config({ path: process.env.DACS_ENV_PATH ?? '.env' });
const FAUCET = process.env.DEMOS_FAUCET ?? 'https://faucetbackend.demos.sh';

async function balanceDem(h: Awaited<ReturnType<typeof connectDemos>>): Promise<number | null> {
  // Raw nodeCall, validated before SDK normalization (error envelopes and missing
  // balances are unreadable, never a zero balance that authorizes a faucet call).
  const demos = h.demos as unknown as { nodeCall: (m: string, a: Record<string, unknown>) => Promise<unknown> };
  return readBalanceDem((m, a) => demos.nodeCall(m, a), h.address);
}

try {
const results = await runFaucetTopup({
  async connect(env) {
    const h = await connectDemos(mnemonicFromEnv(env));
    return {
      balance: () => balanceDem(h),
      request: () => requestFaucet(fetch, FAUCET, h.address),
    };
  },
  settle: () => new Promise((resolve) => setTimeout(resolve, 5000)),
  report(row) {
    const status = row.outcome === 'ample' ? AMPLE_MESSAGE : row.outcome;
    // No SDK error messages, response bodies, credential values or addresses.
    console.log(`[${new Date().toISOString()}] ${row.label} ${status}`);
  },
});
process.exit(jobExitCode(results));

} catch {
  console.log('faucet-topup failed');
  process.exit(1);
}
