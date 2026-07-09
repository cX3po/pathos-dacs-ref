/**
 * total-balance.mts — print the summed DEM balance across the gateway's buyer + seller wallets.
 * Used by the autofire's balance-delta safety guard (retry only when a fire spent exactly 0 DEM).
 *   npx tsx src/live/total-balance.mts   →  prints a single number (total DEM) to stdout.
 */
import { connectDemos, mnemonicFromEnv } from '../demos/connection.js';
import { config } from 'dotenv';

config({ path: '/home/eric/axiom/.env' });
let total = 0;
for (const env of ['DEMOS_MNEMONIC', 'DEMOS_SELLER_MNEMONIC']) {
  const h = await connectDemos(mnemonicFromEnv(env));
  const info = await (h.demos as unknown as { getAddressInfo: (a: string) => Promise<{ balance?: bigint }> }).getAddressInfo(h.address);
  total += Number(info?.balance ?? 0n) / 1e9;
}
process.stdout.write(String(total));
