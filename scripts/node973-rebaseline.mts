// node#973 re-baseline — characterize storage-program tx inclusion on the STATUS RPC, not the /tx route.
// Per our commitment to @norgejbb-byte: submit a storage-program tx, then report getTransactionStatus per
// hash (distinguishing accepted-for-propagation / included / timeout / nonterminal), and record the /tx route
// verdict SEPARATELY per host — never collapsing the two. Testnet only, no real funds.
import { connectDemos } from '../src/demos/connection.js';
import { anchor } from '../src/demos/storage.js';
import { config } from 'dotenv';
config({ path: process.env.DACS_ENV_PATH ?? '.env' });

const HOSTS = ['https://demosnode.discus.sh/', 'https://node2.demos.sh/'];
const out: Record<string, unknown> = { ts: new Date().toISOString(), hosts: {} };

async function httpGet(base: string, path: string): Promise<{ status: number; ctype: string; body: string }> {
  try {
    const r = await fetch(new URL(path, base).toString(), { signal: AbortSignal.timeout(15000) });
    const body = (await r.text()).slice(0, 200);
    return { status: r.status, ctype: r.headers.get('content-type') ?? '', body };
  } catch (e) { return { status: -1, ctype: '', body: (e as Error).message.slice(0, 120) }; }
}

for (const host of HOSTS) {
  const rec: Record<string, unknown> = {};
  // /version — establish which server layer is live (bunServer.ts vs server_rpc.ts, per #734)
  rec.version = await httpGet(host, '/version');

  let txHash = '';
  try {
    const handle = await connectDemos(process.env.DEMOS_MNEMONIC as string, host);
    rec.address = handle.address;
    // minimal storage-program write — captures txHash even if broadcastAndWait times out (the bug)
    try {
      const res = await anchor(handle, `node973-probe-${Date.now()}`, { probe: 'node973-rebaseline', host });
      txHash = (res as { txHash?: string }).txHash ?? '';
      rec.write = { outcome: 'anchor-returned', storageAddress: (res as { storageAddress?: string }).storageAddress, txHash };
    } catch (e) {
      txHash = (e as { txHash?: string }).txHash ?? '';
      rec.write = { outcome: 'anchor-threw', error: (e as Error).message.slice(0, 160), txHash };
    }

    // Poll getTransactionStatus for the SAME hash — the reliable inclusion oracle
    if (txHash) {
      const states: Array<{ t: number; state: unknown }> = [];
      const demos = (handle as unknown as { demos: { call: (m: string, e: string, p: unknown) => Promise<unknown> } }).demos;
      for (let i = 0; i < 8; i++) {
        let s: unknown;
        try { s = await demos.call('nodeCall', 'getTransactionStatus', { hash: txHash }); }
        catch (e) { s = { error: (e as Error).message.slice(0, 100) }; }
        const state = (s && typeof s === 'object' && 'state' in s) ? (s as { state: unknown }).state : s;
        states.push({ t: i * 10, state });
        if (state === 'included' || state === 'failed') break;
        await new Promise((r) => setTimeout(r, 10000));
      }
      rec.getTransactionStatus = states;
      // /tx/<hash> route verdict — recorded SEPARATELY (never collapsed into inclusion)
      rec.txRoute = await httpGet(host, `/tx/${txHash}`);
    }
  } catch (e) { rec.connectError = (e as Error).message.slice(0, 160); }

  (out.hosts as Record<string, unknown>)[host] = rec;
}

const { writeFileSync } = await import('node:fs');
writeFileSync('/tmp/node973_rebaseline.json', JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
console.log('\n[node973] DONE');
