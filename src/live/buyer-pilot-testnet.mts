/**
 * buyer-pilot-testnet — the buyer role of the verification-agent pilot, on the testnet, against a running verify
 * endpoint that gates with the real node payment verifier.
 *
 * Steps (the fixture's, with real settlement): discover the seller's anchored DACS-1 listing by its storage address and
 * verify it as a counterparty would; bind its presented seller to the seller the buyer configured; refuse a substituted
 * seller; meet the 402 with a d402_payment from the buyer wallet under the buyer's own cap, exactly once; receive the
 * verdict and the seller-signed delivery receipt and cold-check it under the bound seller's key; repeat the request
 * without paying again; label the purchase as a self-purchase when the payee is one of our own sellers.
 *
 * Run:  LIVE=1 DACS_ENV_PATH=<dotenv> PILOT_ENDPOINT=http://127.0.0.1:8403 PILOT_LISTING_ANCHOR=stor-… PILOT_SELLER_DID=did:demos:agent:…
 *       PILOT_BUNDLE_ANCHOR=stor-… node --import tsx src/live/buyer-pilot-testnet.mts --json
 * Env:  DEMOS_RPC (default https://demosnode.discus.sh/), BUYER_CAP_DEM (default 1), BUYER_MNEMONIC_ENV (default DEMOS_MNEMONIC),
 *       PILOT_OUR_SELLERS (comma-separated seller DIDs that are ours; default: PILOT_SELLER_DID), PILOT_CONFIRM_MS (default 240000).
 * Prints one JSON record; exits 0 when every step passed, 1 otherwise. Without LIVE=1 nothing is sent.
 */
import { request as httpRequest } from 'node:http';
import { config } from 'dotenv';
import { D402Client } from '@kynesyslabs/demosdk/d402/client';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { agentDidSignatureVerifier, assertDacs1Listing } from './producer-listing.js';
import { verifyDeliveryReceipt } from '../lib/delivery-receipt.js';
import { bindPaymentPayee, runBuyerPilot, settleThroughNode, type NodeBroadcaster } from './buyer-pilot-core.js';
import { resourceForBody } from './verify-endpoint.mjs';
import { fetchAnchored, unwrapTextAnchor } from '../demos/storage.js';

config({ path: process.env.DACS_ENV_PATH ?? '.env' });
const LIVE = process.env.LIVE === '1';
const RPC = process.env.DEMOS_RPC ?? 'https://demosnode.discus.sh/';
const ENDPOINT = process.env.PILOT_ENDPOINT ?? '';
const LISTING_ANCHOR = process.env.PILOT_LISTING_ANCHOR ?? '';
const SELLER_DID = process.env.PILOT_SELLER_DID ?? '';
const BUNDLE_ANCHOR = process.env.PILOT_BUNDLE_ANCHOR ?? '';
const BUYER_CAP_DEM = Number(process.env.BUYER_CAP_DEM ?? '1');
const OUR_SELLERS = new Set((process.env.PILOT_OUR_SELLERS ?? SELLER_DID).split(',').map((s) => s.trim()).filter(Boolean));
const CONFIRM_MS = Math.min(600_000, Math.max(30_000, Number(process.env.PILOT_CONFIRM_MS ?? '240000')));

function call(url: URL, method: string, body?: string, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: url.hostname, port: url.port, path: url.pathname, method, headers: { ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (r) => {
      const chunks: Buffer[] = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let parsed: any = null; try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; } res({ status: r.statusCode ?? 0, body: parsed }); });
    });
    req.on('error', rej);
    req.end(body);
  });
}

async function main(): Promise<number> {
  const startedAt = new Date().toISOString();
  if (!LIVE) { console.log(JSON.stringify({ harness: 'buyer-pilot-testnet:0.1', mode: 'dry', note: 'set LIVE=1 to run; nothing was sent' })); return 0; }
  if (!ENDPOINT || !LISTING_ANCHOR || !SELLER_DID || !BUNDLE_ANCHOR) { console.log(JSON.stringify({ harness: 'buyer-pilot-testnet:0.1', mode: 'testnet', rollup: 'FAIL', error: 'PILOT_ENDPOINT, PILOT_LISTING_ANCHOR, PILOT_SELLER_DID and PILOT_BUNDLE_ANCHOR are required' })); return 1; }
  const endpoint = new URL(ENDPOINT);
  const health = await call(new URL('/healthz', endpoint), 'GET').catch(() => ({ status: 0, body: null }));
  // The buyer wallet is unlocked only after the core decides to pay: the wallet handle is created lazily inside settle().
  let handle: Awaited<ReturnType<typeof import('../demos/connection.js')['connectDemos']>> | null = null;
  const wallet = async () => {
    if (handle) return handle;
    const { connectDemos } = await import('../demos/connection.js');
    const mnemonic = process.env[process.env.BUYER_MNEMONIC_ENV ?? 'DEMOS_MNEMONIC'] ?? '';
    handle = await connectDemos(mnemonic, RPC);
    return handle;
  };
  let settlements = 0;
  const result = await runBuyerPilot({ listingAnchor: LISTING_ANCHOR, sellerDid: SELLER_DID, bundleAnchor: BUNDLE_ANCHOR, buyerCapDem: BUYER_CAP_DEM, ourSellers: OUR_SELLERS, confirmMs: CONFIRM_MS }, {
    fetchAnchored: async (address) => { const f = await fetchAnchored(RPC, address); const raw = f ? (unwrapTextAnchor(f.data) ?? f.data) : null; return typeof raw === 'string' ? JSON.parse(raw) : (raw as Record<string, unknown> | null); },
    verifyListing: async (listing) => { assertDacs1Listing(listing); await verifyBundleListing(listing as never, { verifySignature: agentDidSignatureVerifier as never }); },
    call: (path, method, body, headers) => call(new URL(path, endpoint), method, body, headers),
    settle: async (requirement) => {
      if (settlements > 0) return { success: false, hash: '', message: 'a second settlement was requested; refused' };
      settlements += 1;
      const h = await wallet();
      const client = new D402Client(h.demos as never);
      const payment = bindPaymentPayee(await client.createPayment(requirement as never) as { content?: { to?: unknown } }, requirement.recipient);
      return settleThroughNode(h.demos as unknown as NodeBroadcaster, payment, CONFIRM_MS);
    },
    txBlock: async (txHash) => {
      const h = await wallet();
      const tx = await (h.demos as unknown as { getTxByHash(hash: string): Promise<{ blockNumber?: unknown }> }).getTxByHash(txHash);
      const b = typeof tx?.blockNumber === 'number' ? tx.blockNumber : (typeof tx?.blockNumber === 'string' && /^\d+$/.test(tx.blockNumber) ? Number(tx.blockNumber) : null);
      return b !== null && b > 0 ? b : null;
    },
    verifyReceipt: (receipt, sellerPubKeyHex) => verifyDeliveryReceipt(receipt, sellerPubKeyHex),
    resourceIdFor: (bodyText, amountOs) => resourceForBody(bodyText, amountOs).resourceId,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
  });
  const out = { harness: 'buyer-pilot-testnet:0.1', mode: 'testnet', settlement: 'd402_payment', startedAt, finishedAt: new Date().toISOString(), rpc: RPC,
    endpoint: { url: ENDPOINT, healthz: health.body ?? null }, listingAnchor: LISTING_ANCHOR, bundleAnchor: BUNDLE_ANCHOR, buyerCapDem: BUYER_CAP_DEM, ...result };
  console.log(JSON.stringify(out));
  return result.rollup === 'PASS' ? 0 : 1;
}

main().then((rc) => process.exit(rc)).catch((error) => { console.log(JSON.stringify({ harness: 'buyer-pilot-testnet:0.1', mode: 'testnet', rollup: 'FAIL', error: error instanceof Error ? error.message : String(error) })); process.exit(1); });
