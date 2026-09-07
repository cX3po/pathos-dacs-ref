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
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { config } from 'dotenv';
import { D402Client } from '@kynesyslabs/demosdk/d402/client';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { agentDidSignatureVerifier, assertDacs1Listing } from './producer-listing.js';
import { verifyDeliveryReceipt } from '../lib/delivery-receipt.js';
import { amountToOs } from '../adapters/demos/d402-service.js';
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

interface Step { step: string; outcome: 'pass' | 'fail'; detail: string }
const steps: Step[] = [];
const step = (name: string, ok: boolean, detail: string) => { steps.push({ step: name, outcome: ok ? 'pass' : 'fail', detail }); return ok; };
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function call(url: URL, method: string, body?: string, headers: Record<string, string> = {}): Promise<{ status: number; body: any; text: string }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: url.hostname, port: url.port, path: url.pathname, method, headers: { ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (r) => {
      const chunks: Buffer[] = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let parsed: any = null; try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; } res({ status: r.statusCode ?? 0, body: parsed, text }); });
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
  // 1. discover: the seller's anchored listing, read from the chain and verified the way a counterparty would.
  let listing: Record<string, unknown> | undefined; let sellerDid = '';
  try {
    const fetched = await fetchAnchored(RPC, LISTING_ANCHOR);
    const raw = fetched ? (unwrapTextAnchor(fetched.data) ?? fetched.data) : null;
    listing = typeof raw === 'string' ? JSON.parse(raw) : (raw as Record<string, unknown> | null) ?? undefined;
    if (!listing) throw new Error(`listing ${LISTING_ANCHOR} is absent`);
    assertDacs1Listing(listing);
    await verifyBundleListing(listing as never, { verifySignature: agentDidSignatureVerifier as never });
    sellerDid = String((listing.seller as { identity: { presentedBy: string } }).identity.presentedBy);
    step('discover', Boolean(sellerDid), `listing ${String(listing.listingId)} at ${LISTING_ANCHOR.slice(0, 16)}… by ${sellerDid.slice(0, 32)}… verified`);
  } catch (error) { step('discover', false, error instanceof Error ? error.message : String(error)); }
  // 2. bind: the listing's presented seller equals the seller the buyer configured independently.
  const sellerBound = sellerDid !== '' && sellerDid === SELLER_DID;
  step('bind', sellerBound, `verified listing seller ${sellerBound ? 'equals' : 'differs from'} the configured seller`);
  const expectedSellerPubKeyHex = SELLER_DID.startsWith('did:demos:agent:') ? SELLER_DID.slice('did:demos:agent:'.length) : '';
  const expectedPayee = expectedSellerPubKeyHex ? `0x${expectedSellerPubKeyHex}` : '';
  // 3. substitution: a listing whose presented seller changed fails verification and is not bought.
  let substitutionRefused = false;
  if (listing) {
    const substituted = { ...listing, seller: { ...(listing.seller as object), identity: { ...((listing.seller as { identity: object }).identity), presentedBy: 'did:demos:agent:' + '00'.repeat(32) } } };
    try { await verifyBundleListing(substituted as never, { verifySignature: agentDidSignatureVerifier as never }); substitutionRefused = false; }
    catch { substitutionRefused = true; }
  }
  step('substitution-refused', substitutionRefused, 'a listing whose presented seller changed fails verification and is not bought');
  // 4. the seller's endpoint: health, then the 402 for the exact request bytes.
  const health = await call(new URL('/healthz', endpoint), 'GET').catch(() => ({ status: 0, body: null, text: '' }));
  const bundleFetched = await fetchAnchored(RPC, BUNDLE_ANCHOR).catch(() => null);
  const bundleRaw = bundleFetched ? (unwrapTextAnchor(bundleFetched.data) ?? bundleFetched.data) : null;
  const bundle = typeof bundleRaw === 'string' ? JSON.parse(bundleRaw) : bundleRaw;
  if (!bundle) { step('challenge-402', false, `bundle ${BUNDLE_ANCHOR} is absent`); return finish(startedAt, health, [], null, null, 1); }
  const body = JSON.stringify({ bundle });
  const first = await call(new URL('/verify', endpoint), 'POST', body);
  const requirement = first.body ?? {};
  const expectedResource = requirement.amount !== undefined ? resourceForBody(body, String(amountToOs(String(requirement.amount)))).resourceId : '';
  const payee = String(requirement.recipient ?? '');
  step('challenge-402', first.status === 402 && payee !== '' && payee.toLowerCase() === expectedPayee && requirement.resourceId === expectedResource,
    `${first.status} recipient ${payee.slice(0, 12)}… ${payee.toLowerCase() === expectedPayee ? 'is' : 'is not'} the bound seller; resourceId ${requirement.resourceId === expectedResource ? 'bound to these bytes' : 'mismatch'}`);
  // 5. pay under the buyer's cap, exactly once, only to the bound seller's payee; wait for inclusion.
  const priceDem = requirement.amount !== undefined ? Number(amountToOs(String(requirement.amount))) / 1e9 : NaN;
  const underCap = Number.isFinite(priceDem) && priceDem <= BUYER_CAP_DEM;
  const payments: Array<{ txHash: string; to: string; amountOs: string; blockNumber: number | null; memo: string }> = [];
  let proof = '';
  if (sellerBound && underCap && payee.toLowerCase() === expectedPayee && first.status === 402) {
    const { connectDemos } = await import('../demos/connection.js');
    const mnemonic = process.env[process.env.BUYER_MNEMONIC_ENV ?? 'DEMOS_MNEMONIC'] ?? '';
    const handle = await connectDemos(mnemonic, RPC);
    const client = new D402Client(handle.demos as never);
    const payment = await client.createPayment(requirement as never);
    const settled = await client.settle(payment as never);
    if (settled.success && settled.hash) {
      proof = settled.hash;
      // The gate's verifier accepts a payment only once the node reports it in a block: poll, bounded.
      let blockNumber: number | null = typeof settled.blockNumber === 'number' && settled.blockNumber > 0 ? settled.blockNumber : null;
      const deadline = Date.now() + CONFIRM_MS;
      while (blockNumber === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 5000));
        try {
          const tx = await (handle.demos as unknown as { getTxByHash(h: string): Promise<{ blockNumber?: unknown }> }).getTxByHash(proof);
          const b = typeof tx?.blockNumber === 'number' ? tx.blockNumber : (typeof tx?.blockNumber === 'string' && /^\d+$/.test(tx.blockNumber) ? Number(tx.blockNumber) : null);
          if (b !== null && b > 0) blockNumber = b;
        } catch { /* not yet readable */ }
      }
      const memo = requirement.description ? `resourceId:${requirement.resourceId} - ${requirement.description}` : `resourceId:${requirement.resourceId}`;
      payments.push({ txHash: proof, to: payee, amountOs: String(amountToOs(String(requirement.amount))), blockNumber, memo });
      step('pay-capped', blockNumber !== null, `paid ${priceDem} DEM (cap ${BUYER_CAP_DEM}) once to the bound seller's payee; ${blockNumber !== null ? `included in block ${blockNumber}` : 'not included within the confirmation window'}`);
    } else {
      step('pay-capped', false, `settlement failed: ${String(settled.message ?? 'no hash')}`);
    }
  } else {
    step('pay-capped', false, `not paid: bound=${sellerBound} underCap=${underCap} payee-ok=${payee.toLowerCase() === expectedPayee}`);
  }
  // 6. deliver: the paid request returns the verdict and a seller-signed receipt over these exact bytes.
  let paid: { status: number; body: any; text: string } = { status: 0, body: null, text: '' };
  let receipt: unknown = null; let receiptCheck: { ok: boolean } = { ok: false };
  if (proof) {
    paid = await call(new URL('/verify', endpoint), 'POST', body, { 'X-Payment-Proof': proof });
    receipt = paid.body?.deliveryReceipt ?? null;
    receiptCheck = receipt ? verifyDeliveryReceipt(receipt, expectedSellerPubKeyHex) : { ok: false };
    const { receipt: _r, deliveryReceipt: _d, ...deliveredVerdict } = paid.body ?? {};
    const rb = (receipt as { body?: any })?.body ?? receipt ?? {};
    const inputBound = rb.inputHash === sha256(body);
    const resultBound = rb.resultHash === sha256(JSON.stringify(deliveredVerdict));
    const paymentBound = rb.payment?.txHash === proof && rb.payment?.amountOs === String(amountToOs(String(requirement.amount))) && rb.quoteRef === requirement.resourceId;
    step('deliver', paid.status === 200 && typeof paid.body?.verdict?.decision === 'string' && receiptCheck.ok === true && inputBound && resultBound && paymentBound,
      `${paid.status} verdict ${paid.body?.verdict?.decision} receipt ${receiptCheck.ok ? 'verified under the bound seller key' : 'invalid'} input=${inputBound} result=${resultBound} payment=${paymentBound}`);
    // 7. retry without paying again: the same proof is redelivered; the payment count stays one.
    const again = await call(new URL('/verify', endpoint), 'POST', body, { 'X-Payment-Proof': proof });
    step('retry-without-payment', again.status === 200 && again.body?.receipt?.redelivered === true && payments.length === 1, `redelivered=${again.body?.receipt?.redelivered} payments=${payments.length}`);
  } else {
    step('deliver', false, 'no payment proof'); step('retry-without-payment', false, 'no payment proof');
  }
  // 8. self-purchase: the payee is one of our own sellers; such a purchase is never revenue.
  const selfPurchase = payments.length === 1 && OUR_SELLERS.has(SELLER_DID) && payments[0]!.to.toLowerCase() === expectedPayee;
  step('self-purchase-labelled', selfPurchase, `payee is ${selfPurchase ? '' : 'not '}one of our configured sellers; revenue_eligible=false`);
  return finish(startedAt, health, payments, receipt, paid.body?.verdict ?? null, steps.every((s) => s.outcome === 'pass') ? 0 : 1);
}

function finish(startedAt: string, health: { status: number; body: any }, payments: unknown[], receipt: unknown, verdict: unknown, rc: number): number {
  const out = {
    harness: 'buyer-pilot-testnet:0.1', mode: 'testnet', settlement: 'd402_payment', startedAt, finishedAt: new Date().toISOString(),
    rollup: rc === 0 ? 'PASS' : 'FAIL', rpc: RPC, endpoint: { url: ENDPOINT, healthz: health.body ?? null },
    listingAnchor: LISTING_ANCHOR, bundleAnchor: BUNDLE_ANCHOR, seller: SELLER_DID, buyerCapDem: BUYER_CAP_DEM,
    payments, self_purchase: steps.find((s) => s.step === 'self-purchase-labelled')?.outcome === 'pass', revenue_eligible: false,
    deliveryReceipt: receipt, verdict, steps,
  };
  console.log(JSON.stringify(out));
  return rc;
}

main().then((rc) => process.exit(rc)).catch((error) => { console.log(JSON.stringify({ harness: 'buyer-pilot-testnet:0.1', mode: 'testnet', rollup: 'FAIL', error: error instanceof Error ? error.message : String(error), steps })); process.exit(1); });
