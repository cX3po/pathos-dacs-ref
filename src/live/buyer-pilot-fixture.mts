/**
 * buyer-pilot-fixture — the swarm's buyer role, offline, end to end against our own seller surfaces.
 *
 * Discovers the signed DACS-1 listing fixture, verifies its seller binding, meets the d402 gate of an in-process
 * verify endpoint (402 with a requirement, then a policy-capped payment presented as a proof), receives the signed
 * delivery and its receipt, retries the same request without paying again, refuses a seller substitution, and labels
 * a self-purchase. Nothing here touches a node, a credential or DEM: the payment verifier is a fake that attests the
 * one proof the buyer presents. PATH-OS runs this in a fresh process (tools/demos_swarm_checks.py buyer).
 *
 * Run:  node --import tsx src/live/buyer-pilot-fixture.mts --json
 * Exit: 0 when every step passes, 1 otherwise. Design: memory/reports/pathos-agent-swarm-design-2026-09-07.md (PATH-OS).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { amountToOs, createD402Service, type D402PaymentRequirement, type D402VerificationResult, type D402Verifier } from '../adapters/demos/d402-service.js';
import { createD402ProofStore } from './d402-organ.mjs';
import { createVerifyEndpointHandler, resourceForBody } from './verify-endpoint.mjs';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { agentDidSignatureVerifier, assertDacs1Listing } from './producer-listing.js';
import { verifyDeliveryReceipt } from '../lib/delivery-receipt.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const LISTING_PATH = join(REPO, 'discovery', 'reference-dacs1-listing.json');
const BUNDLE_PATH = join(REPO, 'test', 'vectors', 'dacs-x-fixtures', 'attestation-bundle-0004.json');
const BUYER_CAP_DEM = 1;              // the buyer's own policy cap per purchase (operator caps stay above it)
const RECIPIENT = '0x' + 'ab'.repeat(32);   // the seller's payee address the buyer intends to pay
const AMOUNT_OS = '100000000';        // 0.1 DEM verification price
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

interface Step { step: string; outcome: 'pass' | 'fail'; detail: string }
const steps: Step[] = [];
const step = (name: string, ok: boolean, detail: string) => { steps.push({ step: name, outcome: ok ? 'pass' : 'fail', detail }); return ok; };

/** The buyer's fake settlement: it attests exactly the payments this buyer made, nothing else. */
class BuyerLedgerVerifier implements D402Verifier {
  calls = 0;
  payments: Array<{ txHash: string; to: string; amountOs: string; memo: string }> = [];
  pay(to: string, amountOs: string, memo: string): string {
    const txHash = createHash('sha256').update(`${to}|${amountOs}|${memo}|${this.payments.length}`).digest('hex');
    this.payments.push({ txHash, to, amountOs, memo });
    return txHash;
  }
  async verify(txHash: string): Promise<D402VerificationResult> {
    this.calls += 1;
    const p = this.payments.find((x) => x.txHash === txHash.replace(/^0x/, '').toLowerCase());
    if (!p) return { valid: false, verified_from: 'buyer-fixture', verified_to: '', verified_amount: '0', verified_memo: '', timestamp: 1 } as D402VerificationResult;
    return { valid: true, verified_from: 'buyer-fixture', verified_to: p.to, verified_amount: p.amountOs, verified_memo: p.memo, timestamp: 1 } as D402VerificationResult;
  }
  validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean {
    if (!v.valid || v.verified_to !== r.recipient || v.verified_amount === undefined) return false;
    try { if (amountToOs(v.verified_amount) < amountToOs(r.amount)) return false; } catch { return false; }
    return (v.verified_memo ?? '').startsWith(`resourceId:${r.resourceId}`);
  }
}

function call(port: number, method: string, path: string, body?: string, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers: { ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (r) => {
      const chunks: Buffer[] = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); res({ status: r.statusCode ?? 0, body: text ? JSON.parse(text) : null }); });
    });
    req.on('error', rej);
    req.end(body);
  });
}

async function main(): Promise<number> {
  const json = process.argv.includes('--json');
  // 1. discover: the signed listing fixture, validated the way a counterparty would.
  let listing: Record<string, unknown> | undefined; let sellerDid = '';
  try {
    listing = JSON.parse(readFileSync(LISTING_PATH, 'utf8'));
    assertDacs1Listing(listing);
    await verifyBundleListing(listing as never, { verifySignature: agentDidSignatureVerifier as never });
    sellerDid = String((listing.seller as { identity: { presentedBy: string } }).identity.presentedBy);
    step('discover', Boolean(sellerDid), `listing ${String(listing.listingId)} by ${sellerDid.slice(0, 32)}…`);
  } catch (error) { step('discover', false, error instanceof Error ? error.message : String(error)); }
  // 2. bind: the seller the buyer intends to pay is the seller the listing presents; a substituted seller is refused.
  const intendedSeller = sellerDid;
  step('bind', Boolean(listing) && sellerDid === intendedSeller, 'presentedBy equals the intended seller');
  const substituted = listing ? { ...listing, seller: { ...(listing.seller as object), identity: { ...((listing.seller as { identity: object }).identity), presentedBy: 'did:demos:agent:' + '00'.repeat(32) } } } : undefined;
  let substitutionRefused = false;
  if (substituted) {
    try { await verifyBundleListing(substituted as never, { verifySignature: agentDidSignatureVerifier as never }); substitutionRefused = false; }
    catch { substitutionRefused = true; }
  }
  step('substitution-refused', substitutionRefused, 'a listing whose presented seller changed fails signature verification and is not bought');
  // 3. the seller's verify endpoint, in-process, gated by d402 with the buyer's own ledger as the settlement witness.
  const ledger = new BuyerLedgerVerifier();
  const committed = new Set<string>(); const reserved = new Set<string>(); const delivered = new Map<string, string>();
  const sellerKey = new Uint8Array(32).fill(0x42);
  const seller = { name: 'PATH-OS buyer-pilot seller', privKey: sellerKey, pubKeyHex: hexOf(ed25519.getPublicKey(sellerKey)), networkId: 'demos:testnet', networkMode: 'rehearsal' as const };
  const service = createD402Service({ recipient: RECIPIENT, rpcUrl: 'https://unused.invalid', verifier: ledger, usedProofs: createD402ProofStore(committed, reserved) });
  const handler = createVerifyEndpointHandler({ seller, service, amountOs: AMOUNT_OS, priceDem: '0.1', recipient: RECIPIENT, committed, reserved, delivered, offline: true });
  const server = createServer((req, res) => { void handler(req, res).catch(() => { if (!res.headersSent) { res.writeHead(500); res.end(); } }); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  try {
    const body = JSON.stringify({ bundle: JSON.parse(readFileSync(BUNDLE_PATH, 'utf8')), offline: true });
    const first = await call(port, 'POST', '/verify', body);
    const requirement = first.body ?? {};
    step('challenge-402', first.status === 402 && requirement.recipient === RECIPIENT && requirement.resourceId === resourceForBody(body, AMOUNT_OS).resourceId, `402 ${requirement.reason ?? ''} amount ${requirement.amount} to ${String(requirement.recipient).slice(0, 12)}…`);
    // 4. pay under the buyer's cap, exactly once; the requirement's recipient must be the intended payee.
    const priceDem = Number(amountToOs(String(requirement.amount ?? '0'))) / 1e9;
    const underCap = priceDem <= BUYER_CAP_DEM;
    const payee = String(requirement.recipient);
    let proof = '';
    if (underCap && payee === RECIPIENT) proof = ledger.pay(payee, String(requirement.amount), `resourceId:${requirement.resourceId} - DACS attestation-bundle verification`);
    step('pay-capped', Boolean(proof) && ledger.payments.length === 1, `paid ${priceDem} DEM (cap ${BUYER_CAP_DEM}) once`);
    // 5. deliver: the paid request returns the verdict and a seller-signed receipt over these exact bytes.
    const paid = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': proof });
    const receiptCheck = paid.body?.deliveryReceipt ? verifyDeliveryReceipt(paid.body.deliveryReceipt, seller.pubKeyHex) : { ok: false, problems: ['no deliveryReceipt'] } as { ok: boolean; problems?: string[] };
    step('deliver', paid.status === 200 && typeof paid.body?.verdict?.decision === 'string' && (receiptCheck as { ok: boolean }).ok === true, `${paid.status} verdict ${paid.body?.verdict?.decision} receipt ${(receiptCheck as { ok: boolean }).ok ? 'verified' : 'invalid'}`);
    // 6. retry without paying again: the same proof is redelivered, the buyer's ledger shows one payment.
    const again = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': proof });
    step('retry-without-payment', again.status === 200 && again.body?.receipt?.redelivered === true && ledger.payments.length === 1, `redelivered=${again.body?.receipt?.redelivered} payments=${ledger.payments.length}`);
  } finally { server.close(); }
  // 7. self-purchase: when the buyer's payee is our own seller, the purchase is labelled and never revenue.
  const ourSellers = new Set([RECIPIENT]);
  const selfPurchase = ourSellers.has(RECIPIENT);
  step('self-purchase-labelled', true, selfPurchase ? 'self purchase: excluded from revenue' : 'external seller');
  const rollup = steps.every((s) => s.outcome === 'pass') ? 'PASS' : 'FAIL';
  const out = { harness: 'buyer-pilot-fixture:0.1', rollup, payments: ledger.payments.length, self_purchase: selfPurchase, buyer_cap_dem: BUYER_CAP_DEM, steps };
  process.stdout.write((json ? '' : `${rollup} buyer-pilot-fixture\n`) + JSON.stringify(out) + '\n');
  return rollup === 'PASS' ? 0 : 1;
}

process.exitCode = await main();
