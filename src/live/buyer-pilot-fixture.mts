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
import { agentDidForPubkey, agentDidSignatureVerifier, assertDacs1Listing, keypairSigner } from './producer-listing.js';
import { dacs1Listing, presentSellerIdentity, signDacs1Listing } from './listing-wire.js';
import { listingLogicalAddress } from '../dacs1/addressing.js';
import { verifyDeliveryReceipt } from '../lib/delivery-receipt.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const BUNDLE_PATH = join(REPO, 'test', 'vectors', 'dacs-x-fixtures', 'attestation-bundle-0004.json');
const BUYER_CAP_DEM = 1;              // the buyer's own policy cap per purchase (operator caps stay above it)
// Fixture payee mapping: the seller identity below is paid at this address. A DACS-1 listing names the seller's DID, not a
// payee address; the address comes from the rail's payment requirement, and the buyer accepts it only for a bound seller.
const RECIPIENT = '0x' + 'ab'.repeat(32);
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
  // 0. the seller this fixture sells as: one ed25519 key signs the listing and the delivery receipts.
  const sellerKey = new Uint8Array(32).fill(0x42);
  const sellerPub = ed25519.getPublicKey(sellerKey);
  const seller = { name: 'PATH-OS buyer-pilot seller', privKey: sellerKey, pubKeyHex: hexOf(sellerPub), networkId: 'demos:testnet', networkMode: 'rehearsal' as const };
  const sellerSigner = keypairSigner({ privKey: sellerKey, pubKey: sellerPub });
  // 1. discover: a signed DACS-1 verification listing by that seller, validated the way a counterparty would.
  let listing: Record<string, unknown> | undefined; let sellerDid = '';
  try {
    const identity = await presentSellerIdentity(sellerSigner, Date.now());
    const listingId = 'buyer-pilot-verify-bundle';
    const unsigned = { ...dacs1Listing({
      listingId, listingVersion: 1, seller: { identity, displayName: seller.name },
      offering: { title: 'verify-bundle: DACS attestation-bundle verification', description: 'cold verification of an attestation bundle, delivered with a signed receipt', category: 'verification', tags: ['verify-bundle'], deliverable: { kind: 'storage-program' } },
      pricing: { kind: 'fixed', price: { amount: '0.1', currency: 'DEM' } }, acceptedRails: [{ railId: 'pay-dem' }],
      pipeline: [{ kind: 'vet-credentials' }, { kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' }, { kind: 'pay-dem', parameters: { rail: 'pay-dem' } }, { kind: 'deliver-storage-program' }],
      terms: { deadlineSecAfterCommit: 3600 }, validity: { notBefore: Date.now() - 60_000, notAfter: Date.now() + 7_200_000 },
    }), logical_address: listingLogicalAddress(String(identity.presentedBy), listingId, 1) };
    const signed = await signDacs1Listing(unsigned, sellerSigner);
    listing = signed.listing;
    assertDacs1Listing(listing);
    await verifyBundleListing(listing as never, { verifySignature: agentDidSignatureVerifier as never });
    sellerDid = String((listing.seller as { identity: { presentedBy: string } }).identity.presentedBy);
    step('discover', Boolean(sellerDid), `listing ${listingId} by ${sellerDid.slice(0, 32)}… verified`);
  } catch (error) { step('discover', false, error instanceof Error ? error.message : String(error)); }
  // 2. bind: the verified listing's seller must equal the seller the buyer configured independently (the delivery signer).
  const intendedSeller = agentDidForPubkey(sellerPub);
  const sellerBound = sellerDid !== '' && sellerDid === intendedSeller;
  step('bind', sellerBound, 'verified listing seller equals the configured fixture delivery signer');
  const expectedSellerPubKeyHex = sellerDid.slice('did:demos:agent:'.length);
  const substituted = listing ? { ...listing, seller: { ...(listing.seller as object), identity: { ...((listing.seller as { identity: object }).identity), presentedBy: 'did:demos:agent:' + '00'.repeat(32) } } } : undefined;
  let substitutionRefused = false;
  if (substituted) {
    try { await verifyBundleListing(substituted as never, { verifySignature: agentDidSignatureVerifier as never }); substitutionRefused = false; }
    catch { substitutionRefused = true; }
  }
  step('substitution-refused', substitutionRefused, 'a listing whose presented seller changed fails verification and is not bought');
  // 3. the seller's verify endpoint, in-process, gated by d402 with the buyer's own ledger as the settlement witness.
  const ledger = new BuyerLedgerVerifier();
  const committed = new Set<string>(); const reserved = new Set<string>(); const delivered = new Map<string, string>();
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
    if (sellerBound && underCap && payee === RECIPIENT) proof = ledger.pay(payee, String(requirement.amount), `resourceId:${requirement.resourceId} - DACS attestation-bundle verification`);
    step('pay-capped', Boolean(proof) && ledger.payments.length === 1, `paid ${priceDem} DEM (cap ${BUYER_CAP_DEM}) once to the bound seller's payee`);
    // 5. deliver: the paid request returns the verdict and a seller-signed receipt over these exact bytes.
    const paid = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': proof });
    const receipt = paid.body?.deliveryReceipt;
    const receiptCheck = receipt ? verifyDeliveryReceipt(receipt, expectedSellerPubKeyHex) : { ok: false } as { ok: boolean };
    // the receipt must be about THIS transaction: these request bytes, the delivered verdict bytes, this payment.
    const { receipt: _r, deliveryReceipt: _d, ...deliveredVerdict } = paid.body ?? {};
    const rb = receipt?.body ?? receipt ?? {};
    const inputBound = rb.inputHash === createHash('sha256').update(body).digest('hex');
    const resultBound = rb.resultHash === createHash('sha256').update(JSON.stringify(deliveredVerdict)).digest('hex');
    const paymentBound = rb.payment?.txHash === proof && rb.payment?.amountOs === String(requirement.amount) && rb.quoteRef === requirement.resourceId;
    step('deliver', paid.status === 200 && typeof paid.body?.verdict?.decision === 'string' && receiptCheck.ok === true && inputBound && resultBound && paymentBound,
      `${paid.status} verdict ${paid.body?.verdict?.decision} receipt ${receiptCheck.ok ? 'verified' : 'invalid'} input=${inputBound} result=${resultBound} payment=${paymentBound}`);
    // 6. retry without paying again: the same proof is redelivered, the buyer's ledger shows one payment.
    const again = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': proof });
    step('retry-without-payment', again.status === 200 && again.body?.receipt?.redelivered === true && ledger.payments.length === 1, `redelivered=${again.body?.receipt?.redelivered} payments=${ledger.payments.length}`);
  } finally { server.close(); }
  // 7. self-purchase: the observed payment's payee is one of our own configured sellers; such a purchase is never revenue.
  const ourSellers = new Set([RECIPIENT]);
  const selfPurchase = ledger.payments.length === 1 && ourSellers.has(ledger.payments[0]!.to);
  step('self-purchase-labelled', selfPurchase, 'observed fixture payment targets our configured seller; revenue_eligible=false');
  const rollup = steps.every((s) => s.outcome === 'pass') ? 'PASS' : 'FAIL';
  const out = { harness: 'buyer-pilot-fixture:0.1', mode: 'offline-fixture', settlement: 'fake-ledger', rollup, payments: ledger.payments.length, self_purchase: selfPurchase, revenue_eligible: !selfPurchase, buyer_cap_dem: BUYER_CAP_DEM, seller: intendedSeller, steps };
  process.stdout.write((json ? '' : `${rollup} buyer-pilot-fixture\n`) + JSON.stringify(out) + '\n');
  return rollup === 'PASS' ? 0 : 1;
}

process.exitCode = await main();
