/**
 * buyer-pilot-core — the buyer role of the verification-agent pilot as a pure sequence over injected dependencies, so
 * the boundaries (no payment before binding, one payment at most, cap in OS, payee equality, resource binding, receipt
 * under the bound seller key, inclusion before delivery counts) are tested offline; buyer-pilot-testnet.mts wires the
 * real chain, wallet and endpoint.
 */
import { createHash } from 'node:crypto';
import { amountToOs } from '../adapters/demos/d402-service.js';

export interface PilotStep { step: string; outcome: 'pass' | 'fail'; detail: string }
export interface PilotPayment { txHash: string; to: string; amountOs: string; blockNumber: number | null; memo: string }
export interface PilotRequirement { recipient?: unknown; amount?: unknown; resourceId?: unknown; description?: unknown; reason?: unknown }
export interface PilotHttp { status: number; body: any }

export interface BuyerPilotDeps {
  /** A parsed anchored object by storage address, or null when absent; throws on transport failure. */
  fetchAnchored(address: string): Promise<Record<string, unknown> | null>;
  /** Counterparty listing verification; throws when the listing does not verify. */
  verifyListing(listing: Record<string, unknown>): Promise<void>;
  call(path: string, method: string, body?: string, headers?: Record<string, string>): Promise<PilotHttp>;
  /** One d402 payment for a requirement; the caller guarantees it is invoked at most once per run. */
  settle(requirement: { recipient: string; amount: string; resourceId: string; description?: string }): Promise<{ success: boolean; hash: string; blockNumber?: number; message?: string }>;
  /** The block a transaction is included in, or null while pending; throws on transport failure. */
  txBlock(txHash: string): Promise<number | null>;
  verifyReceipt(receipt: unknown, sellerPubKeyHex: string): { ok: boolean };
  resourceIdFor(bodyText: string, amountOs: string): string;
  sleep(ms: number): Promise<void>;
  now(): number;
}

export interface BuyerPilotConfig {
  listingAnchor: string;
  sellerDid: string;
  bundleAnchor: string;
  buyerCapDem: number;
  ourSellers: ReadonlySet<string>;
  confirmMs: number;
  pollMs?: number;
}

export interface BuyerPilotResult {
  rollup: 'PASS' | 'FAIL';
  steps: PilotStep[];
  payments: PilotPayment[];
  deliveryReceipt: unknown;
  verdict: unknown;
  self_purchase: boolean;
  revenue_eligible: false;
  seller: string;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/** The OS amount of a 402 requirement, read without coercion: a decimal-integer string is OS, a finite number is DEM. */
export function requirementAmountOs(amount: unknown): bigint | null {
  try {
    if (typeof amount === 'string') return /^[0-9]{1,30}$/.test(amount) ? amountToOs(amount) : null;
    if (typeof amount === 'number' && Number.isFinite(amount) && amount > 0) return amountToOs(amount);
  } catch { return null; }
  return null;
}

/** The buyer's cap in OS; null unless the cap is a finite positive number of DEM. */
export function capOs(buyerCapDem: unknown): bigint | null {
  if (typeof buyerCapDem !== 'number' || !Number.isFinite(buyerCapDem) || buyerCapDem <= 0) return null;
  try { return amountToOs(buyerCapDem); } catch { return null; }
}

export async function runBuyerPilot(cfg: BuyerPilotConfig, deps: BuyerPilotDeps): Promise<BuyerPilotResult> {
  const steps: PilotStep[] = [];
  const step = (name: string, ok: boolean, detail: string) => { steps.push({ step: name, outcome: ok ? 'pass' : 'fail', detail }); return ok; };
  const payments: PilotPayment[] = [];
  const done = (receipt: unknown, verdict: unknown): BuyerPilotResult => ({
    rollup: steps.every((s) => s.outcome === 'pass') && payments.length === 1 ? 'PASS' : 'FAIL', steps, payments, deliveryReceipt: receipt, verdict,
    self_purchase: steps.find((s) => s.step === 'self-purchase-labelled')?.outcome === 'pass', revenue_eligible: false, seller: cfg.sellerDid,
  });
  // 1. discover: the seller's anchored listing, verified the way a counterparty would.
  let listing: Record<string, unknown> | null = null; let sellerDid = '';
  try {
    listing = await deps.fetchAnchored(cfg.listingAnchor);
    if (!listing) throw new Error(`listing ${cfg.listingAnchor} is absent`);
    await deps.verifyListing(listing);
    sellerDid = String((listing.seller as { identity?: { presentedBy?: unknown } } | undefined)?.identity?.presentedBy ?? '');
    step('discover', sellerDid !== '', `listing ${String(listing.listingId ?? '')} at ${cfg.listingAnchor.slice(0, 16)}… by ${sellerDid.slice(0, 32)}… verified`);
  } catch (error) { step('discover', false, error instanceof Error ? error.message : String(error)); }
  // 2. bind: the listing's presented seller equals the seller the buyer configured independently.
  const sellerBound = sellerDid !== '' && sellerDid === cfg.sellerDid;
  step('bind', sellerBound, `verified listing seller ${sellerBound ? 'equals' : 'differs from'} the configured seller`);
  const expectedSellerPubKeyHex = cfg.sellerDid.startsWith('did:demos:agent:') ? cfg.sellerDid.slice('did:demos:agent:'.length).toLowerCase() : '';
  const expectedPayee = expectedSellerPubKeyHex ? `0x${expectedSellerPubKeyHex}` : '';
  // 3. substitution: a listing whose presented seller changed fails verification and is not bought.
  let substitutionRefused = false;
  if (listing) {
    const substituted = { ...listing, seller: { ...(listing.seller as object), identity: { ...((listing.seller as { identity: object }).identity), presentedBy: 'did:demos:agent:' + '00'.repeat(32) } } };
    try { await deps.verifyListing(substituted); substitutionRefused = false; } catch { substitutionRefused = true; }
  }
  step('substitution-refused', substitutionRefused, 'a listing whose presented seller changed fails verification and is not bought');
  // 4. the 402 for the exact request bytes: status, the bound seller as payee, the amount read without coercion, the resource bound to these bytes.
  const bundle = await deps.fetchAnchored(cfg.bundleAnchor).catch(() => null);
  if (!bundle) { step('challenge-402', false, `bundle ${cfg.bundleAnchor} is absent`); step('pay-capped', false, 'no challenge'); step('deliver', false, 'no payment'); step('retry-without-payment', false, 'no payment'); step('self-purchase-labelled', false, 'no payment'); return done(null, null); }
  const body = JSON.stringify({ bundle });
  const first = await deps.call('/verify', 'POST', body);
  const requirement: PilotRequirement = first.body ?? {};
  const amountOs = requirementAmountOs(requirement.amount);
  const payee = typeof requirement.recipient === 'string' ? requirement.recipient : '';
  const payeeOk = payee !== '' && expectedPayee !== '' && payee.toLowerCase() === expectedPayee;
  const resourceOk = amountOs !== null && typeof requirement.resourceId === 'string' && requirement.resourceId === deps.resourceIdFor(body, amountOs.toString());
  const challengeOk = first.status === 402 && payeeOk && resourceOk && amountOs !== null && amountOs > 0n;
  step('challenge-402', challengeOk, `${first.status} recipient ${payee.slice(0, 12)}… ${payeeOk ? 'is' : 'is not'} the bound seller; amount ${amountOs === null ? 'unreadable' : amountOs.toString() + ' OS'}; resourceId ${resourceOk ? 'bound to these bytes' : 'mismatch'}`);
  // 5. pay: at most once, only when bound, substitution refused, the challenge whole, and the amount under the buyer cap (compared in OS).
  const cap = capOs(cfg.buyerCapDem);
  const underCap = cap !== null && amountOs !== null && amountOs <= cap;
  let proof = '';
  if (sellerBound && substitutionRefused && challengeOk && underCap) {
    const settled = await deps.settle({ recipient: payee, amount: amountOs!.toString(), resourceId: String(requirement.resourceId), ...(typeof requirement.description === 'string' ? { description: requirement.description } : {}) });
    if (settled.success && typeof settled.hash === 'string' && settled.hash) {
      proof = settled.hash;
      let blockNumber: number | null = typeof settled.blockNumber === 'number' && settled.blockNumber > 0 ? settled.blockNumber : null;
      const deadline = deps.now() + cfg.confirmMs;
      while (blockNumber === null && deps.now() < deadline) {
        await deps.sleep(cfg.pollMs ?? 5000);
        try { const b = await deps.txBlock(proof); if (b !== null && b > 0) blockNumber = b; } catch { /* not yet readable */ }
      }
      const memo = typeof requirement.description === 'string' && requirement.description ? `resourceId:${String(requirement.resourceId)} - ${requirement.description}` : `resourceId:${String(requirement.resourceId)}`;
      payments.push({ txHash: proof, to: payee, amountOs: amountOs!.toString(), blockNumber, memo });
      step('pay-capped', blockNumber !== null, `paid ${amountOs!.toString()} OS (cap ${cap!.toString()} OS) once to the bound seller's payee; ${blockNumber !== null ? `included in block ${blockNumber}` : 'not included within the confirmation window'}`);
    } else {
      step('pay-capped', false, `settlement failed: ${String(settled.message ?? 'no hash')}`);
    }
  } else {
    step('pay-capped', false, `not paid: bound=${sellerBound} substitutionRefused=${substitutionRefused} challenge=${challengeOk} underCap=${underCap}`);
  }
  // 6. deliver and 7. retry: only with a proof; the receipt must verify under the bound seller key and bind these bytes, this result, this payment.
  let receipt: unknown = null; let verdict: unknown = null;
  if (proof) {
    const paid = await deps.call('/verify', 'POST', body, { 'X-Payment-Proof': proof });
    receipt = paid.body?.deliveryReceipt ?? null;
    const receiptCheck = receipt ? deps.verifyReceipt(receipt, expectedSellerPubKeyHex) : { ok: false };
    const { receipt: _r, deliveryReceipt: _d, ...deliveredVerdict } = paid.body ?? {};
    verdict = paid.body?.verdict ?? null;
    const rb = (receipt as { body?: any })?.body ?? receipt ?? {};
    const inputBound = rb.inputHash === sha256(body);
    const resultBound = rb.resultHash === sha256(JSON.stringify(deliveredVerdict));
    const paymentBound = rb.payment?.txHash === proof && rb.payment?.amountOs === amountOs!.toString() && rb.quoteRef === requirement.resourceId;
    step('deliver', paid.status === 200 && typeof paid.body?.verdict?.decision === 'string' && receiptCheck.ok === true && inputBound && resultBound && paymentBound,
      `${paid.status} verdict ${paid.body?.verdict?.decision} receipt ${receiptCheck.ok ? 'verified under the bound seller key' : 'invalid'} input=${inputBound} result=${resultBound} payment=${paymentBound}`);
    const again = await deps.call('/verify', 'POST', body, { 'X-Payment-Proof': proof });
    step('retry-without-payment', again.status === 200 && again.body?.receipt?.redelivered === true && payments.length === 1, `redelivered=${again.body?.receipt?.redelivered} payments=${payments.length}`);
  } else {
    step('deliver', false, 'no payment proof'); step('retry-without-payment', false, 'no payment proof');
  }
  // 8. self-purchase: the payee is one of our own sellers; such a purchase is never revenue.
  const selfPurchase = payments.length === 1 && cfg.ourSellers.has(cfg.sellerDid) && payments[0]!.to.toLowerCase() === expectedPayee;
  step('self-purchase-labelled', selfPurchase, `payee is ${selfPurchase ? '' : 'not '}one of our configured sellers; revenue_eligible=false`);
  return done(receipt, verdict);
}
