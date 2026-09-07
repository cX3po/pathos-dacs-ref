import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bindPaymentPayee, capOs, requirementAmountOs, runBuyerPilot, settleThroughNode, type BuyerPilotDeps } from '../../src/live/buyer-pilot-core.js';

const SELLER_HEX = '11'.repeat(32);
const SELLER_DID = `did:demos:agent:${SELLER_HEX}`;
const PAYEE = `0x${SELLER_HEX}`;
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const BUNDLE = { jobId: 'j' };
const BODY = JSON.stringify({ bundle: BUNDLE });
const resourceIdFor = (b: string, amountOs: string) => sha256(`${b}|${amountOs}`);
/** The resourceId the endpoint would bind for this body at a normalized OS amount. */
const ridFor = (amountOs: string) => resourceIdFor(BODY, amountOs);
type Tamper = 'inputHash' | 'resultHash' | 'payment';

function harness(over: Partial<BuyerPilotDeps> & { requirement?: Record<string, unknown>; receiptSeller?: string; included?: boolean; settleOk?: boolean; tamper?: Tamper } = {}) {
  const listing = { listingId: 'l', seller: { identity: { presentedBy: SELLER_DID } } };
  const bundle = BUNDLE;
  const body = BODY;
  const state = { settlements: 0, calls: [] as string[], now: 0 };
  const requirement = over.requirement ?? { recipient: PAYEE, amount: '100000000', resourceId: resourceIdFor(body, '100000000'), description: 'DACS attestation-bundle verification' };
  const receiptFor = (proof: string, verdict: unknown) => {
    const rb = { inputHash: sha256(body), resultHash: sha256(JSON.stringify({ verdict })), payment: { txHash: proof, amountOs: String(requirement.amount).length > 9 ? String(requirement.amount) : '100000000' }, quoteRef: requirement.resourceId, seller: { pubKeyHex: over.receiptSeller ?? SELLER_HEX } };
    if (over.tamper === 'inputHash') rb.inputHash = sha256(body + ' ');
    if (over.tamper === 'resultHash') rb.resultHash = sha256(JSON.stringify({ verdict: { decision: 'fail' } }));
    if (over.tamper === 'payment') rb.payment = { txHash: 'cd'.repeat(32), amountOs: rb.payment.amountOs };
    return { body: rb };
  };
  const deps: BuyerPilotDeps = {
    fetchAnchored: async (address) => (address === 'stor-listing' ? listing : address === 'stor-bundle' ? bundle : null),
    verifyListing: async (l) => { if ((l.seller as any).identity.presentedBy !== SELLER_DID) throw new Error('unknown seller'); },
    call: async (path, _method, _body, headers) => {
      state.calls.push(path + (headers?.['X-Payment-Proof'] ? ':paid' : ''));
      if (!headers?.['X-Payment-Proof']) return { status: 402, body: requirement };
      const verdict = { decision: 'pass' };
      const first = state.calls.filter((c) => c.endsWith(':paid')).length === 1;
      return { status: 200, body: { verdict, deliveryReceipt: receiptFor(headers['X-Payment-Proof'], verdict), receipt: { redelivered: !first } } };
    },
    settle: async () => { state.settlements += 1; return over.settleOk === false ? { success: false, hash: '', message: 'refused' } : { success: true, hash: 'ab'.repeat(32), blockNumber: over.included === false ? undefined : 250000 }; },
    txBlock: async () => null,
    verifyReceipt: (receipt, sellerPubKeyHex) => ({ ok: ((receipt as any).body?.seller?.pubKeyHex ?? '') === sellerPubKeyHex }),
    resourceIdFor,
    sleep: async (ms) => { state.now += ms; },
    now: () => state.now,
    ...Object.fromEntries(Object.entries(over).filter(([k]) => !['requirement', 'receiptSeller', 'included', 'settleOk', 'tamper'].includes(k))),
  } as BuyerPilotDeps;
  const cfg = { listingAnchor: 'stor-listing', sellerDid: SELLER_DID, bundleAnchor: 'stor-bundle', buyerCapDem: 1, ourSellers: new Set([SELLER_DID]), confirmMs: 30_000, pollMs: 5_000 };
  return { deps, cfg, state };
}

test('buyer pilot core: the happy path settles exactly once across delivery and retry and passes', async () => {
  const { deps, cfg, state } = harness();
  const r = await runBuyerPilot(cfg, deps);
  assert.equal(r.rollup, 'PASS', JSON.stringify(r.steps));
  assert.equal(state.settlements, 1); assert.equal(r.payments.length, 1); assert.equal(r.payments[0]!.blockNumber, 250000);
  assert.equal(r.self_purchase, true); assert.equal(r.revenue_eligible, false);
});

test('buyer pilot core: no settlement on resource mismatch, unbound seller, wrong payee, over-cap amounts, invalid caps', async () => {
  for (const [label, over, cfgOver] of [
    ['resource mismatch', { requirement: { recipient: PAYEE, amount: '100000000', resourceId: 'other' } }, {}],
    ['unbound seller', {}, { sellerDid: 'did:demos:agent:' + '22'.repeat(32) }],
    ['wrong payee', { requirement: { recipient: '0x' + '33'.repeat(32), amount: '100000000', resourceId: 'x' } }, {}],
    // over-cap cases carry the correct resourceId for the body at the normalized OS amount: only the cap refuses them
    ['over cap numeric (2 DEM)', { requirement: { recipient: PAYEE, amount: 2, resourceId: ridFor('2000000000') } }, {}],
    ['over cap string (2 DEM in OS)', { requirement: { recipient: PAYEE, amount: '2000000000', resourceId: ridFor('2000000000') } }, {}],
    ['cap 0', {}, { buyerCapDem: 0 }],
    ['cap NaN', {}, { buyerCapDem: Number.NaN }],
  ] as const) {
    const { deps, cfg, state } = harness(over as any);
    const r = await runBuyerPilot({ ...cfg, ...(cfgOver as object) }, deps);
    assert.equal(state.settlements, 0, label); assert.equal(r.rollup, 'FAIL', label); assert.equal(r.payments.length, 0, label);
  }
});

test('buyer pilot core: string amounts are OS and numbers are DEM, never coerced across', () => {
  assert.equal(requirementAmountOs('100000000'), 100000000n);
  assert.equal(requirementAmountOs(2), 2000000000n);
  assert.equal(requirementAmountOs('2'), 2n);
  assert.equal(requirementAmountOs('1.5'), null); assert.equal(requirementAmountOs(-1), null); assert.equal(requirementAmountOs(Number.NaN), null); assert.equal(requirementAmountOs({ amount: 1 }), null);
  assert.equal(capOs(1), 1000000000n); assert.equal(capOs(0), null); assert.equal(capOs(Number.POSITIVE_INFINITY), null); assert.equal(capOs('1'), null);
});

test('buyer pilot core: an inclusion timeout keeps the payment but fails the run; a foreign or tampered receipt fails; a failed settlement pays nothing', async () => {
  const timeout = harness({ included: false });
  const r1 = await runBuyerPilot(timeout.cfg, timeout.deps);
  assert.equal(r1.rollup, 'FAIL'); assert.equal(timeout.state.settlements, 1); assert.equal(r1.payments[0]!.blockNumber, null);
  assert.equal(r1.steps.find((s) => s.step === 'pay-capped')!.outcome, 'fail');
  const foreign = harness({ receiptSeller: '44'.repeat(32) });
  const r2 = await runBuyerPilot(foreign.cfg, foreign.deps);
  assert.equal(r2.rollup, 'FAIL'); assert.equal(r2.steps.find((s) => s.step === 'deliver')!.outcome, 'fail'); assert.equal(foreign.state.settlements, 1);
  // a tampered receipt whose signature check still returns true fails delivery on the binding it broke; the one payment stays on record
  for (const tamper of ['inputHash', 'resultHash', 'payment'] as const) {
    const tampered = harness({ tamper, verifyReceipt: () => ({ ok: true }) });
    const rt = await runBuyerPilot(tampered.cfg, tampered.deps);
    assert.equal(rt.rollup, 'FAIL', tamper); assert.equal(rt.steps.find((s) => s.step === 'deliver')!.outcome, 'fail', tamper); assert.equal(tampered.state.settlements, 1, tamper);
  }
  const refused = harness({ settleOk: false });
  const r3 = await runBuyerPilot(refused.cfg, refused.deps);
  assert.equal(r3.rollup, 'FAIL'); assert.equal(r3.payments.length, 0);
});

test('buyer pilot core: the d402 payment binds its top-level payee to the bound recipient', () => {
  const skeleton = () => ({ content: { type: 'd402_payment', to: '', data: ['d402_payment', { to: PAYEE, amount: '100000000', memo: 'resourceId:x' }] } });
  assert.equal(bindPaymentPayee(skeleton(), PAYEE).content.to, PAYEE);
  const preset = skeleton(); preset.content.to = '0x';
  assert.equal(bindPaymentPayee(preset, PAYEE).content.to, PAYEE);
  const other = skeleton(); other.content.to = '0x' + '33'.repeat(32);
  assert.throws(() => bindPaymentPayee(other, PAYEE), /differs from the bound recipient/);
  assert.throws(() => bindPaymentPayee({}, PAYEE), /no content/);
  const mismatch = skeleton();
  mismatch.content.data[1] = {
    to: '0x' + '33'.repeat(32), amount: '100000000',
    memo: 'resourceId:x'
  };
  assert.throws(() => bindPaymentPayee(mismatch, PAYEE), /data payee/);
  const same = skeleton();
  same.content.to = PAYEE.toUpperCase();
  assert.equal(bindPaymentPayee(same, PAYEE.toUpperCase()), same);
  assert.equal(same.content.to, PAYEE.toLowerCase());
});

test('buyer pilot core: settlement goes sign -> confirm -> broadcastAndWait; included succeeds with its block, failed and unconfirmed pay nothing, a timeout or broadcast error is an uncertain success without a block', async () => {
  const HASH = 'ab'.repeat(32);
  const node = (over: { sign?: () => Promise<unknown>; confirm?: () => Promise<unknown>; wait?: () => Promise<unknown> } = {}) => ({
    sign: over.sign ?? (async () => ({ hash: HASH })),
    confirm: over.confirm ?? (async () => ({ valid: true })),
    broadcastAndWait: over.wait ?? (async () => ({ status: { state: 'included', blockNumber: 250000 } })),
  });
  assert.deepEqual(await settleThroughNode(node(), {}, 1000), { success: true, hash: HASH, blockNumber: 250000 });
  const failed = await settleThroughNode(node({ wait: async () => ({ status: { state: 'failed' } }) }), {}, 1000);
  assert.equal(failed.success, false); assert.equal(failed.hash, HASH);
  const unconfirmed = await settleThroughNode(node({ confirm: async () => { throw new Error('rejected'); } }), {}, 1000);
  assert.equal(unconfirmed.success, false); assert.match(unconfirmed.message ?? '', /before broadcast/);
  const timeout = await settleThroughNode(node({ wait: async () => { throw Object.assign(new Error('timeout'), { name: 'BroadcastTimeoutError', txHash: HASH }); } }), {}, 1000);
  assert.equal(timeout.success, true); assert.equal(timeout.hash, HASH); assert.equal(timeout.blockNumber, undefined); assert.match(timeout.message ?? '', /inclusion not observed/);
  const unknown = await settleThroughNode(node({ wait: async () => { throw new Error('socket closed'); } }), {}, 1000);
  assert.equal(unknown.success, true); assert.equal(unknown.blockNumber, undefined); assert.match(unknown.message ?? '', /outcome unknown/);
  const unsigned = await settleThroughNode(node({ sign: async () => ({}) }), {}, 1000);
  assert.equal(unsigned.success, false); assert.equal(unsigned.hash, '');
});
