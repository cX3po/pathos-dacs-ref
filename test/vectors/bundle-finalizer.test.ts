import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { finalizeBundle, verifyFinalizedBundleCold, type BundleFinalizerDependencies, type CompletedSessionEvidence } from '../../src/adapters/dacs/bundle-finalizer.js';
import { emitSettlementEvidenceV1, evidenceHashV1 } from '../../src/lib/emit-settlement-evidence-v1.js';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsHashHex } from '../../src/jcs.js';
import type { AnchorReceipt } from '../../src/types/bundle.js';
import type { AttestationRef } from '../../src/types/verify-result.js';

const FIX = new URL('../fixtures/dacs-standard-63793a39/', import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, FIX), 'utf8'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const key = (n: number) => { const privateKey = new Uint8Array(32).fill(n); return { privateKey, claim: `cci:${hex(ed25519.getPublicKey(privateKey))}` }; };
const buyer = key(11), seller = key(12);
const signer = (k: ReturnType<typeof key>) => ({ claim: k.claim, sign: (domain: Parameters<typeof sign>[0], hash: string) => sign(domain, new TextEncoder().encode(hash), k.privateKey) });

function signedEvidence(unsigned: ReturnType<typeof emitSettlementEvidenceV1>, author = buyer) {
  return { ...unsigned, signature: { algorithm: 'ed25519' as const, signer: author.claim,
    value: Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, new TextEncoder().encode(evidenceHashV1(unsigned)), author.privateKey)).toString('base64url') } };
}

function setup() {
  const memory = new Map<string, unknown>();
  const receipts = new Map<string, AnchorReceipt>();
  const bindings: unknown[] = [];
  const receipt = (logicalAddress: string, nativeAddress: string, contentHash: string, writer: string, transactionRef = { kind: 'fake', value: `tx-${logicalAddress}` }, nonce = '0'): AnchorReceipt => ({
    receiptVersion: '1', substrate: 'test', finalityProfile: 'instant', logicalAddress, nativeAddress, contentHash, transactionRef,
    writer, nonce, state: 'finalized', observationDisposition: 'established', observedAt: 1_780_000_000_100,
    blockRef: { id: 'block', timestamp: 1_780_000_000_000 }, evidence: { kind: 'test-proof', value: 'proof' },
  });
  const putEvidence = (logical: string, value: unknown): AttestationRef => {
    const hash = jcsHashHex(value); memory.set(logical, value); receipts.set(logical, receipt(logical, logical, hash, buyer.claim));
    return { anchor: { substrate: 'demos', locator: logical }, contentHash: hash, type: 'settlement-evidence', producedAt: new Date(1_780_000_000_000).toISOString(), signer: buyer.claim };
  };
  let counter = 0;
  const deps: BundleFinalizerDependencies = {
    signers: { buyer: signer(buyer), seller: signer(seller) }, now: () => 1_780_000_001_000,
    async anchor(request) {
      const nativeAddress = `bundle-native-${counter}`; const nonce = String(counter++);
      const anchor = { logicalAddress: request.logicalAddress, nativeAddress, transactionRef: { kind: 'fake', value: `tx-${nativeAddress}` }, writer: request.logicalAddress.includes('buyer') ? buyer.claim : seller.claim, nonce };
      memory.set(nativeAddress, request.content); receipts.set(request.logicalAddress, receipt(request.logicalAddress, nativeAddress, request.contentHash, anchor.writer, anchor.transactionRef, nonce)); return anchor;
    },
    async fetchAnchored(address) { if (!memory.has(address)) throw new Error('not found'); return memory.get(address); },
    async receiptProvider(request) { const found = receipts.get(request.logicalAddress); if (!found) throw new Error('no receipt'); return found; },
    async publishBundleBinding(binding) { bindings.push(binding); },
  };
  return { deps, memory, receipts, bindings, putEvidence };
}

function session(state: ReturnType<typeof setup>): CompletedSessionEvidence {
  const payment = signedEvidence(emitSettlementEvidenceV1({ kind: 'payment', jobId: 'bundle-job', phase: 'pay-x402', phaseIndex: 2, outcome: 'success', observedAt: 1_780_000_000_000,
    paymentTxRefs: [{ rail: 'pay-x402', txHash: 'tx-payment', kind: 'x402' }], paymentAmount: '10', paymentCurrency: 'USDC', finalityModel: 'provider-receipt', finalityObservedAt: 1_780_000_000_000 }));
  const delivery = signedEvidence(emitSettlementEvidenceV1({ kind: 'delivery', jobId: 'bundle-job', phase: 'deliver-attested-payload', phaseIndex: 3, outcome: 'success', observedAt: 1_780_000_000_000,
    deliverableContentHash: 'de'.repeat(32), deliverableAnchorKind: 'https', deliverableAnchorLocator: 'https://example.invalid/result' }));
  const paymentRef = state.putEvidence('evidence-payment', payment), deliveryRef = state.putEvidence('evidence-delivery', delivery);
  const listing = { listingId: 'listing-bundle', listingVersion: 1, contentHash: 'aa'.repeat(32),
    pipeline: [{ kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' }, { kind: 'pay-x402' }, { kind: 'deliver-attested-payload' }] };
  return {
    jobId: 'bundle-job', listing, listingRef: { listingId: listing.listingId, version: listing.listingVersion, contentHash: listing.contentHash },
    agreementRef: { anchor: { substrate: 'demos', locator: 'dacs3:commit:bundle-job' }, contentHash: 'ac'.repeat(32), type: 'finality-commitment', producedAt: new Date(0).toISOString() },
    parties: [{ role: 'buyer', bundleHash: '01'.repeat(32), primaryClaim: buyer.claim }, { role: 'seller', bundleHash: '02'.repeat(32), primaryClaim: seller.claim }],
    phaseResults: [
      { index: 0, kind: 'negotiate-fixed-price', outcome: 'ok', orchestrator: buyer.claim },
      { index: 1, kind: 'commit-agreement', outcome: 'ok', orchestrator: buyer.claim },
      { index: 2, kind: 'pay-x402', outcome: 'ok', orchestrator: buyer.claim, evidenceRef: paymentRef, evidenceLogicalAddress: 'evidence-payment' },
      { index: 3, kind: 'deliver-attested-payload', outcome: 'ok', orchestrator: buyer.claim, evidenceRef: deliveryRef, evidenceLogicalAddress: 'evidence-delivery' },
    ], outcome: 'completed', faultedParty: 'none', recipeRegistryVersion: 1, railRegistryVersion: 1,
  };
}

test('finalizeBundle emits EBFAB role copies, phase-ordered evidence, bindings, and finalized receipts', async () => {
  const state = setup(); const result = await finalizeBundle(session(state), state.deps);
  const buyerBundle = result.bundles.buyer!.bundle, sellerBundle = result.bundles.seller!.bundle;
  assert.equal('evidenceBoundFaultBundleVersion' in buyerBundle && buyerBundle.evidenceBoundFaultBundleVersion, '1');
  assert.equal('evidenceBoundFaultBundleVersion' in sellerBundle && sellerBundle.evidenceBoundFaultBundleVersion, '1');
  assert.equal(result.bundles.buyer?.bundle.phaseSummary.map((p) => p.index).join(','), '0,1,2,3');
  assert.equal(result.bundles.buyer?.bundle.settlementEvidence.map((r) => r.anchor.locator).join(','), 'evidence-payment,evidence-delivery');
  assert.equal(state.bindings.length, 2);
  assert.ok(result.bundles.buyer?.bundle.signatures.every((s) => !s.value.includes('=')));
});

test('kind fab emits FaultAttestationBundle and never legacy bundleVersion', async () => {
  const state = setup(); const input = session(state); input.kind = 'fab';
  const result = await finalizeBundle(input, state.deps);
  const buyerBundle = result.bundles.buyer!.bundle;
  assert.equal('faultBundleVersion' in buyerBundle && buyerBundle.faultBundleVersion, '1');
  assert.ok(!('bundleVersion' in buyerBundle));
});

test('SEB rejects duplicate evidence references', async () => {
  const state = setup(); const input = session(state); input.phaseResults[3]!.evidenceRef = input.phaseResults[2]!.evidenceRef;
  await assert.rejects(finalizeBundle(input, state.deps), /duplicate reference/);
});

test('SEB rejects phase-kind divergence before anchoring', async () => {
  const state = setup(); const input = session(state); input.phaseResults[2]!.kind = 'pay-dem';
  await assert.rejects(finalizeBundle(input, state.deps), /contiguous 0\.\.n prefix/);
});

test('SEB verifies evidence signer and receipt writer as the authenticated phase orchestrator', async () => {
  const state = setup(); const input = session(state); input.phaseResults[2]!.orchestrator = seller.claim;
  await assert.rejects(finalizeBundle(input, state.deps), /evidence signer is not/);
});

test('cold final bundle verification re-fetches both role copies and finalized receipts', async () => {
  const state = setup(); const result = await finalizeBundle(session(state), state.deps);
  const verdict = await verifyFinalizedBundleCold({ jobId: 'bundle-job', ...result }, state.deps);
  assert.equal(verdict.outcome, 'pass');
});

test('cold final bundle verification returns indeterminate for non-final receipt', async () => {
  const state = setup(); const result = await finalizeBundle(session(state), state.deps);
  const buyerLogical = result.bundles.buyer!.address.logical;
  state.receipts.set(buyerLogical, { ...state.receipts.get(buyerLogical)!, state: 'included' });
  const verdict = await verifyFinalizedBundleCold({ jobId: 'bundle-job', ...result }, state.deps);
  assert.equal(verdict.outcome, 'indeterminate');
});

test('pinned EBFAB, bijection, phase-divergence, binding, and settlement success inputs are replayable', () => {
  const ebfab = load('fixtures/evidence-bound-fault-bundle-compatibility-v0.4.json');
  const bijection = load('vectors/security/bundle-settlement-evidence-bijection-v0.4.json');
  const divergence = load('vectors/security/phase-kind-divergence-v0.3.json');
  const binding = load('vectors/security/bundle-binding-v0.1.json');
  const payment = load('fixtures/settlement-evidence-payment-success.json');
  const delivery = load('fixtures/settlement-evidence-delivery-success.json');
  assert.ok(JSON.stringify(ebfab).includes('evidenceBoundFaultBundleVersion'));
  assert.ok(bijection.vectors.length > 0 && divergence.vectors.length > 0 && binding.vectors.length > 0);
  assert.equal(payment.evidence.evidenceVersion, '1');
  assert.equal(delivery.evidence.evidenceVersion, '1');
});
