/**
 * DACS-4 Settle — spec/SDK SettlementEvidence V1 (§9.7) vectors
 *
 * Locks in:
 *   - INDEPENDENT-EMISSION byte-match: emitSettlementEvidenceV1(fixture logical inputs)
 *     reproduces the dacs-x fixture's evidenceHash (payment + delivery) — convergence
 *     by emitting the same bytes, NOT by re-hashing a shared fixture.
 *   - verifySettlementEvidenceV1 negatives (§7.5.1 do-not-collapse):
 *       · missing phaseIndex (PC-2)               → fail
 *       · success payment without settlementFinality (PC-6) → fail
 *       · delivery carrying settlementFinality (PC-6)        → fail
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { jcsHashHex } from '../../src/jcs.js';
import { emitSettlementEvidenceV1, evidenceHashV1 } from '../../src/lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../../src/lib/verify-settlement-evidence-v1.js';

const FIXDIR = fileURLToPath(new URL('./dacs-x-fixtures', import.meta.url));
const load = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(`${FIXDIR}/${name}`, 'utf8')) as Record<string, unknown>;
const targetHash = (fx: Record<string, unknown>): string => {
  const { signature: _s, ...unsigned } = fx;
  void _s;
  return jcsHashHex(unsigned);
};

const emitPaymentFrom = (fx: Record<string, unknown>, mut?: (refs: Array<Record<string, unknown>>) => Array<Record<string, unknown>>) => {
  const refs = fx.paymentTxRefs as Array<{ rail: string; txHash: string; kind: string }>;
  const amount = fx.paymentAmount as { amount: string; currency: string };
  const finality = fx.settlementFinality as { model: 'block-depth'; finalityBlocks?: number; finalityObservedAt: number };
  const baseRefs = refs.map((r) => ({ rail: r.rail, txHash: r.txHash, kind: r.kind }));
  return emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    phaseIndex: fx.phaseIndex as number,
    outcome: fx.outcome as 'success' | 'failure',
    paymentTxRefs: (mut ? mut(baseRefs) : baseRefs) as never,
    paymentAmount: amount.amount,
    paymentCurrency: amount.currency,
    finalityModel: finality.model,
    finalityObservedAt: finality.finalityObservedAt,
    finalityBlocks: finality.finalityBlocks,
    observedAt: fx.observedAt as number,
  });
};

test('payment evidence byte-matches the SDK fixture (independent emission)', () => {
  const fx = load('settlement-evidence-payment.json');
  assert.equal(evidenceHashV1(emitPaymentFrom(fx)), targetHash(fx));
});

test('delivery evidence byte-matches the SDK fixture (independent emission)', () => {
  const fx = load('settlement-evidence-delivery.json');
  const anchor = fx.deliverableAnchor as { kind: string; locator: string };
  const emitted = emitSettlementEvidenceV1({
    kind: 'delivery',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    phaseIndex: fx.phaseIndex as number,
    outcome: fx.outcome as 'success' | 'failure',
    deliverableContentHash: fx.deliverableContentHash as string,
    deliverableAnchorKind: anchor.kind,
    deliverableAnchorLocator: anchor.locator,
    observedAt: fx.observedAt as number,
  });
  assert.equal(evidenceHashV1(emitted), targetHash(fx));
});

test('F1: nested extra subfields are IGNORED — emitted bytes/hash unchanged', () => {
  const fx = load('settlement-evidence-payment.json');
  const clean = emitPaymentFrom(fx);
  // smuggle an extra subfield into every tx ref; the closed constructor must drop it
  const dirty = emitPaymentFrom(fx, (refs) => refs.map((r) => ({ ...r, extra: 'leak' })));
  const dirtyRefs = (dirty as unknown as { paymentTxRefs: Array<Record<string, unknown>> }).paymentTxRefs;
  assert.ok(dirtyRefs.every((r) => !('extra' in r)), 'extra subfield must not survive into the emitted object');
  assert.equal(evidenceHashV1(dirty), evidenceHashV1(clean));
  assert.equal(evidenceHashV1(dirty), targetHash(fx));
});

test('verifier: missing phaseIndex → fail (PC-2)', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  delete fx.phaseIndex;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('verifier: success payment without settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  delete fx.settlementFinality;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('verifier: delivery carrying settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-delivery.json') as Record<string, unknown>;
  delete fx.signature;
  fx.settlementFinality = { model: 'block-depth', finalityObservedAt: 1780014402000 };
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F2 verifier: FAILURE-outcome payment carrying settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  fx.outcome = 'failure'; // finality stays present → forbidden outside success-payment
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F3 verifier: non-safe-integer phaseIndex → fail', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  fx.phaseIndex = Number.MAX_SAFE_INTEGER + 2;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F3 verifier: non-hex deliverableContentHash → fail', () => {
  const fx = load('settlement-evidence-delivery.json') as Record<string, unknown>;
  delete fx.signature;
  fx.deliverableContentHash = 'NOT-A-HEX-HASH';
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F2 verifier: paymentTxRef with OPTIONAL kind omitted → pass (SDK isChainTxRef requires only rail+txHash)', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  fx.paymentTxRefs = [{ rail: 'polygon-amoy-usdc', txHash: 'polygon-amoy:0xsettle0001' }];
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'pass');
});

test('F2 verifier: genuinely malformed paymentTxRef entry (missing txHash) → fail', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  fx.paymentTxRefs = [{ rail: 'polygon-amoy-usdc', kind: 'payment' }];
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F1 verifier: observedAt not a safe integer → fail (SDK Number.isSafeInteger)', () => {
  const fx = load('settlement-evidence-payment.json') as Record<string, unknown>;
  delete fx.signature;
  fx.observedAt = 1.5;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});
