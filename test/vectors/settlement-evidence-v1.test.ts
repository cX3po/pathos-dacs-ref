/**
 * DACS-4 Settle — SettlementEvidence V1 (§9.7) against the Standard's conformance fixtures
 *
 * Fixtures: test/vectors/dacs-standard-fixtures/settlement-evidence-{payment,delivery}-success.json, copied
 * verbatim from DACS-Standard conformance/fixtures at commit 18b385b6 (see SOURCE.md there). Their `evidence`
 * member is the wire record: no phaseIndex (DACS-4 §9.5.8 SB-1 recovers it from the anchor address) and
 * paymentTxRefs as §9.7 ChainTxRef arms with exact keys, which is what the pinned dacs-sdk validates.
 *
 * Locks in:
 *   - INDEPENDENT-EMISSION byte-match: emitSettlementEvidenceV1(fixture logical inputs) reproduces the
 *     fixture's evidenceHash (payment + delivery) — convergence by emitting the same bytes.
 *   - The fixture's own signature verifies under our SETTLEMENT_EVIDENCE domain over that hash.
 *   - verifySettlementEvidenceV1 negatives (§7.5.1 do-not-collapse), including the legacy in-body
 *     phaseIndex (tolerated) and the legacy {rail,txHash,kind} reference form (read, not emitted).
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { jcsHashHex } from '../../src/jcs.js';
import {
  emitSettlementEvidenceV1,
  evidenceHashV1,
  signSettlementEvidenceV1,
} from '../../src/lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../../src/lib/verify-settlement-evidence-v1.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { generateKeypair, verify } from '../../src/lib/sign.js';
import type { PaymentTxRefV1 } from '../../src/types/settle.js';

const FIXDIR = fileURLToPath(new URL('./dacs-standard-fixtures', import.meta.url));
interface StandardFixture { evidence: Record<string, unknown>; evidenceHash: string; publicKeys: Record<string, string> }
const loadFixture = (name: string): StandardFixture => JSON.parse(readFileSync(`${FIXDIR}/${name}`, 'utf8')) as StandardFixture;
const load = (name: string): Record<string, unknown> => structuredClone(loadFixture(name).evidence);
const targetHash = (fx: Record<string, unknown>): string => {
  const { signature: _s, ...unsigned } = fx;
  void _s;
  return jcsHashHex(unsigned);
};

const emitPaymentFrom = (fx: Record<string, unknown>, mut?: (refs: Array<Record<string, unknown>>) => Array<Record<string, unknown>>) => {
  const refs = fx.paymentTxRefs as Array<Record<string, unknown>>;
  const amount = fx.paymentAmount as { amount: string; currency: string };
  const finality = fx.settlementFinality as { model: 'block-depth'; finalityBlocks?: number; finalityObservedAt: number };
  const baseRefs = refs.map((r) => ({ ...r }));
  return emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    outcome: fx.outcome as 'success' | 'failure',
    paymentTxRefs: (mut ? mut(baseRefs) : baseRefs) as unknown as PaymentTxRefV1[],
    paymentAmount: amount.amount,
    paymentCurrency: amount.currency,
    finalityModel: finality.model,
    finalityObservedAt: finality.finalityObservedAt,
    finalityBlocks: finality.finalityBlocks,
    observedAt: fx.observedAt as number,
  });
};

test('payment evidence byte-matches the Standard fixture (independent emission; the fixture states its evidenceHash)', () => {
  const fixture = loadFixture('settlement-evidence-payment-success.json');
  const fx = load('settlement-evidence-payment-success.json');
  assert.equal(targetHash(fx), fixture.evidenceHash, 'our JCS hash of the fixture record equals the hash the Standard states');
  assert.equal(evidenceHashV1(emitPaymentFrom(fx)), fixture.evidenceHash);
  assert.ok(!('phaseIndex' in emitPaymentFrom(fx)), 'SB-1: no phaseIndex in the emitted body');
});

test('delivery evidence byte-matches the Standard fixture (independent emission)', () => {
  const fixture = loadFixture('settlement-evidence-delivery-success.json');
  const fx = load('settlement-evidence-delivery-success.json');
  const anchor = fx.deliverableAnchor as { kind: string; locator: string };
  const emitted = emitSettlementEvidenceV1({
    kind: 'delivery',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    outcome: fx.outcome as 'success' | 'failure',
    deliverableContentHash: fx.deliverableContentHash as string,
    deliverableAnchorKind: anchor.kind,
    deliverableAnchorLocator: anchor.locator,
    observedAt: fx.observedAt as number,
  });
  assert.equal(targetHash(fx), fixture.evidenceHash);
  assert.equal(evidenceHashV1(emitted), fixture.evidenceHash);
});

test('the Standard fixtures\' own signatures verify under our SETTLEMENT_EVIDENCE domain over the evidence hash', () => {
  for (const name of ['settlement-evidence-payment-success.json', 'settlement-evidence-delivery-success.json']) {
    const fixture = loadFixture(name);
    const signature = fixture.evidence.signature as { algorithm: string; signer: string; value: string };
    const pub = Buffer.from(fixture.publicKeys[signature.signer]!, 'base64url');
    assert.equal(signature.algorithm, 'ed25519');
    assert.equal(
      verify(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, Buffer.from(signature.value, 'base64url'), new TextEncoder().encode(fixture.evidenceHash), pub),
      true, `${name}: the Standard signed sep || UTF8(evidenceHash) with the key it publishes`,
    );
  }
});

test('signed evidence authenticates the canonical signature-omitted artifact hash', () => {
  const fx = load('settlement-evidence-payment-success.json');
  const unsigned = emitPaymentFrom(fx);
  const keys = generateKeypair();
  const signed = signSettlementEvidenceV1(unsigned, `cci:${Buffer.from(keys.pubKey).toString('hex')}`, keys.privKey);
  const signature = Buffer.from(signed.signature!.value, 'base64');
  assert.equal(evidenceHashV1(signed), evidenceHashV1(unsigned));
  assert.equal(verify(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, signature, new TextEncoder().encode(evidenceHashV1(unsigned)), keys.pubKey), true);
});

test('F1: nested extra subfields are IGNORED — emitted bytes/hash unchanged', () => {
  const fx = load('settlement-evidence-payment-success.json');
  const clean = emitPaymentFrom(fx);
  const dirty = emitPaymentFrom(fx, (refs) => refs.map((r) => ({ ...r, extra: 'leak' })));
  const dirtyRefs = (dirty as unknown as { paymentTxRefs: Array<Record<string, unknown>> }).paymentTxRefs;
  assert.ok(dirtyRefs.every((r) => !('extra' in r)), 'extra subfield must not survive into the emitted object');
  assert.equal(evidenceHashV1(dirty), evidenceHashV1(clean));
  assert.equal(evidenceHashV1(dirty), targetHash(fx));
});

test('emitter: a demos ChainTxRef keeps exactly kind/txHash/blockNumber; an unknown kind is refused', () => {
  const fx = load('settlement-evidence-payment-success.json');
  const demos = emitPaymentFrom(fx, () => [{ kind: 'demos', txHash: 'abc', blockNumber: 7, extra: 'smuggled' }]);
  assert.deepEqual((demos as unknown as { paymentTxRefs: unknown[] }).paymentTxRefs, [{ kind: 'demos', txHash: 'abc', blockNumber: 7 }]);
  assert.throws(() => emitPaymentFrom(fx, () => [{ kind: 'lightning', txHash: 'abc' }]), /unknown ChainTxRef kind/);
});

test('verifier: the Standard form without phaseIndex passes; a legacy in-body phaseIndex (evidence anchored before 2026-09-06) is tolerated', () => {
  const fx = load('settlement-evidence-payment-success.json');
  delete fx.signature;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'pass');
  fx.phaseIndex = 0;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'pass');
});

test('verifier: success payment without settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-payment-success.json');
  delete fx.signature;
  delete fx.settlementFinality;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('verifier: delivery carrying settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-delivery-success.json');
  delete fx.signature;
  fx.settlementFinality = { model: 'block-depth', finalityObservedAt: 1780014402000 };
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F2 verifier: FAILURE-outcome payment carrying settlementFinality → fail (PC-6)', () => {
  const fx = load('settlement-evidence-payment-success.json');
  delete fx.signature;
  fx.outcome = 'failure';
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F3 verifier: non-safe-integer phaseIndex → fail', () => {
  const fx = load('settlement-evidence-payment-success.json');
  delete fx.signature;
  fx.phaseIndex = Number.MAX_SAFE_INTEGER + 2;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('F3 verifier: non-hex deliverableContentHash → fail', () => {
  const fx = load('settlement-evidence-delivery-success.json');
  delete fx.signature;
  fx.deliverableContentHash = 'NOT-A-HEX-HASH';
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});

test('verifier: paymentTxRefs accept the §9.7 ChainTxRef arms with exact keys and the legacy {rail,txHash,kind?} form; extras and unknown kinds fail', () => {
  const base = load('settlement-evidence-payment-success.json');
  delete base.signature;
  const withRefs = (refs: unknown[]) => verifySettlementEvidenceV1({ ...base, paymentTxRefs: refs }).decision;
  assert.equal(withRefs([{ kind: 'demos', txHash: 'h' }]), 'pass');
  assert.equal(withRefs([{ kind: 'demos', txHash: 'h', blockNumber: 12 }]), 'pass');
  assert.equal(withRefs([{ kind: 'evm', chainId: 80002, txHash: 'polygon-amoy:0xsettle0001' }]), 'pass');
  assert.equal(withRefs([{ kind: 'storage-program', address: 'stor-a', writeTxHash: 'tx' }]), 'pass');
  assert.equal(withRefs([{ rail: 'polygon-amoy-usdc', txHash: 'polygon-amoy:0xsettle0001' }]), 'pass', 'legacy form, kind optional');
  assert.equal(withRefs([{ rail: 'pay-ap2', txHash: 'ap2:tx-1', kind: 'payment' }]), 'pass', 'legacy form as the AP2 extension emits it');
  assert.equal(withRefs([{ kind: 'demos', txHash: 'h', extra: 1 }]), 'fail', 'exact keys on a spec arm');
  assert.equal(withRefs([{ kind: 'demos', blockNumber: 1 }]), 'fail', 'txHash required');
  assert.equal(withRefs([{ kind: 'evm', txHash: 'x' }]), 'fail', 'chainId required');
  assert.equal(withRefs([{ kind: 'lightning', txHash: 'x' }]), 'fail', 'unknown arm');
  assert.equal(withRefs([{ rail: 'polygon-amoy-usdc', kind: 'payment' }]), 'fail', 'legacy form without txHash');
});

test('F1 verifier: observedAt not a safe integer → fail (SDK Number.isSafeInteger)', () => {
  const fx = load('settlement-evidence-payment-success.json');
  delete fx.signature;
  fx.observedAt = 1.5;
  assert.equal(verifySettlementEvidenceV1(fx).decision, 'fail');
});
