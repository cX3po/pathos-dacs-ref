/**
 * ACCEPTANCE PROOF — pathos independently emits the SDK's SettlementEvidence V1 bytes.
 *
 * This is the whole point of the fix/settlement-evidence-v1-realign build: it upgrades
 * the settlement cross-impl claim from "both re-hash the same shared fixture" to genuine
 * INDEPENDENT-EMISSION convergence.
 *
 * For each dacs-x cross-impl fixture (settlement-evidence-payment.json + -delivery.json):
 *   (a) load the fixture, strip its signature, compute the TARGET evidenceHash via jcsHashHex;
 *   (b) call emitSettlementEvidenceV1 with that fixture's LOGICAL INPUTS (jobId, phase,
 *       phaseIndex, outcome, observedAt, + payment/delivery payload);
 *   (c) ASSERT evidenceHashV1(emitted) === TARGET hash.
 *
 * If a byte-match fails, the emitted object's field SET / shape is wrong — fix the emitter
 * until jcsHashHex(emitted minus sig) === jcsHashHex(fixture minus sig).
 *
 * Run: npx tsx conformance/security-vectors/settlement-v1/run.mts
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { jcsHashHex } from '../../../src/jcs.js';
import { emitSettlementEvidenceV1, evidenceHashV1 } from '../../../src/lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../../../src/lib/verify-settlement-evidence-v1.js';

const HERE = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
const FIXDIR = `${HERE}/../../../test/vectors/dacs-x-fixtures`;

const load = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(`${FIXDIR}/${name}`, 'utf8')) as Record<string, unknown>;

/** TARGET hash = sha256(JCS(fixture minus signature)). */
function targetHash(fixture: Record<string, unknown>): string {
  const { signature: _sig, ...unsigned } = fixture;
  void _sig;
  return jcsHashHex(unsigned);
}

let pass = 0;
let total = 0;
console.log('\n=== SettlementEvidence V1 INDEPENDENT-EMISSION byte-match ===\n');

// --- PAYMENT -------------------------------------------------------------
{
  total++;
  const fx = load('settlement-evidence-payment.json');
  const target = targetHash(fx);
  // Pass nested values as PRIMITIVES (not the fixture's nested objects) — this proves
  // the emitter fully RECONSTRUCTS every nested object from scalars (F1).
  const fxTxRefs = fx.paymentTxRefs as Array<{ rail: string; txHash: string; kind: string }>;
  const fxAmount = fx.paymentAmount as { amount: string; currency: string };
  const fxFinality = fx.settlementFinality as {
    model: 'block-depth'; finalityBlocks?: number;
    finalityCommitmentLevel?: 'processed' | 'confirmed' | 'finalized'; finalityObservedAt: number;
  };
  const emitted = emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    phaseIndex: fx.phaseIndex as number,
    outcome: fx.outcome as 'success' | 'failure',
    paymentTxRefs: fxTxRefs.map((r) => ({ rail: r.rail, txHash: r.txHash, kind: r.kind })),
    paymentAmount: fxAmount.amount,
    paymentCurrency: fxAmount.currency,
    finalityModel: fxFinality.model,
    finalityObservedAt: fxFinality.finalityObservedAt,
    finalityBlocks: fxFinality.finalityBlocks,
    observedAt: fx.observedAt as number,
  });
  const got = evidenceHashV1(emitted);
  const matched = got === target;
  pass += matched ? 1 : 0;
  console.log(`  [${matched ? '✓' : '✗'}] payment   byte-match`);
  console.log(`        target : ${target}`);
  console.log(`        emitted: ${got}`);
  console.log(`        => ${matched ? 'BYTE-MATCH PASS' : 'BYTE-MATCH FAIL'}\n`);
}

// --- DELIVERY ------------------------------------------------------------
{
  total++;
  const fx = load('settlement-evidence-delivery.json');
  const target = targetHash(fx);
  const fxAnchor = fx.deliverableAnchor as { kind: string; locator: string };
  const emitted = emitSettlementEvidenceV1({
    kind: 'delivery',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    phaseIndex: fx.phaseIndex as number,
    outcome: fx.outcome as 'success' | 'failure',
    deliverableContentHash: fx.deliverableContentHash as string,
    deliverableAnchorKind: fxAnchor.kind,
    deliverableAnchorLocator: fxAnchor.locator,
    observedAt: fx.observedAt as number,
  });
  const got = evidenceHashV1(emitted);
  const matched = got === target;
  pass += matched ? 1 : 0;
  console.log(`  [${matched ? '✓' : '✗'}] delivery  byte-match`);
  console.log(`        target : ${target}`);
  console.log(`        emitted: ${got}`);
  console.log(`        => ${matched ? 'BYTE-MATCH PASS' : 'BYTE-MATCH FAIL'}\n`);
}

// --- ADVERSARIAL: nested extra subfields are IGNORED (F1) ----------------
// A caller smuggles extra subfields into every nested object. The closed sanitizing
// constructor must DROP them, so the emitted bytes/hash are UNCHANGED.
{
  total++;
  const fx = load('settlement-evidence-payment.json');
  const target = targetHash(fx);
  const fxTxRefs = fx.paymentTxRefs as Array<{ rail: string; txHash: string; kind: string }>;
  const fxAmount = fx.paymentAmount as { amount: string; currency: string };
  const fxFinality = fx.settlementFinality as { model: 'block-depth'; finalityBlocks?: number; finalityObservedAt: number };
  const emitted = emitSettlementEvidenceV1({
    kind: 'payment',
    jobId: fx.jobId as string,
    phase: fx.phase as string,
    phaseIndex: fx.phaseIndex as number,
    outcome: fx.outcome as 'success' | 'failure',
    // each entry carries an extra subfield that MUST be dropped
    paymentTxRefs: fxTxRefs.map((r) => ({ rail: r.rail, txHash: r.txHash, kind: r.kind, extra: 'leak' } as never)),
    paymentAmount: fxAmount.amount,
    paymentCurrency: fxAmount.currency,
    finalityModel: fxFinality.model,
    finalityObservedAt: fxFinality.finalityObservedAt,
    finalityBlocks: fxFinality.finalityBlocks,
    observedAt: fx.observedAt as number,
  });
  // Sanity: the emitted object itself carries NO extra subfield on its tx refs.
  const emittedRefs = (emitted as { paymentTxRefs: Array<Record<string, unknown>> }).paymentTxRefs;
  const noExtraInObject = emittedRefs.every((r) => !('extra' in r));
  const got = evidenceHashV1(emitted);
  const matched = got === target && noExtraInObject;
  pass += matched ? 1 : 0;
  console.log(`  [${matched ? '✓' : '✗'}] payment   adversarial nested-extra IGNORED`);
  console.log(`        target : ${target}`);
  console.log(`        emitted: ${got}`);
  console.log(`        extra-subfield-dropped: ${noExtraInObject}`);
  console.log(`        => ${matched ? 'PASS (extra ignored, hash unchanged)' : 'FAIL'}\n`);
}

console.log(`${pass}/${total} byte-match assertions pass`);
if (pass !== total) {
  console.error('\nFAIL: pathos did NOT reproduce the SDK evidence bytes — field shape/order is wrong.');
  process.exit(1);
}
console.log('PASS: independent emission of the §9.7 evidence ENVELOPE; evidenceHash byte-matches on payment + delivery success fixtures.');

/* ---------------------------------------------------------------------------- */
/*  Verifier conformance vectors — verifySettlementEvidenceV1 (§7.5.1)           */
/* ---------------------------------------------------------------------------- */

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const validPayment = {
  evidenceVersion: '1', jobId: 'DACS-VERIFY-SETTLE-0001', phase: 'pay-evm-erc20', phaseIndex: 0,
  outcome: 'success',
  paymentTxRefs: [{ rail: 'polygon-amoy-usdc', txHash: 'polygon-amoy:0xsettle0001', kind: 'payment' }],
  paymentAmount: { amount: '5', currency: 'USDC' },
  settlementFinality: { model: 'block-depth', finalityBlocks: 1, finalityObservedAt: 1780014401000 },
  observedAt: 1780014400000,
};
const validDelivery = {
  evidenceVersion: '1', jobId: 'DACS-VERIFY-DELIVER-0001', phase: 'deliver-storage-program', phaseIndex: 0,
  outcome: 'success',
  deliverableContentHash: '052a3e356972170c7b655e7d5a92ab2fe070b3ebf4ae8f63f4fd93ad0cc2cb0e',
  deliverableAnchor: { kind: 'storage-program', locator: 'stor-dacs-verify-delivery-0001' },
  observedAt: 1780014402000,
};
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

type VCase = { name: string; expected: 'pass' | 'fail' | 'indeterminate' | 'error'; evidence: unknown };
const vcases: VCase[] = [
  { name: 'valid-payment', expected: 'pass', evidence: clone(validPayment) },
  { name: 'valid-delivery', expected: 'pass', evidence: clone(validDelivery) },
  // missing-phaseIndex → PASS (SB-1: phaseIndex is not an evidence field — recovered from the PC-2 anchor address; in-body copy is an open-world extra)
  { name: 'missing-phaseIndex', expected: 'pass', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; delete e.phaseIndex; return e; })() },
  // success payment with no settlementFinality → fail (PC-6)
  { name: 'success-payment-missing-finality', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; delete e.settlementFinality; return e; })() },
  // delivery carrying settlementFinality → fail (PC-6)
  { name: 'delivery-with-finality', expected: 'fail', evidence: (() => { const e = clone(validDelivery) as Record<string, unknown>; e.settlementFinality = { model: 'block-depth', finalityObservedAt: 1780014402000 }; return e; })() },
  // F2: FAILURE-outcome payment carrying settlementFinality → fail (PC-6, finality forbidden outside success-payment)
  { name: 'failure-payment-with-finality', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; e.outcome = 'failure'; return e; })() },
  // F3: phaseIndex not a SAFE integer → fail (SDK uses Number.isSafeInteger)
  { name: 'phaseIndex-not-safe-integer', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; e.phaseIndex = Number.MAX_SAFE_INTEGER + 2; return e; })() },
  // F3: deliverableContentHash not lowercase 64-hex → fail
  { name: 'deliverable-content-hash-not-hex', expected: 'fail', evidence: (() => { const e = clone(validDelivery) as Record<string, unknown>; e.deliverableContentHash = 'NOT-A-HEX-HASH'; return e; })() },
  // F1: observedAt not a SAFE integer → fail (SDK uses Number.isSafeInteger, settlement.ts L308)
  { name: 'observedAt-not-safe-integer', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; e.observedAt = 1.5; return e; })() },
  // F2: GENUINELY malformed paymentTxRef entry (missing txHash) → fail. NOTE: `kind` is
  // OPTIONAL per the SDK's isChainTxRef (rail+txHash required), so a missing-kind entry is
  // NOT malformed; this tests a missing-txHash entry the SDK also rejects.
  { name: 'malformed-payment-txref-entry', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; e.paymentTxRefs = [{ rail: 'polygon-amoy-usdc', kind: 'payment' }]; return e; })() },
  // outcome not in {success,failure} → fail
  { name: 'bad-outcome-enum', expected: 'fail', evidence: (() => { const e = clone(validPayment) as Record<string, unknown>; e.outcome = 'settled'; return e; })() },
  // malformed (not an object) → error
  { name: 'malformed', expected: 'error', evidence: 'not-an-evidence-object' },
  // F3 (round-trip consistent): a FAILURE payment with `reason` and NO finality, EMITTED
  // by our own emitSettlementEvidenceV1 — the emitter omits settlementFinality on a failure
  // outcome (PC-6, settlement.ts L240) and carries the optional `reason`, so the record our
  // emitter produces PASSES our verifier. (Replaces the prior hand-mutated fixture.)
  { name: 'failure-payment-with-reason-no-finality', expected: 'pass', evidence: emitSettlementEvidenceV1({
      kind: 'payment',
      jobId: validPayment.jobId,
      phase: validPayment.phase,
      phaseIndex: validPayment.phaseIndex,
      outcome: 'failure',
      paymentTxRefs: validPayment.paymentTxRefs.map((r) => ({ rail: r.rail, txHash: r.txHash, kind: r.kind })),
      paymentAmount: validPayment.paymentAmount.amount,
      paymentCurrency: validPayment.paymentAmount.currency,
      observedAt: validPayment.observedAt,
      reason: 'rail-revert',
    }) },
];

const vectors = vcases.map((c) => ({ name: c.name, expected: c.expected, evidence: c.evidence }));
const setHash = sha(JSON.stringify(vectors));
if (!existsSync(`${HERE}/vectors`)) mkdirSync(`${HERE}/vectors`, { recursive: true });
writeFileSync(
  `${HERE}/vectors/settlement-v1-v0.1.json`,
  JSON.stringify({ set: 'settlement-v1-v0.1', spec: 'DACS-4 §9.7 / §7.5.1', hash: setHash, count: vectors.length, vectors }, null, 2),
);

let vpass = 0;
console.log('\n=== verifySettlementEvidenceV1 conformance vectors v0.1 ===');
for (const c of vcases) {
  const r = verifySettlementEvidenceV1(c.evidence);
  const okc = r.decision === c.expected;
  vpass += okc ? 1 : 0;
  console.log(`  [${okc ? '✓' : '✗'}] ${c.name.padEnd(34)} exp=${c.expected.padEnd(13)} got=${r.decision.padEnd(13)}${r.reasons.length ? ' :: ' + r.reasons[0] : ''}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${vpass}/${vcases.length} verifier vectors pass → vectors/settlement-v1-v0.1.json`);
if (vpass !== vcases.length) process.exit(1);
