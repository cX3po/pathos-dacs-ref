/**
 * settlement-evidence-cross-run.mts — dacs-sdk PR #28 SettlementEvidence convergence read.
 *
 * Drives THIS impl's independent §9.7 structural verifier
 * (src/lib/verify-settlement-evidence-v1.ts) over the SAME case set dacs-sdk PR #28's
 * `verifySettlementEvidence` runs (its §14-fixture mutations), and reports, per case,
 * whether the two independent impls reach the same §7.5.1 decision. Independent read —
 * our checks are derived from the DACS-4 normative text, not fitted to #28's tests.
 *
 * SCOPE (honest): our verifier is PURE-STRUCTURAL (record-only). #28's context-gated
 * checks (agreement/rail coherence, HTLC route params, attestationRef, orchestrator
 * binding, key-resolution signature verdicts) take injected context our verifier does
 * not model — those cases are listed as out-of-scope, not silently skipped.
 *
 * Base records: the §14 settlement fixtures from DACS-Standard
 * conformance/fixtures/settlement-evidence-{payment,delivery}-success.json @ be8fe63,
 * inlined verbatim (signature stripped — the structural domain excludes it).
 *
 *   npx tsx conformance/vet-drift/settlement-evidence-cross-run.mts
 *
 * Exit 0 iff every in-scope case either converges or is a DOCUMENTED divergence
 * (a spec ambiguity we raise upstream rather than silently match).
 */
import { verifySettlementEvidenceV1 } from '../../src/lib/verify-settlement-evidence-v1.js';

type Ev = Record<string, unknown>;

/** DACS-Standard conformance/fixtures/settlement-evidence-payment-success.json @ be8fe63 (evidence, sans signature). */
const PAYMENT: Ev = {
  evidenceVersion: '1',
  jobId: 'DACS-VERIFY-SETTLE-0001',
  phase: 'pay-evm-erc20',
  phaseIndex: 0,
  outcome: 'success',
  paymentTxRefs: [{ rail: 'polygon-amoy-usdc', txHash: 'polygon-amoy:0xsettle0001', kind: 'payment' }],
  paymentAmount: { amount: '5', currency: 'USDC' },
  settlementFinality: { model: 'block-depth', finalityBlocks: 1, finalityObservedAt: 1780014401000 },
  observedAt: 1780014400000,
};

/** DACS-Standard conformance/fixtures/settlement-evidence-delivery-success.json @ be8fe63 (evidence, sans signature). */
const DELIVERY: Ev = {
  evidenceVersion: '1',
  jobId: 'DACS-VERIFY-DELIVER-0001',
  phase: 'deliver-storage-program',
  phaseIndex: 0,
  outcome: 'success',
  deliverableContentHash: '052a3e356972170c7b655e7d5a92ab2fe070b3ebf4ae8f63f4fd93ad0cc2cb0e',
  deliverableAnchor: { kind: 'storage-program', locator: 'stor-dacs-verify-delivery-0001' },
  observedAt: 1780014402000,
};

const clone = <T>(x: T): T => structuredClone(x);

/**
 * The #28 structural case set: name → (mutated record, #28's expected decision).
 * Expected decisions are #28's OWN test assertions (test/agent/verifySettlementEvidence.test.ts),
 * so a mismatch is a genuine cross-impl divergence, not a harness artifact.
 */
type Case = { name: string; sdk28: 'pass' | 'fail' | 'error'; ev: unknown; note?: string };
const CASES: Case[] = [
  { name: 'paymentPass', sdk28: 'pass', ev: clone(PAYMENT) },
  { name: 'deliveryPass', sdk28: 'pass', ev: clone(DELIVERY) },
  { name: 'successPaymentMissingFinality', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); delete e.settlementFinality; return e; })() },
  { name: 'successMissingPaymentTxRefs', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); delete e.paymentTxRefs; return e; })() },
  { name: 'successMissingPaymentAmount', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); delete e.paymentAmount; return e; })() },
  { name: 'nonCanonicalAmount', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); (e.paymentAmount as Ev).amount = '5.00'; return e; })() },
  { name: 'nonPositiveAmount', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); (e.paymentAmount as Ev).amount = '0'; return e; })() },
  { name: 'negativeFee', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); e.paymentFee = { amount: '-1', currency: 'USDC' }; return e; })() },
  {
    name: 'failureNoReason', sdk28: 'fail',
    ev: (() => { const e = clone(PAYMENT); e.outcome = 'failure'; delete e.settlementFinality; return e; })(),
    note: 'DOCUMENTED divergence — §9.7 type block says `reason?: string // when outcome == "failure"`: presence-scoping or requiredness? #28 reads MUST-on-failure; we read may-only-on-failure. Raised upstream.',
  },
  { name: 'unknownPhase', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); e.phase = 'pay-nonsense'; return e; })() },
  { name: 'badOutcomeEnum', sdk28: 'fail', ev: (() => { const e = clone(PAYMENT); e.outcome = 'settled'; return e; })() },
  { name: 'deliveryWithFinality', sdk28: 'fail', ev: (() => { const e = clone(DELIVERY); e.settlementFinality = { model: 'block-depth', finalityBlocks: 1, finalityObservedAt: 1 }; return e; })() },
  { name: 'deliveryMissingDeliverable', sdk28: 'fail', ev: (() => { const e = clone(DELIVERY); delete e.deliverableContentHash; return e; })() },
  { name: 'deliveryMalformedContentHash', sdk28: 'fail', ev: (() => { const e = clone(DELIVERY); e.deliverableContentHash = 'not-a-hash'; return e; })() },
  { name: 'storageAnchoredAsEntitlement', sdk28: 'fail', ev: (() => { const e = clone(DELIVERY); (e.deliverableAnchor as Ev).kind = 'entitlement'; return e; })() },
  { name: 'deliveryExtraPaymentFieldPass', sdk28: 'pass', ev: (() => { const e = clone(DELIVERY); e.paymentAmount = { amount: '5', currency: 'USDC' }; return e; })() },
  {
    name: 'malformedRoot', sdk28: 'fail', ev: 'not-an-object',
    note: 'DOCUMENTED divergence — four-value philosophy: #28 grades a non-object root `fail`; we grade unparseable input `error` (§7.5.1 do-not-collapse: a definite record violation vs input that is not a record at all). Raised upstream.',
  },
  {
    name: 'missingPhaseIndex', sdk28: 'pass', ev: (() => { const e = clone(PAYMENT); delete e.phaseIndex; return e; })(),
    note: 'Converges — but for reconciliation-worthy reasons: SB-1 says phaseIndex is NOT an evidence field (anchor-address-derived), #28 ignores it, the merged §14 fixtures carry it in-body (hash-significant), and dacs-verify REQUIRES it in-body. Three-way impl disagreement raised upstream.',
  },
];

/** #28 cases OUT OF SCOPE for a pure-structural verifier (context-gated / key-dependent). */
const OUT_OF_SCOPE = [
  'currencyMismatchNotRejected (rail asset ctx)', 'underpaymentVsAgreement (agreement ctx)',
  'phaseRailMismatch / txRefsMismatch / railNetworkMismatch / incoherentRailTypeHandler (rail ctx)',
  'htlcFinalityParams / htlcMissingSourceFinality / htlcMissingSafetyWindow / htlcInsufficientMargin (HTLC route ctx)',
  'wrongAttestationKind / attestationRefHashMismatch (attestationRef ctx)',
  'nonOrchestratorSigner (orchestrator ctx)', 'okTrueWithErrorClass / okFalseNoErrorClass (phase-result ctx)',
  'wrongAnchor (expectedAnchorLocator ctx)', 'unresolvableKey / malformedKey / wrongSignerKey (key deps)',
  'crossChainAnchorPending / crossChainIdMatchingKindPass (rail ctx)',
];

type Row = { name: string; sdk28: string; ours: string; converged: boolean; documented: boolean };
const rows: Row[] = CASES.map((c) => {
  const ours = verifySettlementEvidenceV1(c.ev).decision;
  return { name: c.name, sdk28: c.sdk28, ours, converged: ours === c.sdk28, documented: !!c.note && ours !== c.sdk28 };
});

let undocumentedDivergence = false;
for (const r of rows) {
  const mark = r.converged ? '✓' : r.documented ? '≠' : '✗';
  if (!r.converged && !r.documented) undocumentedDivergence = true;
  console.log(`${mark} ${r.name}  sdk28=${r.sdk28} ours=${r.ours}${r.converged ? '' : r.documented ? '  (documented divergence)' : '  UNDOCUMENTED DIVERGENCE'}`);
}
for (const c of CASES) if (c.note) console.log(`\n[note] ${c.name}: ${c.note}`);

console.log(`\nOut of scope for the structural verifier (context-gated in #28):`);
for (const s of OUT_OF_SCOPE) console.log(`  - ${s}`);

const converged = rows.filter((r) => r.converged).length;
const documented = rows.filter((r) => !r.converged && r.documented).length;
console.log(`\nSettlementEvidence cross-run: ${converged}/${rows.length} converged, ${documented} documented divergence(s) (pathos-dacs-ref vs dacs-sdk #28)`);
process.exit(undocumentedDivergence ? 1 : 0);
