/**
 * bundle-consistency-cross-run.mts — dacs-sdk PR #30 bundleConsistency convergence read.
 *
 * Drives THIS impl's independent §10.4.3 classifier (src/lib/bundle-consistency-v1.ts)
 * over the SAME case set dacs-sdk PR #30's `bundleConsistency` runs (its unit cases +
 * the §14 session fixtures), and reports per-case verdict convergence. Independent
 * read — our rules are derived from the §10.4.3 (a)–(d) consumer text, not fitted
 * to #30's tests.
 *
 * KNOWN MODEL DIFFERENCE (by design, raised upstream): #30 delegates §10.4.1
 * signature-set validity entirely to an injected `isValid` and its DEFAULT treats any
 * provided copy as valid, so a lone SINGLE-SIGNED NON-abort copy classifies
 * `oneSided`. §10.4.3(b) says that copy "is rejected per §10.4.1, leaving no valid
 * bundle for the session" → our classifier grades it `absent`. The composition
 * question (does verifyBundleCore-as-isValid honor the §10.11 single-signed-abort
 * exception?) is #30 review material.
 *
 * §14 fixture facts inlined from DACS-Standard conformance/fixtures @ be8fe63:
 *   attestation-bundle-0004{,-seller}.json — both 2-signed; buyer outcome
 *   "completed" (phases ok/ok), seller "failed-counterparty" (phase 1 fail,
 *   errorClass counterparty) → divergent.
 *   session-bundle-one-sided.json — single-signed, outcome "aborted-by-other" →
 *   oneSided via the §10.11 suppression arm (NOT an anchoring omission).
 *
 *   npx tsx conformance/vet-drift/bundle-consistency-cross-run.mts
 *
 * Exit 0 iff every case converges or is a DOCUMENTED divergence.
 */
import { bundleConsistencyV1, canonicalDivergenceV1 } from '../../src/lib/bundle-consistency-v1.js';

type B = Record<string, unknown>;
const sig2 = [{ s: 1 }, { s: 2 }];
const sig1 = [{ s: 1 }];

type Case = { name: string; sdk30: string; buyer?: unknown; seller?: unknown; note?: string };
const CASES: Case[] = [
  { name: 'absent-none', sdk30: 'absent' },
  { name: 'absent-nulls', sdk30: 'absent', buyer: null, seller: null },
  {
    name: 'oneSided-buyer-only', sdk30: 'oneSided',
    buyer: { outcome: 'completed', phaseSummary: [], signatures: sig2 },
  },
  {
    name: 'oneSided-seller-only', sdk30: 'oneSided',
    seller: { outcome: 'completed', phaseSummary: [], signatures: sig2 },
  },
  {
    name: 'unified-advisory-only-differences', sdk30: 'unified',
    buyer: { outcome: 'completed', anchoredByRole: 'buyer', finalisedAt: 1000, signatures: sig2,
      phaseSummary: [{ index: 0, kind: 'settle', outcome: 'ok' }] },
    seller: { outcome: 'completed', anchoredByRole: 'seller', finalisedAt: 1002, ratingRefs: ['stor-r'], signatures: sig2,
      phaseSummary: [{ index: 0, kind: 'settle', outcome: 'ok' }] },
  },
  {
    name: 'divergent-outcome', sdk30: 'divergent',
    buyer: { outcome: 'completed', phaseSummary: [], signatures: sig2 },
    seller: { outcome: 'failed-counterparty', phaseSummary: [], signatures: sig2 },
  },
  {
    name: 'divergent-phase-outcome-errorClass', sdk30: 'divergent',
    buyer: { outcome: 'completed', phaseSummary: [{ index: 1, outcome: 'ok' }], signatures: sig2 },
    seller: { outcome: 'completed', phaseSummary: [{ index: 1, outcome: 'fail', errorClass: 'counterparty' }], signatures: sig2 },
  },
  {
    // §10.4.3 ruling #224 (carve-out-free): a phase present in only one copy IS divergence now.
    // dacs-sdk#30's predicate is mid-flip to the same rule (RB: "one predicate, presence-mismatch
    // diverges, both call sites") — so this re-converges once #30 lands its flip.
    name: 'phase-in-one-copy-is-divergence-224', sdk30: 'divergent',
    buyer: { outcome: 'completed', phaseSummary: [{ index: 0, outcome: 'ok' }], signatures: sig2 },
    seller: { outcome: 'completed', phaseSummary: [{ index: 0, outcome: 'ok' }, { index: 1, outcome: 'ok' }], signatures: sig2 },
    note: 'Presence-mismatch → divergent per ruling #224. dacs-sdk#30 still returns unified pre-flip; convergence resumes when #30 adopts the shared predicate RB assigned to @HaykK-Solicy.',
  },
  {
    // §14 fixture shape: attestation-bundle-0004 buyer vs seller (both 2-signed).
    name: 'fixture-0004-buyer-vs-seller', sdk30: 'divergent',
    buyer: { outcome: 'completed', signatures: sig2,
      phaseSummary: [{ index: 0, outcome: 'ok' }, { index: 1, outcome: 'ok' }] },
    seller: { outcome: 'failed-counterparty', signatures: sig2,
      phaseSummary: [{ index: 0, outcome: 'ok' }, { index: 1, outcome: 'fail', errorClass: 'counterparty' }] },
  },
  {
    // §14 fixture shape: session-bundle-one-sided (single-signed, abort outcome).
    name: 'fixture-one-sided-abort', sdk30: 'oneSided',
    buyer: { outcome: 'aborted-by-other', signatures: sig1,
      phaseSummary: [{ index: 0, outcome: 'fail', errorClass: 'counterparty' }] },
    note: 'Converges on the verdict — but #30\'s doc calls oneSided "an anchoring omission, not an abort"; this fixture stands via the §10.11 single-signed-ABORT suppression arm, a different (b) sub-case. Doc-precision note raised upstream.',
  },
  {
    name: 'lone-single-signed-NON-abort', sdk30: 'oneSided',
    buyer: { outcome: 'completed', phaseSummary: [], signatures: sig1 },
    note: 'DOCUMENTED divergence — §10.4.3(b): "a single-signed copy with any other outcome is rejected per §10.4.1, leaving no valid bundle for the session" → ours grades absent. #30\'s default isValid treats any provided copy as valid → oneSided. Raised upstream (whether verifyBundleCore-as-isValid closes this is the composition question).',
  },
];

type Row = { name: string; sdk30: string; ours: string; converged: boolean; documented: boolean };
const rows: Row[] = CASES.map((c) => {
  const r = bundleConsistencyV1({ buyer: c.buyer, seller: c.seller });
  return { name: c.name, sdk30: c.sdk30, ours: r.verdict, converged: r.verdict === c.sdk30, documented: !!c.note && r.verdict !== c.sdk30 };
});

// Divergence-definition spot check: errorClass-only contradiction (same phase outcome).
const errOnly = canonicalDivergenceV1(
  { outcome: 'completed', phaseSummary: [{ index: 0, outcome: 'fail', errorClass: 'transient' }] } as B,
  { outcome: 'completed', phaseSummary: [{ index: 0, outcome: 'fail', errorClass: 'counterparty' }] } as B,
);

let undocumented = false;
for (const r of rows) {
  const mark = r.converged ? '✓' : r.documented ? '≠' : '✗';
  if (!r.converged && !r.documented) undocumented = true;
  console.log(`${mark} ${r.name}  sdk30=${r.sdk30} ours=${r.ours}${r.converged ? '' : r.documented ? '  (documented divergence)' : '  UNDOCUMENTED DIVERGENCE'}`);
}
console.log(`${errOnly ? '✓' : '✗'} errorClass-only contradiction detected by both divergence definitions (${errOnly ?? 'MISSED'})`);
if (!errOnly) undocumented = true;
for (const c of CASES) if (c.note) console.log(`\n[note] ${c.name}: ${c.note}`);

const converged = rows.filter((r) => r.converged).length;
const documented = rows.filter((r) => !r.converged && r.documented).length;
console.log(`\nbundleConsistency cross-run: ${converged}/${rows.length} converged, ${documented} documented divergence(s) (pathos-dacs-ref vs dacs-sdk #30)`);
process.exit(undocumented ? 1 : 0);
