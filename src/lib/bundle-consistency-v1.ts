/**
 * bundle-consistency-v1.ts — DACS-5 §10.4.3 two-sided bundle consistency classification.
 *
 * PATH-OS Labs independent implementation of the §10.4.3 consumer rules (a)–(d),
 * derived from the normative text — NOT fitted to dacs-sdk PR #30 (that would make an
 * independent convergence read meaningless). The rules:
 *
 *  - (a) a consumer fetches BOTH party addresses (`…-bundle-buyer`, `…-bundle-seller`).
 *  - (b) exactly one copy present → classify by the present copy's SIGNATURE SET:
 *        · all §10.4.1 required signatures → it IS the unified session bundle; the
 *          missing copy is an anchoring omission, not an abort — verdict `oneSided`,
 *          standing `full-signatures`.
 *        · single-signed with an ABORT outcome → stands per the §10.11
 *          bundle-suppression rule (aborted-by-self for the non-signer,
 *          aborted-by-other for the signer) — verdict `oneSided`, standing
 *          `abort-suppression`.
 *        · single-signed with any OTHER outcome → rejected per §10.4.1, leaving NO
 *          valid bundle for the session — verdict `absent` (rejection recorded).
 *  - (c) both present and NOT canonically diverging → `unified`.
 *  - (d) both present and canonically diverging → `divergent` (dispute; a §10.5.1
 *        reputation deriver excludes the jobId entirely).
 *
 * "Canonically diverge" (§10.4.3, normative, defined once): the copies differ in
 * `outcome`, or in a shared `phaseSummary` entry's `outcome`/`errorClass` — a
 * contradiction about what happened. Advisory-field differences (`anchoredByRole`,
 * `finalisedAt` skew, one-sided `ratingRefs`, amendment ordering) are NOT divergence,
 * and a phase entry present in only one copy is not itself a contradiction.
 *
 * Pure: no crypto. The default signature-set classification is STRUCTURAL (count the
 * `signatures[]` entries — 2+ = full, 1 = single, else invalid); a caller that has
 * cryptographically verified the copies injects its own classification via
 * `classifySignatures` (e.g. wrap the single-bundle verifier). This mirrors where
 * §10.4.1 puts the burden: validity is the verifier's job, classification is ours.
 */

export type BundleRole = 'buyer' | 'seller';

export type ConsistencyVerdict = 'absent' | 'oneSided' | 'unified' | 'divergent';

/** §10.4.1 signature-set classes used by the (b) rules. */
export type SignatureSetClass = 'full' | 'single' | 'invalid';

/** §10.4.3(b) standing of a lone copy. */
export type OneSidedStanding = 'full-signatures' | 'abort-suppression';

export interface BundleConsistencyV1Result {
  verdict: ConsistencyVerdict;
  /** When `oneSided`: which role's copy stands, and why it stands. */
  oneSided?: { role: BundleRole; standing: OneSidedStanding };
  /** When `divergent`: the first contradiction found (human-readable). */
  divergence?: string;
  /** Copies dropped by the (b) rejection rule or the injected classifier, with the §-cited reason. */
  rejected?: Array<{ role: BundleRole; reason: string }>;
}

const ABORT_OUTCOMES: ReadonlySet<string> = new Set(['aborted-by-self', 'aborted-by-other']);

const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** Structural default for the §10.4.1 signature-set class (no crypto — count entries). */
function structuralSignatureClass(bundle: Record<string, unknown>): SignatureSetClass {
  const sigs = bundle['signatures'];
  if (!Array.isArray(sigs)) return 'invalid';
  if (sigs.length >= 2) return 'full';
  if (sigs.length === 1) return 'single';
  return 'invalid';
}

/** phaseSummary entries keyed by `index` (the stable per-phase identifier). */
function phasesByIndex(bundle: Record<string, unknown>): Map<number, Record<string, unknown>> {
  const out = new Map<number, Record<string, unknown>>();
  const ps = bundle['phaseSummary'];
  if (Array.isArray(ps)) {
    for (const p of ps) if (isObj(p) && typeof p['index'] === 'number') out.set(p['index'] as number, p);
  }
  return out;
}

/**
 * §10.4.3 canonical divergence between two copies. Returns the first contradiction
 * (outcome, or a shared phase's outcome/errorClass) or null when the copies do not
 * canonically diverge.
 */
export function canonicalDivergenceV1(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): string | null {
  if (a['outcome'] !== b['outcome']) {
    return `outcome contradiction: ${JSON.stringify(a['outcome'])} vs ${JSON.stringify(b['outcome'])}`;
  }
  const bp = phasesByIndex(b);
  for (const [idx, pa] of phasesByIndex(a)) {
    const pb = bp.get(idx);
    if (!pb) continue; // a phase present in only one copy is not itself a contradiction
    if (pa['outcome'] !== pb['outcome']) {
      return `phaseSummary contradiction at index ${idx}: outcome ${JSON.stringify(pa['outcome'])} vs ${JSON.stringify(pb['outcome'])}`;
    }
    if ((pa['errorClass'] ?? null) !== (pb['errorClass'] ?? null)) {
      return `phaseSummary contradiction at index ${idx}: errorClass ${JSON.stringify(pa['errorClass'] ?? null)} vs ${JSON.stringify(pb['errorClass'] ?? null)}`;
    }
  }
  return null;
}

export interface BundleConsistencyV1Options {
  /**
   * §10.4.1 signature-set classification per copy. Defaults to the structural count.
   * A caller that ran cryptographic verification injects the real class here;
   * returning 'invalid' drops the copy (treated as not-present, reason recorded).
   */
  classifySignatures?: (bundle: Record<string, unknown>, role: BundleRole) => SignatureSetClass;
}

/**
 * Classify the two-sided copies for a session per §10.4.3 (a)–(d).
 * Never throws; non-object copies are treated as not-present.
 */
export function bundleConsistencyV1(
  copies: { buyer?: unknown; seller?: unknown },
  options: BundleConsistencyV1Options = {},
): BundleConsistencyV1Result {
  const classify = options.classifySignatures ?? ((b: Record<string, unknown>) => structuralSignatureClass(b));
  const rejected: Array<{ role: BundleRole; reason: string }> = [];

  type Standing = { role: BundleRole; bundle: Record<string, unknown>; sig: 'full' | 'single' };
  const standing: Standing[] = [];

  for (const role of ['buyer', 'seller'] as const) {
    const raw = copies[role];
    if (!isObj(raw)) continue; // not present
    const sig = classify(raw, role);
    if (sig === 'invalid') {
      rejected.push({ role, reason: 'copy failed §10.4.1 signature-set validation (classifier: invalid)' });
      continue;
    }
    standing.push({ role, bundle: raw, sig });
  }

  // (b) — a lone SINGLE-SIGNED copy stands only with an abort outcome (§10.11 suppression);
  // any other single-signed outcome is rejected per §10.4.1, leaving no valid bundle.
  // NOTE the rule is scoped to the lone-copy case: when BOTH copies are present each stands on
  // its own signatures for the (c)/(d) comparison (§10.4.3(d): "each bundle stands on its own
  // signatures"), and single-signed validity is the single-bundle verifier's concern.
  if (standing.length === 1) {
    const lone = standing[0]!;
    if (lone.sig === 'single' && !ABORT_OUTCOMES.has(String(lone.bundle['outcome']))) {
      rejected.push({
        role: lone.role,
        reason: `single-signed copy with non-abort outcome ${JSON.stringify(lone.bundle['outcome'])} is rejected per §10.4.1 — no valid bundle for the session (§10.4.3(b))`,
      });
      return { verdict: 'absent', rejected };
    }
    return {
      verdict: 'oneSided',
      oneSided: { role: lone.role, standing: lone.sig === 'full' ? 'full-signatures' : 'abort-suppression' },
      ...(rejected.length ? { rejected } : {}),
    };
  }

  if (standing.length === 0) return rejected.length ? { verdict: 'absent', rejected } : { verdict: 'absent' };

  const div = canonicalDivergenceV1(standing[0]!.bundle, standing[1]!.bundle);
  if (div) return { verdict: 'divergent', divergence: div, ...(rejected.length ? { rejected } : {}) };
  return { verdict: 'unified', ...(rejected.length ? { rejected } : {}) };
}
