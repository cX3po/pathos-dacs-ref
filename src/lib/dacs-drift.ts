/**
 * dacs-drift core — cross-impl conformance / drift evaluation for DACS v0.1 AttestationBundles.
 *
 * Pure logic (no file I/O) so it is unit-testable; the `dacs-drift.mts` CLI wraps it with
 * directory walking + rendering. Reuses the reference-impl primitives — `verifyBundleV1`
 * (structural + signature) and `bundleSignedScopeHashV1` (the v0.1 R5-1 signed-scope hash) —
 * so "does impl X agree with the reference" is answered by the same code that defines the reference.
 */
import { verifyBundleV1 } from './verify-bundle-v1.js';
import { bundleSignedScopeHashV1 } from './bundle-signed-scope-v1.js';
import { jcsHashHex } from '../jcs.js';
import type { AttestationBundleV1 } from '../types/bundle.js';

export type HashStatus = 'match' | 'drift' | 'computed' | 'skipped';

export interface DriftRow {
  fixture: string;
  ourHash: string;
  expected: string | null;
  hashStatus: HashStatus;
  structurallyValid: boolean;
  decision: 'accept' | 'reject' | 'skipped';
  /** Which DACS artifact this row checked. Absent ⇒ legacy bundle row (evaluateBundle). */
  kind?: 'bundle' | 'settlement';
  notes: string;
}

/** A conformance dir holds many artifact kinds (settlement evidence, reputation, identity); only
 *  files carrying `bundleVersion` are AttestationBundles. Non-bundles are SKIPPED, never reported
 *  as structural failures (false-positive guard). */
export function isBundleCandidate(o: unknown): boolean {
  return !!o && typeof o === 'object' && !Array.isArray(o) && 'bundleVersion' in (o as object);
}

/** Normalise an expected hash (strip a case-insensitive `sha256:` prefix, lowercase). */
export function normHash(h: string): string {
  return h.replace(/^sha256:/i, '').toLowerCase();
}

/**
 * Evaluate ONE parsed artifact against an optional expected signed-scope hash.
 * `expected` null/undefined ⇒ discovery mode (compute + verify, status `computed`).
 */
export function evaluateBundle(parsed: unknown, fixture: string, expected?: string | null): DriftRow {
  if (!isBundleCandidate(parsed)) {
    // Codex BLOCKER: a non-bundle may only be SKIPPED in discovery mode. If a manifest expected a
    // hash for this fixture, a non-bundle there means we CANNOT verify the expected hash — that is a
    // FAILURE, never a silent skip (else the tool reports convergence without checking an expected file).
    if (expected != null) {
      return { fixture, ourHash: '', expected: normHash(expected), hashStatus: 'computed',
        structurallyValid: false, decision: 'reject',
        notes: 'manifest expects a bundleHash here, but the file is not an AttestationBundle (no bundleVersion) — cannot verify' };
    }
    return { fixture, ourHash: '', expected: null, hashStatus: 'skipped',
      structurallyValid: true, decision: 'skipped', notes: 'not an AttestationBundle (no bundleVersion) — skipped' };
  }
  const bundle = parsed as AttestationBundleV1;
  // Cross-impl fixtures often use placeholder-DID signers (unverifiable, not failed) → fixture mode.
  const v = verifyBundleV1(bundle, { requireSignatures: false });
  let ourHash = '';
  try {
    const { signatures: _s, ...unsigned } = bundle as unknown as Record<string, unknown>;
    void _s;
    ourHash = bundleSignedScopeHashV1(unsigned);
  } catch {
    ourHash = '';
  }
  const exp = expected != null ? normHash(expected) : null;
  const hashStatus: HashStatus = exp === null ? 'computed' : ourHash === exp ? 'match' : 'drift';
  const notes = v.structurallyValid
    ? (hashStatus === 'drift' ? 'bundleHash differs from expected — impls disagree on signed scope/content' : '')
    : `structural: ${v.reasons.slice(0, 2).join('; ')}`;
  return { fixture, ourHash, expected: exp, hashStatus,
    structurallyValid: v.structurallyValid, decision: v.decision, notes };
}

/** A DACS-4 SettlementEvidence — spec/SDK form carries `evidenceVersion`; our HTLC form carries a
 *  `dacs-4-…` `v`. Either way the evidenceHash is sha256(JCS(evidence without `signature`)). */
export function isSettlementCandidate(o: unknown): boolean {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const r = o as Record<string, unknown>;
  return 'evidenceVersion' in r || (typeof r.v === 'string' && r.v.startsWith('dacs-4'));
}

/**
 * Evaluate ONE parsed DACS-4 SettlementEvidence against an optional expected evidenceHash.
 * evidenceHash = sha256(JCS(evidence minus `signature`)) — the same canonical-form discipline the
 * bundle uses, so two impls (e.g. pathos-dacs-ref ↔ dacs-sdk) that emit the same logical evidence
 * reproduce the same hash. This is the settlement-layer analogue of the bundleHash convergence check.
 */
export function evaluateSettlement(parsed: unknown, fixture: string, expected?: string | null): DriftRow {
  const ev = parsed as Record<string, unknown>;
  let ourHash = '';
  try {
    const { signature: _sig, ...unsigned } = ev;
    void _sig;
    ourHash = jcsHashHex(unsigned);
  } catch { ourHash = ''; }
  // Light cross-impl structural check: a recognisable evidence carries a jobId and an outcome/phase.
  // (dacs-drift checks hash convergence, not crypto — signature verification is impl-specific.)
  const structurallyValid = typeof ev.jobId === 'string' && !!ev.jobId
    && (typeof ev.outcome === 'string' || typeof ev.phase === 'string');
  const exp = expected != null ? normHash(expected) : null;
  const hashStatus: HashStatus = exp === null ? 'computed' : ourHash === exp ? 'match' : 'drift';
  const notes = structurallyValid
    ? (hashStatus === 'drift' ? 'evidenceHash differs from expected — impls disagree on signed scope/content' : '')
    : 'SettlementEvidence missing jobId or outcome/phase';
  return { fixture, ourHash, expected: exp, hashStatus, kind: 'settlement',
    structurallyValid, decision: structurallyValid ? 'accept' : 'reject', notes };
}

/**
 * Dispatch one parsed artifact to the right evaluator: AttestationBundle (bundleHash) or
 * SettlementEvidence (evidenceHash). Anything else is SKIPPED in discovery mode, or a hard
 * failure if a manifest expected a hash for it (can't verify an unrecognised artifact).
 */
export function evaluateArtifact(parsed: unknown, fixture: string, expected?: string | null): DriftRow {
  if (isBundleCandidate(parsed)) return evaluateBundle(parsed, fixture, expected);
  if (isSettlementCandidate(parsed)) return evaluateSettlement(parsed, fixture, expected);
  if (expected != null) {
    return { fixture, ourHash: '', expected: normHash(expected), hashStatus: 'computed',
      structurallyValid: false, decision: 'reject',
      notes: 'manifest expects a hash here, but the file is neither an AttestationBundle nor a SettlementEvidence — cannot verify' };
  }
  return { fixture, ourHash: '', expected: null, hashStatus: 'skipped',
    structurallyValid: true, decision: 'skipped', notes: 'not an AttestationBundle or SettlementEvidence — skipped' };
}

export interface DriftSummary { total: number; checked: number; drift: number; structFail: number; skipped: number; }

export function summarise(rows: DriftRow[]): DriftSummary {
  const skipped = rows.filter((r) => r.hashStatus === 'skipped').length;
  return {
    total: rows.length,
    checked: rows.length - skipped,
    drift: rows.filter((r) => r.hashStatus === 'drift').length,
    structFail: rows.filter((r) => !r.structurallyValid).length, // skipped rows are structurallyValid:true
    skipped,
  };
}

/**
 * Build an expected-hash manifest `{ "<fixture>.json": "<bundleHash>" }` from a set of evaluated
 * rows — the bootstrap for `--expect` (drift-catching) mode. Includes ONLY rows that are an
 * accepted, structurally-valid artifact (bundle OR settlement) with a computed hash; non-DACS files
 * (`skipped`) and structural failures are excluded so a golden manifest never pins a bad fixture.
 * Pure + deterministic (sorted keys) so re-running over the same fixtures yields identical bytes.
 */
export function buildManifest(rows: DriftRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows.filter((r) => r.decision === 'accept' && r.structurallyValid && r.ourHash).sort((a, b) => a.fixture.localeCompare(b.fixture))) {
    out[r.fixture] = r.ourHash;
  }
  return out;
}
