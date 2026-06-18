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
import type { AttestationBundleV1 } from '../types/bundle.js';

export type HashStatus = 'match' | 'drift' | 'computed' | 'skipped';

export interface DriftRow {
  fixture: string;
  ourHash: string;
  expected: string | null;
  hashStatus: HashStatus;
  structurallyValid: boolean;
  decision: 'accept' | 'reject' | 'skipped';
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
 * rows — the bootstrap for `--expect` (drift-catching) mode. Includes ONLY rows that are a
 * structurally-valid, verified bundle (`decision === 'accept'`) with a computed hash; non-bundles
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
