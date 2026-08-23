/**
 * partner-kit/drift.mjs — signed-scope drift evaluation for DACS artifacts, zero dependencies.
 *
 * NON-NORMATIVE partner-kit port of `src/lib/dacs-drift.ts` + `src/lib/bundle-signed-scope-v1.ts`
 * (pathos-dacs-ref). Two honest differences from the reference, both documented:
 *
 *  1. STRUCTURAL CHECK IS A SUBSET. The reference calls its full §10.4 verifier
 *     (`verifyBundleV1`, ~700 lines: signer-set rules, signature walk, ref cross-checks).
 *     This kit applies a LIGHT structural check (see `lightBundleCheck`) sufficient for the
 *     kit's declared vectors — row-for-row parity with the reference evaluator over every
 *     kit drift vector was asserted at generation time (MANIFEST.json receipt). A light-check
 *     "accept" here is NOT a full §10.4 verification.
 *
 *  2. Manifest parsing takes a parsed object (no file I/O) — the runner owns I/O.
 *
 * The HASH surfaces are exact ports:
 *  - bundle signed-scope hash (v0.1 R5-1): sha256(JCS(bundle minus `signatures` minus `anchoredByRole`))
 *  - settlement evidenceHash:              sha256(JCS(evidence minus `signature`))
 */
import { jcsHashHex } from './jcs.mjs';

/** v0.1 R5-1 signed-scope hash — exact port of src/lib/bundle-signed-scope-v1.ts. */
export function bundleSignedScopeHashV1(bundle) {
  const { signatures: _omitSigs, anchoredByRole: _omitRole, ...scope } = bundle;
  void _omitSigs; // §10.4.1 — signatures never in the signed scope
  void _omitRole; // R5-1 — excluded from the hashed canonical form
  return jcsHashHex(scope);
}

/** Only files carrying `bundleVersion` are AttestationBundle candidates. */
export function isBundleCandidate(o) {
  return !!o && typeof o === 'object' && !Array.isArray(o) && 'bundleVersion' in o;
}

/** Normalise an expected hash (strip case-insensitive `sha256:` prefix, lowercase). */
export function normHash(h) {
  return h.replace(/^sha256:/i, '').toLowerCase();
}

/**
 * Kit-local LIGHT structural check (documented subset of verifyBundleV1's structural pass):
 * bundleVersion "1", non-empty string jobId, string outcome, non-empty parties array where
 * every party carries a role + primaryClaim. Returns a reasons list (empty = passes).
 */
export function lightBundleCheck(b) {
  const reasons = [];
  if (b.bundleVersion !== '1') reasons.push(`bundleVersion must be "1" (got ${JSON.stringify(b.bundleVersion)})`);
  if (typeof b.jobId !== 'string' || !b.jobId) reasons.push('jobId must be a non-empty string');
  if (typeof b.outcome !== 'string' || !b.outcome) reasons.push('outcome must be a non-empty string');
  if (!Array.isArray(b.parties) || b.parties.length < 1) {
    reasons.push('parties must be a non-empty array');
  } else {
    for (const p of b.parties) {
      if (!p || typeof p !== 'object' || typeof p.role !== 'string' || typeof p.primaryClaim !== 'string') {
        reasons.push('every party must carry a string role + primaryClaim');
        break;
      }
    }
  }
  return reasons;
}

/** Evaluate ONE parsed AttestationBundle candidate against an optional expected hash. */
export function evaluateBundle(parsed, fixture, expected) {
  if (!isBundleCandidate(parsed)) {
    if (expected != null) {
      return { fixture, ourHash: '', expected: normHash(expected), hashStatus: 'computed',
        structurallyValid: false, decision: 'reject',
        notes: 'manifest expects a bundleHash here, but the file is not an AttestationBundle (no bundleVersion) — cannot verify' };
    }
    return { fixture, ourHash: '', expected: null, hashStatus: 'skipped',
      structurallyValid: true, decision: 'skipped', notes: 'not an AttestationBundle (no bundleVersion) — skipped' };
  }
  const reasons = lightBundleCheck(parsed);
  const structurallyValid = reasons.length === 0;
  let ourHash = '';
  try {
    ourHash = bundleSignedScopeHashV1(parsed);
  } catch {
    ourHash = '';
  }
  const exp = expected != null ? normHash(expected) : null;
  const hashStatus = exp === null ? 'computed' : ourHash === exp ? 'match' : 'drift';
  const notes = structurallyValid
    ? (hashStatus === 'drift' ? 'bundleHash differs from expected — impls disagree on signed scope/content' : '')
    : `structural: ${reasons.slice(0, 2).join('; ')}`;
  return { fixture, ourHash, expected: exp, hashStatus, structurallyValid,
    decision: structurallyValid ? 'accept' : 'reject', kind: 'bundle', notes };
}

/** DACS-4 SettlementEvidence candidate — `evidenceVersion` or a `dacs-4-…` `v`. */
export function isSettlementCandidate(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  return 'evidenceVersion' in o || (typeof o.v === 'string' && o.v.startsWith('dacs-4'));
}

/** Evaluate ONE parsed SettlementEvidence — exact port of the reference evaluator. */
export function evaluateSettlement(parsed, fixture, expected) {
  const ev = parsed;
  let ourHash = '';
  try {
    const { signature: _sig, ...unsigned } = ev;
    void _sig;
    ourHash = jcsHashHex(unsigned);
  } catch { ourHash = ''; }
  const structurallyValid = typeof ev.jobId === 'string' && !!ev.jobId
    && (typeof ev.outcome === 'string' || typeof ev.phase === 'string');
  const exp = expected != null ? normHash(expected) : null;
  const hashStatus = exp === null ? 'computed' : ourHash === exp ? 'match' : 'drift';
  const notes = structurallyValid
    ? (hashStatus === 'drift' ? 'evidenceHash differs from expected — impls disagree on signed scope/content' : '')
    : 'SettlementEvidence missing jobId or outcome/phase';
  return { fixture, ourHash, expected: exp, hashStatus, kind: 'settlement',
    structurallyValid, decision: structurallyValid ? 'accept' : 'reject', notes };
}

/** Dispatch to the right evaluator; unknown artifacts skip (discovery) or fail (manifest). */
export function evaluateArtifact(parsed, fixture, expected) {
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

export function summarise(rows) {
  const skipped = rows.filter((r) => r.hashStatus === 'skipped').length;
  return {
    total: rows.length,
    checked: rows.length - skipped,
    drift: rows.filter((r) => r.hashStatus === 'drift').length,
    structFail: rows.filter((r) => !r.structurallyValid).length,
    skipped,
  };
}

/**
 * Parse + validate an expected-hash manifest object (fail-closed): every value must be a
 * string 64-char sha256 hex (after `sha256:` strip). Port of dacs-drift.mts loadExpected
 * minus file I/O.
 */
export function parseManifest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('manifest must be a JSON object of { fixture: hash }');
  const m = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== 'string') throw new Error(`manifest value for "${k}" is not a string hash`);
    const h = normHash(v);
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`manifest hash for "${k}" is not a 64-char sha256 hex: "${v}"`);
    m[k] = h;
  }
  return m;
}
