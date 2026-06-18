/**
 * GLEIF registration-status → §7.5.1 decision mapping.
 *
 * Locks the deterministic contract the DNO drift-test diffs against — see DACS-Standard
 * convergence issue #146 (Mode-A positions). The compared triple is claim + decision +
 * resolvedEntity; this test pins the `decision` half of that for each GLEIF registration status.
 *
 * The headline change (2026-06-18, locked with DNO): LAPSED → `indeterminate`, not `fail`.
 * A lapsed LEI is "was valid, no longer current" — §7.5.1 "not a conclusive contradiction".
 * RETIRED stays `fail` for now (the open Mode-B-blind hypothesis to revisit toward
 * indeterminate); ANNULLED stays `fail` (issued in error / invalid ab initio).
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { classifyRegistrationStatus, classifyFetchStatus } from '../../src/lib/gleif-classify.js';

test('fetch 404 → fail (true not-found)', () => {
  assert.equal(classifyFetchStatus(404, false)?.decision, 'fail');
  assert.equal(classifyFetchStatus(404, true, 'no such LEI')?.decision, 'fail');
});

test('fetch non-404 error (429/500/403) → error, NOT fail (transient ≠ verdict; protects #146)', () => {
  assert.equal(classifyFetchStatus(429, true, 'rate limited')?.decision, 'error');
  assert.equal(classifyFetchStatus(500, true)?.decision, 'error');
  assert.equal(classifyFetchStatus(403, false)?.decision, 'error');
  // a 200 that nonetheless carries an errors[] array is still not a verdict → error
  assert.equal(classifyFetchStatus(200, true)?.decision, 'error');
  // 3xx (unexpected redirect) is not a 2xx success → error, not a silent proceed-to-parse
  assert.equal(classifyFetchStatus(302, false)?.decision, 'error');
  assert.equal(classifyFetchStatus(199, false)?.decision, 'error');
});

test('fetch 200 with no errors → null (no fetch-level verdict; proceed to registration status)', () => {
  assert.equal(classifyFetchStatus(200, false), null);
});

test('ISSUED → pass (carries the resolved entity name)', () => {
  const r = classifyRegistrationStatus('ISSUED', 'Global Legal Entity Identifier Foundation');
  assert.equal(r.decision, 'pass');
  assert.match(r.reason, /ISSUED/);
});

test('LAPSED → indeterminate (locked with DNO, #146 — was fail before)', () => {
  assert.equal(classifyRegistrationStatus('LAPSED').decision, 'indeterminate');
});

test('RETIRED + ANNULLED → fail (RETIRED is the Mode-B-blind hypothesis to revisit)', () => {
  assert.equal(classifyRegistrationStatus('RETIRED').decision, 'fail');
  assert.equal(classifyRegistrationStatus('ANNULLED').decision, 'fail');
});

test('non-binary / absent status → indeterminate (authority answered; never coerced to pass)', () => {
  assert.equal(classifyRegistrationStatus(undefined).decision, 'indeterminate');
  assert.equal(classifyRegistrationStatus('PENDING_ARCHIVAL').decision, 'indeterminate');
  assert.equal(classifyRegistrationStatus('DUPLICATE').decision, 'indeterminate');
});
