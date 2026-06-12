/**
 * dacs-drift core tests — the cross-impl conformance/drift evaluator (src/lib/dacs-drift.ts).
 * Exercises: match, drift, non-bundle skip, malformed-bundle struct-fail, discovery mode.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { evaluateBundle, summarise, isBundleCandidate } from '../../src/lib/dacs-drift.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (n: string) => path.join(HERE, 'dacs-x-fixtures', n);
const load = (n: string) => JSON.parse(readFileSync(FX(n), 'utf8'));

const H_0004 = '9e5ea58d198b459a2929d38019807c465ce9988dcb89c847cce8e80210df39ba';

test('dacs-drift — MATCH: our fixture vs its known exclude-rule hash', () => {
  const r = evaluateBundle(load('attestation-bundle-0004.json'), 'attestation-bundle-0004.json', H_0004);
  assert.equal(r.hashStatus, 'match');
  assert.equal(r.structurallyValid, true);
  assert.equal(r.decision, 'accept');
  assert.equal(r.ourHash, H_0004);
});

test('dacs-drift — MATCH is sha256:-prefix and case insensitive', () => {
  const r = evaluateBundle(load('attestation-bundle-0004.json'), 'attestation-bundle-0004.json', 'sha256:' + H_0004.toUpperCase());
  assert.equal(r.hashStatus, 'match');
});

test('dacs-drift — DRIFT: stale (old in-hash) expected is flagged', () => {
  const stale = '98d7b565da2cbb6e60048b51cb87450484d78d1bd7eb46c96b5fe6fe4ac2dd5e';
  const r = evaluateBundle(load('attestation-bundle-0004.json'), 'attestation-bundle-0004.json', stale);
  assert.equal(r.hashStatus, 'drift');
  assert.equal(r.structurallyValid, true, 'a drift is a hash disagreement, not a structural failure');
  assert.match(r.notes, /differs from expected/);
});

test('dacs-drift — discovery mode (no expected) computes the hash, status "computed"', () => {
  const r = evaluateBundle(load('attestation-bundle-0004.json'), 'attestation-bundle-0004.json');
  assert.equal(r.hashStatus, 'computed');
  assert.equal(r.ourHash, H_0004);
});

test('dacs-drift — non-bundle JSON is SKIPPED, not a struct-fail', () => {
  const notABundle = { jobId: 'x', some: 'settlement-evidence-without-bundleVersion' };
  assert.equal(isBundleCandidate(notABundle), false);
  const r = evaluateBundle(notABundle, 'settlement-evidence.json', null);
  assert.equal(r.hashStatus, 'skipped');
  assert.equal(r.decision, 'skipped');
  assert.equal(r.structurallyValid, true, 'skip must not count as a structural failure');
});

test('dacs-drift — REGRESSION (Codex blocker): a manifest-expected non-bundle FAILS, never silently skips', () => {
  // discovery mode (no expected) → legitimately skipped
  const skip = evaluateBundle({ jobId: 'x', attestations: [] }, 'settlement.json', null);
  assert.equal(skip.hashStatus, 'skipped');
  assert.equal(skip.structurallyValid, true);
  // BUT if a manifest expected a hash for this fixture, a non-bundle there must FAIL (no false convergence)
  const fail = evaluateBundle({ jobId: 'x', attestations: [] }, 'settlement.json', H_0004);
  assert.equal(fail.structurallyValid, false, 'expected-listed non-bundle must not be a silent skip');
  assert.equal(fail.decision, 'reject');
  assert.equal(summarise([fail]).structFail, 1, 'must count toward struct-fail → non-zero exit');
  assert.notEqual(fail.hashStatus, 'skipped');
});

test('dacs-drift — malformed bundle (has bundleVersion but invalid) is a struct-fail', () => {
  const malformed = { bundleVersion: '1', jobId: '' }; // bundleVersion present → it IS a bundle, but invalid
  const r = evaluateBundle(malformed, 'broken.json', null);
  assert.equal(r.structurallyValid, false);
  assert.equal(r.decision, 'reject');
});

test('dacs-drift — summarise counts checked/drift/struct-fail/skipped correctly', () => {
  const rows = [
    evaluateBundle(load('attestation-bundle-0004.json'), 'a.json', H_0004),                 // match
    evaluateBundle(load('attestation-bundle-0004.json'), 'b.json', 'ab'.repeat(32)),         // drift
    evaluateBundle({ notABundle: true }, 'c.json', null),                                     // skipped
    evaluateBundle({ bundleVersion: '1', jobId: '' }, 'd.json', null),                        // struct-fail
  ];
  const s = summarise(rows);
  assert.equal(s.total, 4);
  assert.equal(s.skipped, 1);
  assert.equal(s.checked, 3, 'checked excludes skipped non-bundles');
  assert.equal(s.drift, 1);
  assert.equal(s.structFail, 1);
});
