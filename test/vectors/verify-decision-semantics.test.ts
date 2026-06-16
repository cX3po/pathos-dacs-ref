/**
 * DACS-2 §7.5.1 — VerifyResult decision semantics (the four-value contract)
 *
 * Locks in the 2026-06-15 conformance fix: the spec's §7.5.1 enumerates FOUR decision
 * values — pass | fail | indeterminate | error — and they MUST NOT collapse. Before the
 * fix our type carried only three and the vet path overloaded `indeterminate` for
 * verifier-side failures (transport/parse), which §7.5.1 classifies as `error`.
 *
 * error vs indeterminate (§7.5.1): `error` = verification could not complete (the verifier
 * never received an authority decision); `indeterminate` = the authority answered, parseably,
 * but non-binary. Consumers MUST NOT treat indeterminate, error, or fail as pass.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  isPass, isFail, isIndeterminate, isError,
  type VerifyDecision,
} from '../../src/types/index.js';

const ALL: VerifyDecision[] = ['pass', 'fail', 'indeterminate', 'error'];

test('§7.5.1 enumerates exactly four decision values, error included', () => {
  // Type-level: each value is assignable to VerifyDecision (compile-time), and the
  // runtime guards partition them exhaustively with no overlap.
  for (const d of ALL) {
    const hits = [isPass(d), isFail(d), isIndeterminate(d), isError(d)].filter(Boolean);
    assert.equal(hits.length, 1, `${d} must match exactly one guard`);
  }
});

test('error and indeterminate are distinct (MUST NOT collapse)', () => {
  assert.equal(isError('error'), true);
  assert.equal(isIndeterminate('error'), false, 'error is not indeterminate');
  assert.equal(isError('indeterminate'), false, 'indeterminate is not error');
});

test('no non-pass decision is ever pass (§7.5.1 aggregation invariant)', () => {
  for (const d of ['fail', 'indeterminate', 'error'] as VerifyDecision[]) {
    assert.equal(isPass(d), false, `${d} MUST NOT read as pass`);
  }
});
