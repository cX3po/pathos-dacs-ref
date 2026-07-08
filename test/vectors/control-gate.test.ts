/**
 * control-gate.test.ts — DACS-1 §6.3.2 step-6 control-gate unit vectors.
 *
 * The #170 golden (control-gate-vectors.json) covers pass/fail/indeterminate; these pin the
 * §7.5.1 do-not-collapse corners the golden does NOT exercise — specifically that a resolver
 * `error` propagates as `error` (never collapses to a definite `fail`), across each control
 * path (required-claim gate, BR-5 selector, key holder-binding, cci-xm linkage).
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { classifyControlGate, type ControlGateInput } from '../../src/lib/control-gate.js';

const NOW = 1_780_000_000_000;

test('resolver error on a REQUIRED claim → error (not fail) — do-not-collapse §7.5.1', () => {
  const input: ControlGateInput = {
    bundle: { presentedBy: 'key:0xabc', claims: [{ ref: 'lei:X', verifiedBy: 'r1' }] },
    requirement: { required: [{ scheme: 'lei', verificationRequired: true }] },
    resolver: { r1: { decision: 'error', errorClass: 'transient' } },
    controlledUse: false,
  };
  const r = classifyControlGate(input, NOW);
  assert.equal(r.decision, 'error');
  assert.equal(r.threw, false);
});

test('resolver error on the KEY control binding (no presentation) → error, not fail', () => {
  const input: ControlGateInput = {
    bundle: { presentedBy: 'key:0xabc', claims: [{ ref: 'key:0xabc', verifiedBy: 'kb' }] },
    resolver: { kb: { decision: 'error', bindingClass: 'control', errorClass: 'permanent' } },
    controlledUse: true,
  };
  assert.equal(classifyControlGate(input, NOW).decision, 'error');
});

test('resolver error on the BR-5 presentedBy verification → error, not fail', () => {
  const input: ControlGateInput = {
    bundle: { presentedBy: 'key:0xabc', claims: [{ ref: 'key:0xabc', verifiedBy: 'v' }] },
    requirement: { required: [{ scheme: 'key', verificationRequired: true }], primaryClaimSelector: 'key' },
    resolver: { v: { decision: 'error' } },
    controlledUse: true,
  };
  assert.equal(classifyControlGate(input, NOW).decision, 'error');
});

test('resolver error on a cci-xm control linkage → error, not fail', () => {
  const input: ControlGateInput = {
    bundle: { presentedBy: 'cci-xm:did:demos:x', claims: [{ ref: 'cci-xm:did:demos:x', verifiedBy: 'link' }] },
    resolver: { link: { decision: 'error' } },
    controlledUse: true,
  };
  assert.equal(classifyControlGate(input, NOW).decision, 'error');
});

test('resolver FAIL (not error) on a control binding still → fail (a definite no-control is not do-not-collapse)', () => {
  const input: ControlGateInput = {
    bundle: { presentedBy: 'key:0xabc', claims: [{ ref: 'key:0xabc', verifiedBy: 'kb' }] },
    resolver: { kb: { decision: 'fail', bindingClass: 'control' } },
    controlledUse: true,
  };
  assert.equal(classifyControlGate(input, NOW).decision, 'fail');
});
