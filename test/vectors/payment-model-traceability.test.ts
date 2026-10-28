import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Offline CI exercises synthetic source integrity and behavioral misreading controls.
// The real Standard is supplied separately by the documented pinned checkout.
test('payment-model traceability synthetic negative controls', () => {
  const controls = spawnSync('python3', ['-m', 'unittest', 'discover', '-s', 'traceability/payment-model/tests', '-v'], { encoding: 'utf8' });
  assert.equal(controls.status, 0, String(controls.error || controls.stderr || controls.stdout));
});
