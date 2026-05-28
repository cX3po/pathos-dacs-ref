/**
 * ed25519 sign/verify round-trip with domain separation
 *
 * Locks in:
 *   - Sign + verify with the same separator + key round-trips correctly
 *   - Sign with separator A + verify with separator B returns false (no cross-context replay)
 *   - Sign with bundleHash intermediate + verify without it returns false (no truncation attack)
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { sign, verify, generateKeypair } from '../../src/lib/sign.js';
import { sha256 } from '@noble/hashes/sha2';

test('round-trip — same separator + key verifies', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('hello, DACS');
  const sig = sign(DOMAIN_SEPARATORS.LISTING, body, privKey);
  assert.equal(verify(DOMAIN_SEPARATORS.LISTING, sig, body, pubKey), true);
});

test('cross-context replay protection — sign with LISTING, verify with AGREEMENT must fail', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('payload');
  const sig = sign(DOMAIN_SEPARATORS.LISTING, body, privKey);
  // Same body + same key but different separator MUST fail
  assert.equal(verify(DOMAIN_SEPARATORS.AGREEMENT, sig, body, pubKey), false);
});

test('intermediate hash — sign with bundleHash, verify without it must fail', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('{"v":"dacs-5-bundle:0.1","jobId":"abc"}');
  const bundleHash = sha256(body);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, body, privKey, bundleHash);
  // Verifying without the intermediate hash MUST fail (no truncation attack)
  assert.equal(verify(DOMAIN_SEPARATORS.BUNDLE_DACS5, sig, body, pubKey), false);
  // Verifying with the intermediate hash MUST pass
  assert.equal(verify(DOMAIN_SEPARATORS.BUNDLE_DACS5, sig, body, pubKey, bundleHash), true);
});

test('mutated body — even a single byte flip breaks verification', () => {
  const { privKey, pubKey } = generateKeypair();
  const body = new TextEncoder().encode('original');
  const sig = sign(DOMAIN_SEPARATORS.AGREEMENT, body, privKey);
  const tampered = new TextEncoder().encode('Original'); // O capitalized
  assert.equal(verify(DOMAIN_SEPARATORS.AGREEMENT, sig, tampered, pubKey), false);
});
