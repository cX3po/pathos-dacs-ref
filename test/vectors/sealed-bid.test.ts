/**
 * DACS-3 sealed-envelope SealedBid — commit / reveal conformance vectors
 *
 * Backs PR #10 (SealedBid body) and finding #19 (salt / commitment).
 *
 * Locks in:
 *   - commit → reveal round-trips (PASS) with a correct bid + salt
 *   - wrong salt FAILs reveal (binding to the salt)
 *   - mutated bid FAILs reveal (binding to the bid; even a one-character price change)
 *   - determinism: same bid + same salt → identical bidHash on every run
 *   - the salt floor (>= 128 bits) is enforced at commit time
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  commitSealedBid,
  verifyReveal,
  MIN_SALT_BYTES,
  type SealedBid,
} from '../../src/lib/sealed-bid.js';

/** A fixed 16-byte salt for deterministic vectors (NOT random — vectors must reproduce). */
const SALT_A = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
]);

/** A different 16-byte salt. */
const SALT_B = new Uint8Array([
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
]);

const BID: SealedBid = {
  price: { amount: '1000.00', currency: 'USDC', substrate: 'evm:8453' },
  deliverable: 'render 30s product video, 1080p',
  terms: { deadlineHours: 48, revisions: 2 },
};

test('commit → reveal round-trips with correct bid + salt (PASS)', () => {
  const commitment = commitSealedBid(BID, SALT_A);
  assert.equal(commitment.v, 'dacs-3-sealed-bid:0.1');
  assert.equal(typeof commitment.bidHash, 'string');
  assert.equal(commitment.bidHash.length, 64); // sha256 hex
  // Reveal against the full commitment object…
  assert.equal(verifyReveal(commitment, BID, SALT_A), true);
  // …and against the raw bidHash hex + hex salt.
  assert.equal(verifyReveal(commitment.bidHash, BID, commitment.saltHex), true);
});

test('wrong salt FAILs reveal (commitment is bound to the salt)', () => {
  const commitment = commitSealedBid(BID, SALT_A);
  assert.equal(verifyReveal(commitment, BID, SALT_B), false);
});

test('mutated bid FAILs reveal (even a one-character price change)', () => {
  const commitment = commitSealedBid(BID, SALT_A);
  const mutated: SealedBid = {
    ...BID,
    price: { ...BID.price, amount: '1000.01' }, // one cent higher
  };
  assert.equal(verifyReveal(commitment, mutated, SALT_A), false);

  // Mutating a nested term also breaks the reveal.
  const mutatedTerms: SealedBid = {
    ...BID,
    terms: { deadlineHours: 24, revisions: 2 },
  };
  assert.equal(verifyReveal(commitment, mutatedTerms, SALT_A), false);
});

test('determinism — same bid + same salt → identical bidHash', () => {
  const c1 = commitSealedBid(BID, SALT_A);
  const c2 = commitSealedBid(BID, SALT_A);
  assert.equal(c1.bidHash, c2.bidHash);

  // JCS key-order independence: a bid built with keys in a different order
  // canonicalizes identically and must produce the same commitment.
  const reordered: SealedBid = {
    terms: { revisions: 2, deadlineHours: 48 },
    deliverable: 'render 30s product video, 1080p',
    price: { substrate: 'evm:8453', currency: 'USDC', amount: '1000.00' },
  };
  const c3 = commitSealedBid(reordered, SALT_A);
  assert.equal(c3.bidHash, c1.bidHash);
});

test('salt floor — commit rejects salt shorter than 128 bits', () => {
  const shortSalt = new Uint8Array(MIN_SALT_BYTES - 1);
  assert.throws(() => commitSealedBid(BID, shortSalt), /salt too short/);
});

test('salt floor — verifyReveal rejects an under-length salt rather than hashing it', () => {
  // Manufacture a "commitment" the honest path could never emit, then confirm a
  // sub-floor salt is refused at verify time too (defense in depth for finding #19).
  const commitment = commitSealedBid(BID, SALT_A);
  const shortSaltHex = '00'.repeat(MIN_SALT_BYTES - 1);
  assert.equal(verifyReveal(commitment, BID, shortSaltHex), false);
});

test('malformed salt hex FAILs reveal without throwing', () => {
  const commitment = commitSealedBid(BID, SALT_A);
  assert.equal(verifyReveal(commitment, BID, 'zz-not-hex'), false);
});

test('sealed-bid commitment is NFC-stable — decomposed and precomposed deliverable hash identically (§7.2 CF-1)', () => {
  const pre: SealedBid = { ...BID, deliverable: 'caf\u00e9 promo' };   // precomposed
  const dec: SealedBid = { ...BID, deliverable: 'cafe\u0301 promo' };  // decomposed
  assert.notEqual('café promo', 'café promo'); // genuinely distinct inputs
  assert.equal(commitSealedBid(pre, SALT_A).bidHash, commitSealedBid(dec, SALT_A).bidHash);
});
