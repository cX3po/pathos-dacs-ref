/**
 * Guards vectors/os-string/os-string-vectors.json — the OS-string wire-grammar conformance set.
 * Verifies: every accept is canonical + round-trips; every reject is rejected by the STRICT grammar;
 * and the committed `bareBigIntAccepts` laxity flags match real BigInt() behaviour.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { STRICT_OS, acceptCases, rejectCases } from '../../vectors/os-string/cases.js';

type AcceptV = { id: string; s: string; roundTrips: boolean };
type RejectV = { id: string; s: string; reason: string; bareBigIntAccepts: boolean };
const dir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(dir, '../../vectors/os-string/os-string-vectors.json'), 'utf8'),
) as { grammar: string; acceptVectors: AcceptV[]; rejectVectors: RejectV[] };

const bareBigIntAccepts = (s: string): boolean => { try { BigInt(s); return true; } catch { return false; } };

test('vector id sets match cases.ts exactly (no drift)', () => {
  assert.deepEqual(acceptCases.map((c) => c.id).sort(), vectors.acceptVectors.map((v) => v.id).sort());
  assert.deepEqual(rejectCases.map((c) => c.id).sort(), vectors.rejectVectors.map((v) => v.id).sort());
});

test('committed grammar is the strict OS-string grammar', () => {
  assert.equal(vectors.grammar, STRICT_OS.source);
});

test('every ACCEPT vector is canonical AND round-trips (BigInt(s).toString() === s)', () => {
  for (const v of vectors.acceptVectors) {
    assert.ok(STRICT_OS.test(v.s), `${v.id}: "${v.s}" must match the strict grammar`);
    assert.equal(BigInt(v.s).toString(), v.s, `${v.id}: "${v.s}" must round-trip canonically`);
    assert.equal(v.roundTrips, true, `${v.id}: committed roundTrips flag wrong`);
  }
});

test('every REJECT vector is rejected by the STRICT grammar', () => {
  for (const v of vectors.rejectVectors) {
    assert.ok(!STRICT_OS.test(v.s), `${v.id}: "${v.s}" MUST be rejected by the strict OS-string grammar`);
  }
});

test('committed bareBigIntAccepts flags match real BigInt() behaviour (the laxity finding)', () => {
  for (const v of vectors.rejectVectors) {
    assert.equal(bareBigIntAccepts(v.s), v.bareBigIntAccepts,
      `${v.id}: "${v.s}" committed bareBigIntAccepts=${v.bareBigIntAccepts} disagrees with actual BigInt()`);
  }
  // The finding: bare BigInt (parseOsString) wrongly admits a majority of the non-canonical cases.
  const lax = vectors.rejectVectors.filter((v) => v.bareBigIntAccepts).length;
  assert.ok(lax >= 1, 'expected at least one bare-BigInt-accepted reject case (the conformance gap)');
});
