/**
 * Guards vectors/canonical-form/canonical-form-vectors.json as a STANDARD-FACING conformance set.
 * Verifies the COMMITTED artifact (not just the cases.ts builders), per the Codex retro-review:
 *  - committed accept `input` canonicalises to its committed expectedSha256 (no trust in cases.ts);
 *  - committed canonicalUtf8Hex is the real canonical bytes AND hashes to expectedSha256 (portable);
 *  - cases.ts and the committed JSON have EXACTLY the same vector ids (no extras/omissions, both ways);
 *  - sameHashAs equivalence holds (NFC=NFD value, key-order, NFC=NFD key);
 *  - the NFD vectors are not silently flattened to NFC in the JSON file (editor-proof byte check);
 *  - every committed reject vector is rejected by the canonicaliser FOR ITS STATED REASON (not just "throws").
 * If this fails, regenerate: npx tsx vectors/canonical-form/generate.mts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { jcsHashHex, jcsCanonical } from '../../src/jcs.js';
import { sha256 } from '@noble/hashes/sha2';
import { acceptCases, rejectCases, NFC_CAFE, NFD_CAFE } from '../../vectors/canonical-form/cases.js';

type AcceptVector = { id: string; input: unknown; canonicalUtf8Hex: string; expectedSha256: string; sameHashAs?: string };
type RejectVector = { id: string; reason: string };
const dir = dirname(fileURLToPath(import.meta.url));
const VPATH = join(dir, '../../vectors/canonical-form/canonical-form-vectors.json');
const rawJson = readFileSync(VPATH, 'utf8');
const vectors = JSON.parse(rawJson) as { acceptVectors: AcceptVector[]; rejectVectors: RejectVector[] };
const byId = new Map<string, AcceptVector>(vectors.acceptVectors.map((v) => [v.id, v]));
const toHex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');

// Reason -> the substring the canonicaliser's thrown message MUST contain (asserts the RIGHT rejection).
const REASON_MSG: Record<string, RegExp> = {
  'safe-integer-range': /safe-integer range/i,
  'unpaired-surrogate': /unpaired UTF-16 surrogate/i,
  'bigint-not-encodable': /BigInt is not JSON-encodable/, // specific msg, NOT the generic catch-all (tamper-path close)
  'nfc-key-collision': /NFC key collision/i,
};

test('vector id sets match cases.ts exactly (no extras / omissions, both directions)', () => {
  const caseAccept = acceptCases.map((c) => c.id).sort();
  const jsonAccept = vectors.acceptVectors.map((v) => v.id).sort();
  assert.deepEqual(caseAccept, jsonAccept, 'accept ids drift between cases.ts and committed JSON');
  const caseReject = rejectCases.map((c) => c.id).sort();
  const jsonReject = vectors.rejectVectors.map((v) => v.id).sort();
  assert.deepEqual(caseReject, jsonReject, 'reject ids drift between cases.ts and committed JSON');
});

test('COMMITTED accept input canonicalises to committed expectedSha256 (no trust in cases.ts)', () => {
  for (const v of vectors.acceptVectors) {
    assert.match(v.expectedSha256, /^[0-9a-f]{64}$/, `${v.id}: committed expectedSha256 not sha256 hex`);
    assert.equal(jcsHashHex(v.input), v.expectedSha256, `${v.id}: committed input does not canonicalise to committed expectedSha256`);
  }
});

test('COMMITTED canonicalUtf8Hex is the real canonical bytes AND hashes to expectedSha256 (portable form)', () => {
  for (const v of vectors.acceptVectors) {
    assert.match(v.canonicalUtf8Hex, /^([0-9a-f]{2})+$/, `${v.id}: canonicalUtf8Hex not hex`);
    // (a) our canonicaliser reproduces exactly these bytes from the committed input
    assert.equal(toHex(jcsCanonical(v.input)), v.canonicalUtf8Hex, `${v.id}: canonicalUtf8Hex != canonical(input) bytes`);
    // (b) the portable bytes hash to the committed expectedSha256 (consumer can verify without our impl)
    const bytes = Uint8Array.from((v.canonicalUtf8Hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
    assert.equal(toHex(sha256(bytes)), v.expectedSha256, `${v.id}: sha256(canonicalUtf8Hex) != expectedSha256`);
  }
});

test('cases.ts builders re-derive the committed hash (oracle round-trip)', () => {
  for (const c of acceptCases) {
    const v = byId.get(c.id)!;
    assert.equal(jcsHashHex(c.build()), v.expectedSha256, `${c.id}: builder hash drift vs committed vector`);
  }
});

test('sameHashAs cases hash identically (NFC=NFD value, key-order, NFC=NFD key)', () => {
  for (const v of vectors.acceptVectors) {
    if (!v.sameHashAs) continue;
    const ref = byId.get(v.sameHashAs);
    assert.ok(ref, `sameHashAs ref missing: ${v.sameHashAs}`);
    assert.equal(v.expectedSha256, ref!.expectedSha256, `${v.id} must hash == ${v.sameHashAs}`);
  }
});

test('the SPECIFIC NFD vectors are NOT silently flattened to NFC (per-vector editor-proof guard)', () => {
  // A generic "some vector is NFD" check is too weak: nfd-decomposed OR unicode-key-nfd could be
  // flattened individually while another vector keeps the suite NFD-positive, silently dropping the
  // value- or key-normalisation coverage (the hash + sameHashAs checks can't catch it — NFC/NFD hash
  // equal by design). Assert EACH intended NFD vector is genuinely NFD, separately for value and key.
  const nfdValue = byId.get('nfd-decomposed')!;
  const vs = JSON.stringify(nfdValue.input);
  assert.notEqual(vs, vs.normalize('NFC'), 'nfd-decomposed input must remain genuinely NFD (value normalisation coverage lost)');

  const nfdKey = byId.get('unicode-key-nfd')!;
  const key = Object.keys(nfdKey.input as Record<string, unknown>)[0]!;
  assert.notEqual(key, key.normalize('NFC'), 'unicode-key-nfd key must remain genuinely NFD (key normalisation coverage lost)');
  assert.equal(key.normalize('NFC'), 'café', 'unicode-key-nfd must NFC-normalise to café');
});

test('the NFC key-collision reject case is a genuine collision before it is rejected', () => {
  // Defend the reject case from silently degrading into a non-collision input: the builder must
  // produce two DISTINCT raw keys whose NFC forms are equal (that is what makes it ambiguous).
  const collision = rejectCases.find((c) => c.id === 'nfc-key-collision')!;
  // Inspect the source key pair via cases.ts's \u-escaped constants (editor-proof), not literal glyphs:
  // distinct raw strings (NFC precomposed vs NFD decomposed) that NFC-collide.
  assert.notEqual(NFC_CAFE, NFD_CAFE, 'collision keys must be distinct raw strings (NFC vs NFD)');
  assert.equal(NFC_CAFE.normalize('NFC'), NFD_CAFE.normalize('NFC'), 'collision keys must NFC-normalise to the same key');
  assert.throws(() => jcsCanonical(collision.build()), /NFC key collision/i);
});

test('committed reject vectors are rejected FOR THEIR STATED REASON (not just "throws")', () => {
  const caseById = new Map(rejectCases.map((c) => [c.id, c]));
  for (const rv of vectors.rejectVectors) {
    const c = caseById.get(rv.id);
    assert.ok(c, `committed reject vector ${rv.id} has no cases.ts builder`);
    assert.equal(c!.reason, rv.reason, `${rv.id}: reason drift cases.ts vs committed JSON`);
    const expected = REASON_MSG[rv.reason];
    assert.ok(expected, `${rv.id}: no message matcher for reason "${rv.reason}"`);
    assert.throws(() => jcsCanonical(c!.build()), expected, `${rv.id} must be rejected for reason ${rv.reason}`);
  }
});
