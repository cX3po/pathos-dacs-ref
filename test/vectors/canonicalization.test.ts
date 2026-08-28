/**
 * JCS canonicalization round-trip tests
 *
 * Vector source: RFC 8785 Appendix A test vectors + DACS §14.6 spec round-trip cases.
 *
 * v0.1 skeleton: validates the `canonicalize` npm package handles the canonical
 * cases. Deeper coverage (e.g. unicode, deeply nested, BigInt rejection) lands in v0.2.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';

test('JCS — RFC 8785 §3.2.3 example: sort object keys lexicographically by UTF-16 code unit', () => {
  const input = { z: 1, a: 2, m: 3 };
  const bytes = jcsCanonical(input);
  const text = new TextDecoder().decode(bytes);
  assert.equal(text, '{"a":2,"m":3,"z":1}');
});

test('JCS — strings preserve UTF-8 encoding for non-ASCII', () => {
  const input = { name: 'café' };
  const bytes = jcsCanonical(input);
  const text = new TextDecoder().decode(bytes);
  assert.equal(text, '{"name":"café"}');
});

test('JCS — nested objects canonicalize recursively', () => {
  const input = { outer: { z: 1, a: 2 }, alpha: { beta: 3 } };
  const bytes = jcsCanonical(input);
  const text = new TextDecoder().decode(bytes);
  assert.equal(text, '{"alpha":{"beta":3},"outer":{"a":2,"z":1}}');
});

test('JCS — arrays preserve insertion order (no sort)', () => {
  const input = { items: [3, 1, 2] };
  const bytes = jcsCanonical(input);
  const text = new TextDecoder().decode(bytes);
  assert.equal(text, '{"items":[3,1,2]}');
});

test('JCS — same input always yields same hash (idempotent)', () => {
  const input = { a: 1, b: 2, c: { d: 4, e: [5, 6] } };
  const h1 = jcsHashHex(input);
  const h2 = jcsHashHex({ c: { e: [5, 6], d: 4 }, b: 2, a: 1 }); // same structure, different declaration order
  assert.equal(h1, h2, 'JCS hash MUST be invariant under key reordering');
});

// --- 7.2 conformance: CF-1 NFC normalisation + numeric safe-integer constraint (2026-06-03) ---
// Strings from explicit code points so decomposed vs precomposed are genuinely distinct.

const CAFE_PRE = 'caf\u00e9';      // precomposed e-acute (U+00E9)
const CAFE_DEC = 'cafe\u0301';     // decomposed e + combining acute (U+0301)

test('CF-1 - decomposed and precomposed strings hash identically (NFC)', () => {
  assert.equal(jcsHashHex({ v: CAFE_PRE }), jcsHashHex({ v: CAFE_DEC }));
});

test('CF-1 does NOT apply to member names - NFC and NFD names hash differently', () => {
  // CORE §B.2 CF-1 scopes normalisation to "every JSON string VALUE"; RFC 8785 preserves
  // member names as received. Normalising names made these two collapse into one canonical
  // form — the #270 divergence, classified upstream as a PATH-OS implementation defect.
  const a: Record<string, number> = {}; a[CAFE_PRE] = 1;
  const b: Record<string, number> = {}; b[CAFE_DEC] = 1;
  assert.notEqual(jcsHashHex(a), jcsHashHex(b));
});

test('an NFC/NFD member-name pair canonicalises to two members, not a rejection', () => {
  // Was: 'CF-1 - NFC key collision is rejected'. With names preserved they never collide.
  const o: Record<string, number> = {}; o[CAFE_PRE] = 1; o[CAFE_DEC] = 2;
  assert.equal(Object.keys(o).length, 2);
  const bytes = jcsCanonical(o);
  const text = new TextDecoder().decode(bytes);
  assert.ok(text.includes(CAFE_PRE), 'precomposed name must survive verbatim');
  assert.ok(text.includes(CAFE_DEC), 'decomposed name must survive verbatim');
});

test('member-name sort is raw UTF-16 code units, not normalised order', () => {
  // RFC 8785 sorts names by their raw UTF-16 code units. Guard that we did not reintroduce
  // a normalise-then-sort step, which would reorder non-ASCII names.
  const o: Record<string, number> = { b: 1, 'ä': 2, a: 3 };
  const text = new TextDecoder().decode(jcsCanonical(o));
  const order = [...text.matchAll(/"((?:[^"\\]|\\.)*)":/g)].map((m) => m[1]);
  assert.deepEqual(order, [...order].sort(), 'names must be in raw UTF-16 code-unit order');
});

test('an omitted-value member name leaves no ghost; its NFD twin survives verbatim', () => {
  // Was framed as "no false collision with its NFC twin" — collisions are impossible now
  // that member names are preserved. What still matters: the omitted precomposed name must
  // not appear, and the surviving decomposed name must come through byte-for-byte.
  const o: Record<string, unknown> = {}; o[CAFE_PRE] = undefined; o[CAFE_DEC] = 1;
  const text = new TextDecoder().decode(jcsCanonical(o));
  assert.equal(text, `{"${CAFE_DEC}":1}`, 'the decomposed name survives exactly as received');
  assert.ok(!text.includes(CAFE_PRE), 'the omitted precomposed name must not appear');
});

test('7.2 - JSON number above 2^53-1 is rejected', () => {
  assert.throws(() => jcsCanonical({ tokenId: 9007199254740993 }), /safe-integer range/);
});

test('7.2 - safe-integer boundary (2^53-1) is accepted', () => {
  assert.equal(new TextDecoder().decode(jcsCanonical({ n: 9007199254740991 })), '{"n":9007199254740991}');
});

test('7.2 - fractional number within range is allowed', () => {
  assert.equal(new TextDecoder().decode(jcsCanonical({ p: 1.5 })), '{"p":1.5}');
});

test('7.2 - an own __proto__ key (from parsed JSON) is preserved, not dropped or poisoned', () => {
  const parsed = JSON.parse('{"__proto__":1,"a":2}');
  assert.ok(Object.prototype.hasOwnProperty.call(parsed, '__proto__'));
  const text = new TextDecoder().decode(jcsCanonical(parsed));
  assert.ok(text.includes('__proto__'), 'the __proto__ key must survive into the canonical form');
  assert.equal(Object.getPrototypeOf({}), Object.prototype, 'global prototype must be untouched');
});

test('toJSON-bearing objects (Date) serialise via toJSON, not as {}', () => {
  const d = new Date('2026-06-03T00:00:00.000Z');
  assert.equal(new TextDecoder().decode(jcsCanonical({ when: d })), '{"when":"2026-06-03T00:00:00.000Z"}');
});

test('toJSON returning another toJSON-bearing object (Wrapper -> Date) resolves fully', () => {
  class Wrapper { toJSON() { return new Date('2026-06-03T00:00:00.000Z'); } }
  assert.equal(new TextDecoder().decode(jcsCanonical({ w: new Wrapper() })), '{"w":"2026-06-03T00:00:00.000Z"}');
});

test('self-returning toJSON is rejected (hop guard), not infinite loop', () => {
  const evil: { toJSON: () => unknown } = { toJSON() { return evil; } };
  assert.throws(() => jcsCanonical({ x: evil }), /toJSON chain too long/);
});

test('JSON value-omission mirrored — function/symbol/undefined array elements become null', () => {
  const arr = [1, undefined, function () {}, Symbol('s'), 'x'];
  assert.equal(new TextDecoder().decode(jcsCanonical({ a: arr })), '{"a":[1,null,null,null,"x"]}');
});

test('JSON value-omission mirrored — sparse array holes become null', () => {
  const sparse = [1, , 3]; // eslint-disable-line no-sparse-arrays
  assert.equal(new TextDecoder().decode(jcsCanonical({ s: sparse })), '{"s":[1,null,3]}');
});

test('toJSON returning undefined omits the property; the twin name survives verbatim', () => {
  const o: Record<string, unknown> = {};
  o[CAFE_PRE] = { toJSON() { return undefined; } };
  o[CAFE_DEC] = 1;
  const text = new TextDecoder().decode(jcsCanonical(o));
  assert.equal(text, `{"${CAFE_DEC}":1}`);
  assert.ok(!text.includes(CAFE_PRE), 'the toJSON-omitted precomposed name must not appear');
});

test('boxed primitives serialise as their primitive value (JSON.stringify parity)', () => {
  const input = { n: new Number(3), s: new String('x'), b: new Boolean(true) };
  assert.equal(new TextDecoder().decode(jcsCanonical(input)), '{"b":true,"n":3,"s":"x"}');
});

test('7.2 - lone UTF-16 surrogate (from parsed JSON) is rejected', () => {
  const high = JSON.parse('{"s":"\\ud800"}');       // lone high surrogate
  const low = JSON.parse('{"s":"\\udc00"}');        // lone low surrogate
  assert.throws(() => jcsCanonical(high), /unpaired UTF-16 surrogate/);
  assert.throws(() => jcsCanonical(low), /unpaired UTF-16 surrogate/);
});

test('7.2 - lone surrogate in an object KEY is rejected', () => {
  const o = JSON.parse('{"\\ud800":1}');
  assert.throws(() => jcsCanonical(o), /unpaired UTF-16 surrogate/);
});

test('7.2 - valid surrogate pair (astral char) is accepted', () => {
  const o = JSON.parse('{"s":"\\ud83d\\ude80"}');   // U+1F680 rocket
  assert.doesNotThrow(() => jcsCanonical(o));
});

test('7.2 - lone surrogate in a key is rejected even when the value is omitted (fail-closed)', () => {
  const o: Record<string, unknown> = {}; o['\ud800'] = undefined;
  assert.throws(() => jcsCanonical(o), /unpaired UTF-16 surrogate/);
});

test('7.2 - BigInt (bare and boxed) is rejected, not silently serialised', () => {
  assert.throws(() => jcsCanonical({ n: 1n }), /BigInt is not JSON-encodable/);
  assert.throws(() => jcsCanonical({ n: Object(1n) }), /BigInt is not JSON-encodable/);
});
