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
