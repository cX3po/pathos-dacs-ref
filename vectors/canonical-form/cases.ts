/**
 * Canonical-form conformance vectors - shared case definitions.
 *
 * Oracle: src/jcs.ts (our RFC 8785 JCS + DACS section B.2 pre-pass implementation).
 * These cases are the foot-guns where two independent DACS implementations silently
 * compute DIFFERENT hashes/signatures for the "same" document. Any conforming SDK
 * MUST reproduce the accept-case hashes and MUST reject the reject-cases.
 *
 * Used by generate.mts (emits canonical-form-vectors.json with computed hashes) and
 * test/vectors/canonical-form.test.ts (re-derives + asserts, guarding the JSON).
 *
 * NOTE: all Unicode is built from explicit \u code points (never literal glyphs) so the
 * NFC-vs-NFD byte distinction is guaranteed in source and cannot be flattened by an editor.
 */

// cafe with precomposed e-acute (U+00E9) = NFC form.
export const NFC_CAFE = 'caf\u00e9';        // c a f + U+00E9
// cafe with e + combining acute accent (U+0301) = NFD form. MUST normalise to NFC_CAFE.
export const NFD_CAFE = 'cafe\u0301';       // c a f e + U+0301

export type AcceptCase = {
  id: string;
  description: string;
  build: () => unknown;
  /** if set, this case MUST hash identically to the referenced case id */
  sameHashAs?: string;
};

export type RejectCase = {
  id: string;
  description: string;
  build: () => unknown;
  reason: string;
};

/** Accept cases: input -> a single reproducible sha256(JCS canonical form). */
export const acceptCases: AcceptCase[] = [
  { id: 'ascii-basic', description: 'plain ASCII object', build: () => ({ a: 1, b: 'hello' }) },
  {
    id: 'key-ordering',
    description: 'keys supplied out of order hash identically (JCS sorts object keys)',
    build: () => ({ b: 'hello', a: 1 }),
    sameHashAs: 'ascii-basic',
  },
  { id: 'nfc-precomposed', description: 'string value: cafe with precomposed U+00E9 (NFC)', build: () => ({ name: NFC_CAFE }) },
  {
    id: 'nfd-decomposed',
    description: 'string value: cafe as e + U+0301 (NFD) - MUST hash identically to NFC after CF-1 normalisation',
    build: () => ({ name: NFD_CAFE }),
    sameHashAs: 'nfc-precomposed',
  },
  { id: 'unicode-key-nfc', description: 'object KEY in NFC form', build: () => ({ [NFC_CAFE]: 1 }) },
  {
    id: 'unicode-key-nfd',
    description: 'object KEY in NFD form - MUST hash identically to the NFC key (keys are NFC-normalised too, gap V2)',
    build: () => ({ [NFD_CAFE]: 1 }),
    sameHashAs: 'unicode-key-nfc',
  },
  { id: 'number-integer', description: 'integer value', build: () => ({ n: 42 }) },
  {
    id: 'safe-int-max',
    description: 'Number.MAX_SAFE_INTEGER (2^53-1 = 9007199254740991) is the LARGEST accepted integer (boundary)',
    build: () => ({ n: 9007199254740991 }),
  },
  { id: 'number-decimal', description: 'in-range decimal value', build: () => ({ n: 0.5 }) },
  // ── ECMAScript number serialisation (RFC 8785 §3.2.2.3) — the formatting foot-guns ──
  // NB: negative-zero is NOT a portable JSON vector (JSON cannot represent -0; it round-trips to 0),
  // so it lives ONLY in the external ES-number reference table in the test, where a real JS -0 is used.
  { id: 'number-small-exponent', description: 'small magnitude uses exponent form: 1e-7 -> "1e-7"', build: () => ({ n: 1e-7 }) },
  { id: 'number-shortest-roundtrip', description: 'shortest round-trip: 0.1+0.2 -> "0.30000000000000004" (not "0.3")', build: () => ({ n: 0.30000000000000004 }) },
  { id: 'number-decimal-tenth', description: 'decimal 0.1 -> "0.1" (no trailing/leading drift)', build: () => ({ n: 0.1 }) },
  { id: 'number-negative-fraction', description: 'negative fractional -> "-1.5"', build: () => ({ n: -1.5 }) },
  // ── string escaping (RFC 8785 §3.2.2.2) ──
  { id: 'string-control-char', description: 'control char U+0001 -> lowercase \\u0001 escape', build: () => ({ s: '\u0001' }) },
  { id: 'string-two-char-escapes', description: 'tab + newline use two-char escapes \\t \\n (not \\u0009)', build: () => ({ s: 'a\tb\nc' }) },
  { id: 'string-quote-backslash', description: 'quote and backslash escape as \\" and \\\\', build: () => ({ s: 'a"b\\c' }) },
  { id: 'string-emoji-nonbmp', description: 'non-BMP emoji (U+1F600, surrogate pair) passes through as raw UTF-8, NOT escaped', build: () => ({ s: '\u{1F600}' }) },
  // ── structural edge cases ──
  { id: 'empty-object', description: 'empty object -> {}', build: () => ({}) },
  { id: 'empty-array', description: 'empty array value -> {"a":[]}', build: () => ({ a: [] }) },
  { id: 'nested', description: 'nested object + array (array order preserved, object keys sorted)', build: () => ({ outer: { z: [3, 2, 1], a: true }, list: ['x', 'y'] }) },
  {
    id: 'key-ordering-nonascii',
    description: 'keys sorted by UTF-16 code unit: a < b < ä (U+00E4) — non-ASCII sorts AFTER ASCII',
    build: () => ({ b: 1, 'ä': 2, a: 3 }),
  },
];

/** Reject cases: a conforming canonicaliser MUST throw/reject (no reproducible canonical form). */
export const rejectCases: RejectCase[] = [
  {
    id: 'number-over-2pow53',
    // 9007199254740992 === 2^53 === MAX_SAFE_INTEGER+1: the FIRST integer outside the IEEE-754 safe
    // range, and (unlike 9007199254740993) it is exactly representable so there is no JS-rounding
    // ambiguity in the vector. NB: a JSON producer that emits the text "9007199254740993" will be read
    // back as this same value — both are unsafe and MUST be rejected. (Not "not JSON-representable".)
    description: 'integer === 2^53 (MAX_SAFE_INTEGER+1) is outside the IEEE-754 safe-integer range and MUST be rejected',
    build: () => ({ big: 9007199254740992 }),
    reason: 'safe-integer-range',
  },
  {
    id: 'number-large-magnitude-over-range',
    // Fable review + Codex precision note: the reject bound is on MAGNITUDE (abs > 2^53-1), applying to
    // every finite number. 1e300 is large and outside the safe range, so it rejects. (Note: in JS
    // Number.isInteger(1e300) is true — JS cannot faithfully represent a *fractional* value this large —
    // so this pins "large-magnitude number rejects", documenting the bound is not a literal integer test.)
    description: 'large-magnitude number outside the IEEE-754 safe range (1e300) MUST be rejected (bound is on magnitude)',
    build: () => ({ n: 1e300 }),
    reason: 'safe-integer-range',
  },
  {
    id: 'number-exponent-over-range',
    // DACS-SPECIFIC divergence from pure RFC 8785: vanilla JCS would ACCEPT 1e21 (it serialises to
    // "1e+21" per ECMAScript), but DACS §B.2's safe-integer bound rejects it. A pure-JCS impl that
    // forgets the DACS bound will accept this and silently diverge — that is exactly what this pins.
    description: '1e21 is valid RFC 8785 JCS but MUST be rejected under the DACS §B.2 safe-integer bound (deliberate DACS tightening)',
    build: () => ({ n: 1e21 }),
    reason: 'safe-integer-range',
  },
  { id: 'lone-surrogate', description: 'unpaired UTF-16 high surrogate has no valid UTF-8 encoding', build: () => ({ s: '\uD800' }), reason: 'unpaired-surrogate' },
  { id: 'bigint', description: 'BigInt is not JSON-encodable', build: () => ({ b: BigInt(1) }), reason: 'bigint-not-encodable' },
  {
    id: 'nfc-key-collision',
    description: 'two distinct keys that NFC-normalise to the same key (ambiguous canonical form)',
    build: () => {
      const o: Record<string, number> = {};
      o[NFC_CAFE] = 1;
      o[NFD_CAFE] = 2;
      return o;
    },
    reason: 'nfc-key-collision',
  },
];
