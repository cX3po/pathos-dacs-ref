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
  { id: 'number-decimal', description: 'in-range decimal value', build: () => ({ n: 0.5 }) },
  { id: 'nested', description: 'nested object + array (array order preserved, object keys sorted)', build: () => ({ outer: { z: [3, 2, 1], a: true }, list: ['x', 'y'] }) },
];

/** Reject cases: a conforming canonicaliser MUST throw/reject (no reproducible canonical form). */
export const rejectCases: RejectCase[] = [
  { id: 'number-over-2pow53', description: 'integer above 2^53-1 has no reproducible JCS form; carry as a string', build: () => ({ big: 9007199254740993 }), reason: 'safe-integer-range' },
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
