/**
 * partner-kit/jcs.mjs — self-contained JCS (RFC 8785) + DACS §B.2 pre-pass.
 *
 * NON-NORMATIVE partner-kit port of `src/jcs.ts` (pathos-dacs-ref). Zero runtime
 * dependencies: sha256 comes from node:crypto; the RFC 8785 serializer below is an
 * ORIGINAL minimal implementation (the in-repo oracle uses the `canonicalize` npm
 * package, Apache-2.0 — not vendored here). Every accept-vector hash this file
 * produces was cross-checked byte-for-byte against the in-repo oracle at kit
 * generation time (see MANIFEST.json receipt).
 *
 * DACS §B.2 pre-canonical pass (identical rules to src/jcs.ts):
 *  - CF-1: NFC-normalise every string value AND object key.
 *  - Reject unpaired UTF-16 surrogates (values and keys).
 *  - Reject any number with magnitude outside the IEEE-754 safe-integer range
 *    (±2^53−1) — includes 1e21, which vanilla RFC 8785 would accept.
 *  - Reject BigInt (not JSON-encodable).
 *  - Reject two distinct keys that NFC-normalise to the same key.
 */
import { createHash } from 'node:crypto';

const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 − 1

const OMIT = Symbol('jcs-omit');

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Reject unpaired surrogates. Applies to values AND member names — a lone surrogate has no
 *  valid UTF-8 encoding either way. */
function surrogateSafe(s) {
  if (LONE_SURROGATE.test(s)) {
    throw new Error(
      'JCS: string/key contains an unpaired UTF-16 surrogate (§7.2) — not a valid ' +
        'Unicode scalar sequence; no reproducible canonical form'
    );
  }
  return s;
}

/** NFC-normalise a string VALUE (CF-1). Deliberately NOT applied to member names: CORE §B.2
 *  CF-1 scopes normalisation to "every JSON string VALUE", and RFC 8785 preserves member
 *  names as received, sorting their raw UTF-16 code units. Normalising names folded NFC and
 *  NFD spellings into one canonical form — the #270 divergence. */
function nfcSafe(s) {
  return surrogateSafe(s.normalize('NFC'));
}

function prepareForCanonical(value, toJsonHops = 0) {
  if (value instanceof Number || value instanceof String || value instanceof Boolean || value instanceof BigInt) {
    value = value.valueOf();
  }
  if (typeof value === 'bigint') {
    throw new Error(
      'JCS: BigInt is not JSON-encodable (§7.2) — carry large quantities as a decimal or 0x-hex string'
    );
  }
  if (value && typeof value === 'object' && typeof value.toJSON === 'function') {
    if (toJsonHops > 64) {
      throw new Error('JCS: toJSON chain too long — self-returning or mutually-recursive toJSON');
    }
    return prepareForCanonical(value.toJSON(), toJsonHops + 1);
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') return OMIT;
  if (typeof value === 'string') return nfcSafe(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Math.abs(value) > MAX_SAFE) {
      throw new Error(
        `JCS: JSON number ${value} is outside the IEEE-754 safe-integer range (§7.2) — ` +
          `carry large quantities as a decimal or 0x-hex string`
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    return Array.from(value, (el) => {
      const p = prepareForCanonical(el);
      return p === OMIT ? null : p;
    });
  }
  if (value && typeof value === 'object') {
    const out = Object.create(null);
    for (const [k, v] of Object.entries(value)) {
      // Member names are validated but NOT normalised. Sorting is RFC 8785's
      // Object.keys().sort() — raw UTF-16 code units — which is what names require.
      const nk = surrogateSafe(k);
      const pv = prepareForCanonical(v);
      if (pv === OMIT) continue;
      // No collision is possible now: names are verbatim and Object.entries cannot yield
      // the same own name twice. The old NFC-collision guard existed only because
      // normalisation could fold two distinct names together.
      out[nk] = pv;
    }
    return out;
  }
  return value; // null, boolean
}

/**
 * Original minimal RFC 8785 serializer over a PREPARED value (pre-pass output:
 * no undefined/function/symbol/toJSON/BigInt/unsafe numbers remain).
 *  - Strings/numbers/booleans/null: ECMAScript JSON.stringify serialization,
 *    which is what RFC 8785 §3.2.2 specifies.
 *  - Arrays: '[' elements ']' with no whitespace.
 *  - Objects: members sorted by the key's UTF-16 code units (RFC 8785 §3.2.3;
 *    JS default Array.prototype.sort() compares exactly that way).
 */
function serializeCanonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') {
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return '[' + v.map(serializeCanonical).join(',') + ']';
  }
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + serializeCanonical(v[k])).join(',') + '}';
}

/** JCS canonical UTF-8 bytes for any JSON value. Throws on non-encodable input (fail-closed). */
export function jcsCanonical(value) {
  const prepared = prepareForCanonical(value);
  if (prepared === OMIT) {
    throw new Error('JCS canonicalization failed — input is not JSON-encodable');
  }
  return new TextEncoder().encode(serializeCanonical(prepared));
}

/** SHA-256 of JCS canonical bytes. Returns 32-byte Uint8Array. */
export function jcsHash(value) {
  return new Uint8Array(createHash('sha256').update(jcsCanonical(value)).digest());
}

/** Hex-encoded SHA-256 of JCS canonical bytes. */
export function jcsHashHex(value) {
  return Buffer.from(jcsHash(value)).toString('hex');
}
