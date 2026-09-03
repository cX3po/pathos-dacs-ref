/**
 * RFC 8785 JSON Canonicalization Scheme (JCS)
 *
 * Used by DACS for every place a hash-stable canonical form is required:
 *   - DACS-1 Listing (§6.3.4) — JCS-canonical bytes are what gets anchored + size-capped at 16 KB
 *   - DACS-1 IdentityBundle (§6.3.2) — JCS-canonical of payload is what bundleHash hashes
 *   - DACS-2 VerifyResult, CompositeVerificationRecord (§7.5, §7.7) — JCS before signing
 *   - DACS-5 AttestationBundle (§10.4.1) — JCS before computing bundleHash and signing
 *
 * Implementation: thin wrapper around the `canonicalize` npm package (RFC 8785 implementation).
 *
 * Spec note: §14.6 universal signature scheme test vectors include canonicalization
 * round-trip tests. This module is the surface those vectors exercise.
 */
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha2';
const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 − 1
// Sentinel for values JSON serialisation omits (undefined / function / symbol).
// In an object they drop the property; in an array they become null — exactly
// as JSON.stringify / RFC 8785 do. We mirror that rather than passing such values
// through to the canonicalizer.
const OMIT = Symbol('jcs-omit');
// Unpaired UTF-16 surrogate: a high surrogate not followed by a low, or a low
// not preceded by a high. JSON.parse can produce these from \uXXXX escapes; they
// have no valid UTF-8 encoding, so the canonical form / hash is not reproducible.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
/** Reject any unpaired surrogate. Applies to values AND member names: a lone surrogate has
 *  no valid UTF-8 encoding either way, so the canonical form would not be reproducible. */
function surrogateSafe(s) {
    if (LONE_SURROGATE.test(s)) {
        throw new Error('JCS: string/key contains an unpaired UTF-16 surrogate (§7.2) — not a valid ' +
            'Unicode scalar sequence; no reproducible canonical form');
    }
    return s;
}
/** NFC-normalise a string VALUE (CF-1) and reject any unpaired surrogate.
 *
 *  Deliberately NOT applied to member names. CORE §B.2 CF-1 reads: "every JSON string
 *  VALUE in a signed or content-hashed DACS document MUST be Unicode-normalised to NFC."
 *  Member names are outside that scope, and RFC 8785 preserves them as received and sorts
 *  their raw UTF-16 code units. Normalising names here made `{"café":1}` (NFC) and
 *  `{"cafe\u0301":1}` (NFD) collapse to one canonical form when the Standard requires them
 *  to stay distinct — the divergence surfaced by the #270 cross-implementation run and
 *  classified upstream as a PATH-OS implementation defect. */
function nfcSafeValue(s) {
    return surrogateSafe(s.normalize('NFC'));
}
/**
 * §7.2 pre-canonical pass, applied identically by producers and verifiers before JCS:
 *  - CF-1 (Unicode normalisation): NFC-normalise every JSON string VALUE. Member names
 *    are left exactly as received: CF-1's scope is string values, and RFC 8785 sorts
 *    names by raw UTF-16 code units. RFC 8785 performs no normalisation at all, so
 *    without CF-1 on values a precomposed vs decomposed input yields a different
 *    canonical form / hash / signature.
 *  - Numeric safe-integer constraint: reject any JSON number outside the IEEE-754
 *    double safe-integer range (±2^53−1) — RFC 8785 has no reproducible canonical
 *    form for integers above 2^53−1; such quantities MUST be carried as a decimal
 *    string (or 0x-hex) rather than a bare number.
 */
function prepareForCanonical(value, toJsonHops = 0) {
    // Boxed primitives serialise as their primitive value (JSON.stringify semantics).
    if (value instanceof Number || value instanceof String || value instanceof Boolean || value instanceof BigInt) {
        value = value.valueOf();
    }
    // BigInt (bare or unwrapped from a boxed BigInt) is not JSON-encodable — reject, as
    // JSON.stringify does, so a large quantity can't slip through as a non-reproducible value.
    if (typeof value === 'bigint') {
        throw new Error('JCS: BigInt is not JSON-encodable (§7.2) — carry large quantities as a decimal or 0x-hex string');
    }
    // NOTE (accepted limitation): JSON.stringify passes the property key to toJSON(key);
    // we call toJSON() with no argument. Standard toJSON impls (Date, etc.) ignore the
    // argument, and DACS documents are parsed-JSON / plain objects with no key-aware
    // toJSON, so this does not affect any DACS canonicalisation surface.
    // Mirror JSON.stringify/RFC8785 toJSON handling so Date and other toJSON-bearing
    // objects serialise as they did before this pre-pass (don't regress them to {}).
    // Recurse on the result so a toJSON returning another toJSON-bearing object
    // (e.g. Wrapper -> Date) still resolves; hop-guard stops self-returning toJSON.
    if (value && typeof value === 'object' && typeof value.toJSON === 'function') {
        if (toJsonHops > 64) {
            throw new Error('JCS: toJSON chain too long — self-returning or mutually-recursive toJSON');
        }
        return prepareForCanonical(value.toJSON(), toJsonHops + 1);
    }
    // JSON omits these (object property dropped / array element → null).
    if (value === undefined || typeof value === 'function' || typeof value === 'symbol')
        return OMIT;
    if (typeof value === 'string')
        return nfcSafeValue(value);
    if (typeof value === 'number') {
        if (!Number.isFinite(value) || Math.abs(value) > MAX_SAFE) {
            throw new Error(`JCS: JSON number ${value} is outside the IEEE-754 safe-integer range (§7.2) — ` +
                `carry large quantities as a decimal or 0x-hex string`);
        }
        return value;
    }
    if (Array.isArray(value)) {
        // Array.from (not .map) so sparse holes are visited and become null, as JSON does.
        return Array.from(value, (el) => {
            const p = prepareForCanonical(el);
            return p === OMIT ? null : p;
        });
    }
    if (value && typeof value === 'object') {
        // null-proto so an own JSON key named "__proto__" is a real own property
        // (a plain {} would invoke the prototype setter and drop/poison it).
        const out = Object.create(null);
        for (const [k, v] of Object.entries(value)) {
            // Member names are validated but NOT normalised — see nfcSafeValue. Sorting is left
            // to RFC 8785 (Object.keys().sort(), i.e. raw UTF-16 code units), which is what the
            // Standard requires for names.
            const nk = surrogateSafe(k); // fail-closed on the name even if the value is omitted
            const pv = prepareForCanonical(v);
            if (pv === OMIT)
                continue; // undefined/function/symbol-valued property: omitted by JSON
            // No collision check is possible or needed now: names are used verbatim, and
            // Object.entries cannot yield the same own name twice. The previous NFC-collision
            // guard existed only because normalisation could fold two distinct names into one.
            out[nk] = pv;
        }
        return out;
    }
    return value; // null, boolean
}
/** Return JCS canonical UTF-8 bytes for any JSON value. Throws if input contains non-JSON-encodable values. */
export function jcsCanonical(value) {
    const prepared = prepareForCanonical(value);
    const canonical = canonicalize(prepared === OMIT ? undefined : prepared);
    if (canonical === undefined) {
        throw new Error('JCS canonicalization failed — input is not JSON-encodable');
    }
    return new TextEncoder().encode(canonical);
}
/** SHA-256 of JCS canonical bytes for a value. Returns 32-byte hash. */
export function jcsHash(value) {
    return sha256(jcsCanonical(value));
}
/** Hex-encoded SHA-256 of JCS canonical bytes — convenience for logs/receipts. */
export function jcsHashHex(value) {
    const h = jcsHash(value);
    return Array.from(h, (b) => b.toString(16).padStart(2, '0')).join('');
}
