/**
 * OS-string wire-grammar conformance vectors — shared case definitions.
 *
 * Demos carries OS amounts (the smallest DEM denomination) as DECIMAL STRINGS on the wire (v3
 * osDenomination migration: bigint internal, canonical OS-string on the wire). The canonical writer
 * is `toOsString(os) = os.toString()`, and `demToOs` rejects negatives — so the canonical image is:
 *
 *     OS-string  ::=  "0" | [1-9][0-9]*            (non-negative, no leading zeros, no sign/space/prefix/fraction)
 *
 * The conformance risk: a permissive READER that accepts more than the writer EMITS makes
 * `toOsString(parseOsString(s)) !== s` for non-canonical `s` — two impls then disagree on what a
 * valid wire amount is, and a re-serialize silently changes the bytes (→ hash/signature drift).
 * `@kynesyslabs/demosdk` v4.0.8 `parseOsString` is bare `BigInt(s)` (src/denomination/conversion.ts), which
 * admits inputs outside the canonical grammar — `""`, leading `+`, whitespace, `0x`/`0b`/`0o` prefixes,
 * and leading zeros — none of which the writer emits.
 *
 * These vectors define the strict grammar + a MUST-REJECT set so any impl can verify its reader
 * matches its writer. `bareBigIntAccepts` flags the cases bare `BigInt()` admits outside the canonical grammar.
 */

/** The canonical OS-string grammar: non-negative decimal, no leading zeros, nothing else. */
export const STRICT_OS = /^(0|[1-9][0-9]*)$/;

export type AcceptCase = { id: string; s: string; description: string };
export type RejectCase = { id: string; s: string; reason: string; bareBigIntAccepts: boolean };

/** Accept: canonical OS-strings. Each MUST round-trip: BigInt(s).toString() === s. */
export const acceptCases: AcceptCase[] = [
  { id: 'zero', s: '0', description: 'zero is the only string with a leading 0' },
  { id: 'one', s: '1', description: 'small value' },
  { id: 'nine', s: '9', description: 'single digit' },
  { id: 'one-dem', s: '1000000000', description: '1 DEM = 1e9 OS (OS_DECIMALS=9)' },
  { id: 'large', s: '123456789012345678901234567890', description: 'big integer (bigint, beyond 2^53)' },
];

/** Reject: every non-canonical string a strict OS-string reader MUST reject. */
export const rejectCases: RejectCase[] = [
  { id: 'empty',         s: '',        reason: 'empty string is not a number', bareBigIntAccepts: true },
  { id: 'whitespace',    s: ' 42 ',    reason: 'surrounding whitespace is not canonical', bareBigIntAccepts: true },
  { id: 'space-only',    s: '   ',     reason: 'whitespace-only', bareBigIntAccepts: true },
  { id: 'leading-plus',  s: '+5',      reason: 'explicit + sign is not canonical', bareBigIntAccepts: true },
  { id: 'hex',           s: '0x1f',    reason: 'hex prefix — radix ambiguity', bareBigIntAccepts: true },
  { id: 'binary',        s: '0b101',   reason: 'binary prefix — radix ambiguity', bareBigIntAccepts: true },
  { id: 'octal',         s: '0o17',    reason: 'octal prefix — radix ambiguity', bareBigIntAccepts: true },
  { id: 'leading-zeros', s: '007',     reason: 'leading zeros — non-canonical encoding of 7', bareBigIntAccepts: true },
  { id: 'negative',      s: '-5',      reason: 'OS amounts are non-negative (demToOs throws on negatives)', bareBigIntAccepts: true },
  { id: 'neg-zero',      s: '-0',      reason: 'a SECOND byte-distinct encoding of zero on a money field (canonical zero is "0")', bareBigIntAccepts: true },
  { id: 'upper-hex',     s: '0X1F',    reason: 'uppercase 0X radix prefix — radix ambiguity', bareBigIntAccepts: true },
  { id: 'newline-trim',  s: '\n42',    reason: 'leading newline (BigInt trims ASCII whitespace incl \\n)', bareBigIntAccepts: true },
  { id: 'fractional',    s: '1.5',     reason: 'OS is an integer denomination — no fraction', bareBigIntAccepts: false },
  { id: 'exponent',      s: '1e3',     reason: 'exponent notation is not canonical', bareBigIntAccepts: false },
  { id: 'separator',     s: '1_000',   reason: 'numeric separators are not wire-canonical', bareBigIntAccepts: false },
  { id: 'non-numeric',   s: 'abc',     reason: 'not a number', bareBigIntAccepts: false },
];
