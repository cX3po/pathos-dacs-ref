// DACS Rule CD-1 (§8.5.1) — canonical decimal for PriceTerm.amount.
//
// RFC 8785 JCS canonicalises JSON *numbers* but preserves *string* bytes
// verbatim. PriceTerm.amount is a STRING, so two parties writing the same
// economic value differently ("1.50" vs "1.5") would otherwise produce
// different canonical bytes, hashes, and signatures. CD-1 forces a single
// minimal-digit form: no leading zeros (except a single 0 before the point),
// no trailing zeros after the point, "." as the only separator, no "+", no
// exponent. §14.4 worked cases: "1.50", "01.5", "1.500" all → "1.5".

export class CanonicalDecimalError extends Error {}

/**
 * Canonicalise a decimal string per CD-1. Throws CanonicalDecimalError on a
 * value that cannot be a conformant amount (exponent, sign, NaN/Infinity,
 * empty, non-numeric). Does NOT enforce positivity — see {@link assertPositive}.
 */
export function canonicalDecimal(raw: string): string {
  if (typeof raw !== "string") {
    throw new CanonicalDecimalError("amount must be a string");
  }
  const s = raw.trim();
  // Reject anything CD-1 forbids outright.
  if (s === "" || /[eE]/.test(s)) {
    throw new CanonicalDecimalError(`non-canonical/exponent amount: ${JSON.stringify(raw)}`);
  }
  if (!/^-?\d*\.?\d*$/.test(s) || !/\d/.test(s)) {
    throw new CanonicalDecimalError(`not a plain decimal: ${JSON.stringify(raw)}`);
  }
  const negative = s.startsWith("-");
  const body = negative ? s.slice(1) : s;

  let [intPart = "", fracPart = ""] = body.split(".");
  // Strip leading zeros from the integer part, keep a single 0.
  intPart = intPart.replace(/^0+/, "");
  if (intPart === "") intPart = "0";
  // Strip trailing zeros from the fractional part.
  fracPart = fracPart.replace(/0+$/, "");

  let out = fracPart ? `${intPart}.${fracPart}` : intPart;
  // Normalise "-0" → "0".
  if (negative && out !== "0") out = "-" + out;
  return out;
}

/** True iff `raw` is already in CD-1 canonical form (idempotent check). */
export function isCanonicalDecimal(raw: string): boolean {
  try {
    return canonicalDecimal(raw) === raw;
  } catch {
    return false;
  }
}

/**
 * DACS §9.3 PriceTerm.amount positivity (normative): amount MUST parse to a
 * finite value strictly greater than zero. Returns the canonical form.
 */
export function assertPositiveAmount(raw: string): string {
  const c = canonicalDecimal(raw);
  if (c.startsWith("-") || c === "0") {
    throw new CanonicalDecimalError(`PriceTerm.amount must be > 0 (§9.3): ${JSON.stringify(raw)}`);
  }
  return c;
}
