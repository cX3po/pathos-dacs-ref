// RFC 8785 JSON Canonicalization Scheme (JCS) — DACS subset.
//
// DACS §7.1 ("Numeric safe-integer constraint") mandates that every JSON number
// in a signed or content-hashed document lie within the IEEE-754 double
// safe-integer range; any quantity that could exceed it (token IDs, uint256,
// large counters) MUST be carried as a decimal string, NOT a bare number. We
// therefore serialise numbers as safe integers only and THROW on any
// non-integer or out-of-range number. That throw is not a limitation — it is an
// active enforcement of §7.1, and it surfaces producers that violate it.

export function canonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return serializeNumber(v);
    case "string":
      return serializeString(v);
    case "object":
      return Array.isArray(v)
        ? serializeArray(v)
        : serializeObject(v as Record<string, unknown>);
    default:
      throw new Error(`JCS: unsupported value type "${typeof v}"`);
  }
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error("JCS: non-finite number");
  if (!Number.isInteger(n)) {
    throw new Error(
      `JCS(DACS §7.1): non-integer JSON number ${n} — carry it as a decimal string instead`,
    );
  }
  if (!Number.isSafeInteger(n)) {
    throw new Error(
      `JCS(DACS §7.1): integer ${n} is outside the IEEE-754 safe range — carry it as a decimal string`,
    );
  }
  // Safe integers (incl. -0 → "0") serialise identically under JCS.
  return String(n === 0 ? 0 : n);
}

function serializeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default: {
        const code = ch.codePointAt(0)!;
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += ch; // UTF-8 emitted verbatim per JCS (no \u for non-control)
        }
      }
    }
  }
  return out + '"';
}

function serializeArray(arr: unknown[]): string {
  return "[" + arr.map(serialize).join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>): string {
  // RFC 8785: object members ordered by UTF-16 code-unit value of the key.
  // JS string comparison already compares by UTF-16 code units.
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined) // JSON omits undefined-valued members
    .sort();
  return (
    "{" +
    keys.map((k) => serializeString(k) + ":" + serialize(obj[k])).join(",") +
    "}"
  );
}

/**
 * Returns a shallow clone of `doc` with the named signature field(s) removed —
 * the "signed scope" per DACS §7.2 ("the signed scope is all fields except the
 * signature field itself"). Use before computing a content hash for signing.
 */
export function withoutSignature<T extends Record<string, unknown>>(
  doc: T,
  ...fields: string[]
): Record<string, unknown> {
  const omit = new Set(fields.length ? fields : ["signature", "signatures"]);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc)) if (!omit.has(k)) out[k] = v;
  return out;
}
