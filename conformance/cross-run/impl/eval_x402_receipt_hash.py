#!/usr/bin/env python3
r"""
Independent reference evaluator for DACS-4 §9.5.7 rules X402-1..X402-4
(canonical x402 settlement-response hashing).

Set: x402-receipt-hash-v0.1
Impl: pathos-dacs-ref@cross-run-1

This is a from-spec implementation. It reads no answer key and contains no
per-vector special cases: `evaluate()` sees only the fields of one vector and
decides purely by applying the rule text below.

======================================================================
WHAT THIS IMPLEMENTS, AND THE SPEC LINES IT COMES FROM
======================================================================

--- X402-1 (versioned receipt selection) -----------------------------
DACS-4 §9.5.7:

  "(X402-1) Versioned receipt selection. For a success-outcome record,
   `protocolVersion` MUST be the negotiated x402 version as a minimal
   unsigned-decimal string. Version "1" selects `X-PAYMENT-RESPONSE`;
   version "2" selects `PAYMENT-RESPONSE`. The handler MUST base64-decode
   the selected header, parse its JSON as that version's
   `SettlementResponse`, require `success == true`, and retain every
   received member, including `extensions` and unrecognised members. A
   handler MUST refuse a protocol version whose settlement-response header
   or schema it does not implement."

Implemented as:
  * protocolVersion must be a string in minimal unsigned-decimal form
    (no sign, no leading zeros, digits only).
  * "1" -> required header name X-PAYMENT-RESPONSE
    "2" -> required header name PAYMENT-RESPONSE
    any other version -> refused (not implemented).
  * The supplied responseHeader.name must be the name the declared version
    selects. Header-name comparison is ASCII-case-insensitive (HTTP field
    names are case-insensitive, RFC 9110 §5.1); the *version->name* binding
    itself is exact.
  * base64-decode -> parse JSON -> top-level must be a JSON object ->
    `success` must be present and boolean and true.
  * EVERY received member is retained (no allow-listing, no stripping of
    `extensions` or unrecognised members). This mirrors CORE SIG-5
    preserve-unknown: "A verifier MAY ignore the *meaning* of unknown
    fields but MUST include their bytes in the hash."

--- X402-2 (canonical receipt hash) ----------------------------------
DACS-4 §9.5.7:

  "(X402-2) Canonical receipt hash. Before hashing, the handler MUST apply
   CORE §B.2 CF-1 to the complete X402-1 object. It MUST recursively
   NFC-normalise every JSON string value. It MUST then set
   `paymentReceiptHash = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))`,
   where `nfcSettlementResponse` is that normalised object and JCS is
   RFC 8785. The value MUST be exactly 64 lower-case hexadecimal digits
   without `0x`. The base64 header text, decoded non-canonical JSON bytes,
   an on-chain transaction receipt, and `settlementTxHash` alone are not
   conforming preimages."

CORE §B.2 CF-1:

  "Before computing the canonical form, every JSON string value in a signed
   or content-hashed DACS document MUST be Unicode-normalised to NFC."

So the exact pipeline this file implements is:

    obj   = json.loads(base64_decode(header.value))        # X402-1
    nfc   = recursive NFC(obj)                             # CF-1 / X402-2
    bytes = JCS(nfc) encoded UTF-8, no BOM                 # RFC 8785
    hash  = sha256(bytes).hexdigest()                      # lower-case hex,
                                                           # 64 chars, no 0x

JCS (RFC 8785) is implemented in full here rather than approximated with
json.dumps(sort_keys=True), because:
  * RFC 8785 §3.2.3 sorts object member names by their **UTF-16 code units**,
    not by Python code points (these differ above the BMP);
  * RFC 8785 §3.2.2.2 requires the ECMAScript JSON.stringify string escaping
    (only ", \, and C0 controls escaped; all other code points literal UTF-8);
  * RFC 8785 §3.2.2.3 requires the ECMAScript Number::toString serialisation.

--- X402-3 (receipt/evidence consistency) ----------------------------
DACS-4 §9.5.7:

  "(X402-3) Receipt/evidence consistency. A successful response's
   `transaction` MUST equal `settlementTxHash` when that field is recorded.
   Its `network` MUST map to `chainId` when that field is recorded: directly
   from v2 `eip155:{chainId}`, or through the registered v1 legacy-network
   mapping. A mismatch MUST reject the evidence; it MUST NOT be repaired by
   hashing a different receipt interpretation."

Implemented as:
  * If evidence.settlementTxHash is present: response["transaction"] must
    equal it as EVM transaction hashes. Equality uses the canonical EVM hash
    spelling of DACS-4 §9.5.8 SB-1 ("EVM hashes are rendered as exactly 64
    lower-case hexadecimal digits without `0x`; a verified legacy spelling
    with `0x` or upper-case characters collapses to that form"), i.e. strip
    an optional 0x prefix and lower-case, then compare. A value that is not
    64 hex digits after that collapse is malformed -> `error`.
  * If evidence.chainId is present:
      - v2: response["network"] MUST be exactly "eip155:<minimal-decimal
        chainId>". Anything else that still parses as eip155:<digits> but
        names a different chain is a mismatch. A network string that is not
        a well-formed eip155 CAIP-2 identifier is malformed -> `error`.
      - v1: response["network"] is a legacy network *name* resolved through
        the registered legacy-network mapping (see _V1_LEGACY_NETWORKS and
        the UNDERSPECIFICATION note below).

--- X402-4 (verification and invalid input) --------------------------
DACS-4 §9.5.7:

  "(X402-4) Verification and invalid input. A verifier presented with the
   response header MUST independently apply X402-1 and X402-2 and compare
   the resulting 32 bytes. Invalid base64, invalid JSON/schema, a non-success
   response, a non-canonical stored hash, or a hash mismatch MUST be
   rejected. A handler without the complete successful response object MUST
   NOT emit success-outcome `pay-x402` evidence."

======================================================================
VERDICT TAXONOMY: why a given rejection is `error` and not `fail`
======================================================================

X402-4 says all of its listed conditions "MUST be rejected" but does not
itself split them into `error` and `fail`. The split used here is taken from
the taxonomy the rest of the specification states explicitly:

  DACS-4 §9.5.8 SB-1: "A well-formed tuple mismatch is `fail` ... A malformed
  or non-canonical address ... is `error`."

  DACS-4 §9.5.8 SB-1: "a resolved index whose event does not match is `fail`;
  a missing, non-integer, negative, non-safe-integer, or otherwise malformed
  signed coordinate is `error`."

  DACS-4 §9.5.8 SB-1: "A reference that cannot produce this canonical form is
  malformed and yields `error`."

  DACS-2 §(verification outcome table): "malformed JSON/HTML/XML, parser
  exception -> `error` (verifier-side failure to obtain a decision, never
  `fail`)."

  DACS-1 DCR-4: "A malformed legacy hostname is `error`, not a new identity."

  CORE: "If a critical AP2, x402, ERC-8004, or A2A reference is unresolvable
  or ambiguous, the DACS result is `indeterminate` or `error`, never a
  borrowed `pass`."

Generalised rule applied here:

  error = the verifier cannot obtain a comparison at all — the input is not
          a processable, conforming X402-1 success object, or a value it must
          compare against is malformed / non-canonical.
  fail  = the verifier DID obtain a well-formed comparison and the comparison
          is negative (hash mismatch, transaction mismatch, network/chainId
          mismatch).
  pass  = X402-1, X402-2 and X402-3 all verify.

Concretely:
  error <- protocolVersion not a minimal unsigned decimal string
  error <- protocolVersion whose header/schema is not implemented (X402-1
           "A handler MUST refuse a protocol version ... it does not
           implement")
  error <- the header the declared version selects is not the header supplied
           (the required X402-1 input is absent; nothing can be decoded)
  error <- invalid base64 (X402-4 "Invalid base64")
  error <- invalid JSON, non-object top level, duplicate member names
           (X402-4 "invalid JSON/schema"; RFC 8785 §3.1 requires duplicate-free
           input)
  error <- `success` absent or not a boolean (invalid schema)
  error <- `success == false` (X402-4 "a non-success response"); X402-1 makes
           `success == true` a *precondition of the object being hashed at
           all*, so there is no conforming X402-2 preimage and therefore no
           hash comparison to lose — see the AMBIGUITY note below
  error <- a stored `paymentReceiptHash` that is not exactly 64 lower-case
           hex digits without 0x (X402-4 "a non-canonical stored hash";
           SB-1 "malformed ... yields `error`")
  error <- no stored hash recorded at all, so X402-4's "compare the resulting
           32 bytes" cannot be performed
  error <- a malformed `transaction` / `network` value that cannot be brought
           to canonical form for comparison
  fail  <- computed hash != stored paymentReceiptHash (X402-4 "a hash
           mismatch")
  fail  <- response.transaction != evidence.settlementTxHash (X402-3)
  fail  <- response.network does not map to evidence.chainId (X402-3)

======================================================================
UNDERSPECIFICATION / AMBIGUITY NOTES (flagged, not papered over)
======================================================================

(U1) The "registered v1 legacy-network mapping" referenced by X402-3 is NOT
     defined anywhere in the supplied normative text (CORE, DACS-1..DACS-4).
     X402-3 makes conformance depend on a registry the spec never publishes
     or points at by name/anchor. This evaluator carries a small table of the
     well-known x402 v1 network names as _V1_LEGACY_NETWORKS. Two
     implementations with different tables will disagree on v1 vectors.
     This is a real upstream finding.

(U2) RESOLVED 2026-08-28 — this note previously recorded an open ambiguity and
     chose the wrong side of it. It said the spec "does not say" whether member
     names are NFC-normalised, and this evaluator normalised BOTH names and
     values on the reasoning that leaving names alone would defeat CF-1's
     reproducibility purpose.

     The ambiguity is now settled and the answer is the other one. CF-1's scope
     is "every JSON string VALUE"; RFC 8785 §3.2.3 preserves member names as
     received and sorts them by raw UTF-16 code units. Upstream DACS-Standard
     PR #345 states this explicitly in scripts/jcs.py ("string values are
     NFC-normalised; object member names are serialised and UTF-16-sorted"),
     and it was one of the two divergences upstream's #270 triage attributed to
     PATH-OS. This evaluator no longer normalises member names.

     No vector in this set changes: as the original note observed, every member
     name here is ASCII, so the set never disambiguated. The change matters for
     correctness and cross-implementation agreement, not for these results.

(U3) X402-2 does not restate CORE §B.2's numeric safe-integer constraint for
     the settlement response, and RFC 8785 gives no canonical form for
     integers above 2^53-1. This evaluator treats an out-of-safe-range JSON
     number in the response as malformed -> `error`, per CORE §B.2. No vector
     in this set contains any JSON number inside the hashed object, so the
     ECMAScript Number::toString path is untested by this set.

(U4) X402-4's list ("Invalid base64, invalid JSON/schema, a non-success
     response, a non-canonical stored hash, or a hash mismatch") lumps
     unprocessable input together with a negative comparison under one verb,
     "MUST be rejected". The error/fail split above is inferred from the
     taxonomy used elsewhere in the spec, not stated in §9.5.7. The single
     genuinely arguable case is `success == false`: it is well-formed JSON
     and a reader does reach a definite conclusion, which would argue `fail`.
     It is classified `error` here because X402-1 makes `success == true` a
     precondition for the object ever entering the X402-2 preimage, so no
     conforming receipt hash exists to compare — the verifier never obtains
     the comparison that a `fail` verdict reports on. §9.5.7 should say which
     it is.

(U5) X402-1 binds a version to a header NAME but does not say what a verifier
     must do when a header of the *other* version's name is supplied. Treated
     here as "the selected header is absent" -> `error`.
"""

import base64
import binascii
import hashlib
import json
import re
import unicodedata

# ---------------------------------------------------------------------------
# X402-1: version -> settlement-response header name
# ---------------------------------------------------------------------------
# "Version "1" selects `X-PAYMENT-RESPONSE`; version "2" selects
# `PAYMENT-RESPONSE`."  Any other version is a version this implementation
# does not implement, and X402-1 requires it be refused.
_VERSION_HEADER = {
    "1": "X-PAYMENT-RESPONSE",
    "2": "PAYMENT-RESPONSE",
}

# ---------------------------------------------------------------------------
# X402-3: "the registered v1 legacy-network mapping".
# See UNDERSPECIFICATION note (U1) -- this registry is not published in the
# supplied normative text. These are the well-known x402 v1 EVM network names.
# ---------------------------------------------------------------------------
_V1_LEGACY_NETWORKS = {
    "base": 8453,
    "base-sepolia": 84532,
    "avalanche": 43114,
    "avalanche-fuji": 43113,
    "polygon": 137,
    "polygon-amoy": 80002,
    "sei": 1329,
    "sei-testnet": 1328,
    "iotex": 4689,
}

_MINIMAL_UNSIGNED_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_CANONICAL_HASH64 = re.compile(r"^[0-9a-f]{64}$")
_B64_STD = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_EIP155 = re.compile(r"^eip155:(0|[1-9][0-9]*)$")

_MAX_SAFE_INT = 2**53 - 1


class Malformed(Exception):
    """Input cannot be processed into a comparison -> verdict `error`."""


class Mismatch(Exception):
    """A well-formed comparison came out negative -> verdict `fail`."""


# ===========================================================================
# RFC 8785 (JCS) canonical serialisation
# ===========================================================================

# RFC 8785 §3.2.2.2 / ECMA-262 QuoteJSONString: escape only `"`, `\`, and the
# C0 controls; use the two-character escapes for \b \t \n \f \r and \u00xx
# (lower-case hex) for the remaining controls. Every other code point is
# emitted literally and encoded as UTF-8.
_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _jcs_string(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(n):
    """RFC 8785 §3.2.2.3: ECMAScript Number::toString.

    See note (U3): no vector in this set exercises this path.
    """
    if isinstance(n, int):
        if abs(n) > _MAX_SAFE_INT:
            # CORE §B.2 numeric safe-integer constraint: outside the IEEE-754
            # double safe-integer range there is no reproducible canonical
            # form. Readers SHOULD reject.
            raise Malformed("JSON number outside IEEE-754 safe-integer range")
        return str(n)
    # float
    if n != n or n in (float("inf"), float("-inf")):
        raise Malformed("non-finite JSON number")
    if n == 0:
        return "0"
    if float(n).is_integer() and abs(n) < 1e21:
        i = int(n)
        if abs(i) > _MAX_SAFE_INT:
            raise Malformed("JSON number outside IEEE-754 safe-integer range")
        return str(i)
    r = repr(float(n))  # shortest round-trip, as ECMAScript requires
    # Align Python's exponent spelling with ECMAScript's ("1e-07" -> "1e-7").
    if "e" in r:
        mant, exp = r.split("e")
        if mant.endswith(".0"):
            mant = mant[:-2]
        sign = "-" if exp.startswith("-") else "+"
        digits = exp.lstrip("+-").lstrip("0") or "0"
        r = "%se%s%s" % (mant, sign, digits)
    return r


def _utf16_key(s):
    """RFC 8785 §3.2.3: member names sort by their UTF-16 code units."""
    return s.encode("utf-16-be", "surrogatepass")


def jcs(value):
    """RFC 8785 canonical JSON serialisation, returned as a str."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise Malformed("value of unserialisable type in settlement response")


# ===========================================================================
# CORE §B.2 CF-1: recursive NFC normalisation
# ===========================================================================

def nfc_normalise(value):
    """Recursively NFC-normalise every JSON string VALUE.

    Member names are deliberately NOT normalised -- see note (U2), which records
    why this changed. CF-1's scope is string values; RFC 8785 preserves member
    names as received and sorts them by raw UTF-16 code units. Because names are
    used verbatim, two distinct names can no longer be folded into one, so the
    duplicate-after-normalisation check that used to live here is unreachable and
    has been removed rather than left as dead reassurance.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [nfc_normalise(v) for v in value]
    if isinstance(value, dict):
        return {k: nfc_normalise(v) for k, v in value.items()}
    return value


# ===========================================================================
# Helpers
# ===========================================================================

def _no_duplicate_pairs(pairs):
    """RFC 8785 §3.1 operates on duplicate-free JSON; Python would otherwise
    silently keep the last member and hash a document the sender did not send."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Malformed("duplicate member name in settlement response")
        seen.add(k)
    return dict(pairs)


def _b64decode_strict(text):
    """X402-4: 'Invalid base64 ... MUST be rejected'."""
    if not isinstance(text, str):
        raise Malformed("header value is not a string")
    if not _B64_STD.match(text):
        raise Malformed("header value is not valid base64")
    padded = text
    if len(padded) % 4 == 1:
        raise Malformed("header value is not valid base64 (bad length)")
    if len(padded) % 4:
        padded = padded + "=" * (4 - len(padded) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        raise Malformed("header value is not valid base64")


def _canonical_evm_hash(text, what):
    """DACS-4 §9.5.8 SB-1 canonical EVM hash spelling: exactly 64 lower-case
    hex digits without 0x; 'a verified legacy spelling with 0x or upper-case
    characters collapses to that form'."""
    if not isinstance(text, str):
        raise Malformed("%s is not a string" % what)
    t = text.lower()
    if t.startswith("0x"):
        t = t[2:]
    if not _CANONICAL_HASH64.match(t):
        raise Malformed("%s is not a well-formed EVM transaction hash" % what)
    return t


# ===========================================================================
# X402-1 .. X402-4
# ===========================================================================

def _x402_1_select_and_validate(vector):
    """X402-1: select the versioned header, decode, parse, require success."""
    version = vector.get("protocolVersion")
    if not isinstance(version, str) or not _MINIMAL_UNSIGNED_DECIMAL.match(version):
        # "protocolVersion MUST be the negotiated x402 version as a minimal
        # unsigned-decimal string"
        raise Malformed("protocolVersion is not a minimal unsigned-decimal string")
    expected_name = _VERSION_HEADER.get(version)
    if expected_name is None:
        # "A handler MUST refuse a protocol version whose settlement-response
        # header or schema it does not implement."
        raise Malformed("unimplemented x402 protocol version %r" % version)

    header = vector.get("responseHeader")
    if not isinstance(header, dict):
        raise Malformed("no settlement-response header supplied")
    name = header.get("name")
    if not isinstance(name, str):
        raise Malformed("settlement-response header has no name")
    # HTTP field names are case-insensitive (RFC 9110 §5.1); the version->name
    # binding itself is exact. See note (U5).
    if name.strip().upper() != expected_name:
        raise Malformed(
            "protocolVersion %r selects %s but %s was supplied"
            % (version, expected_name, name)
        )

    raw = _b64decode_strict(header.get("value"))

    # X402-4: "invalid JSON/schema ... MUST be rejected"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed("settlement response is not valid UTF-8")
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_pairs)
    except ValueError:
        raise Malformed("settlement response is not valid JSON")
    if not isinstance(obj, dict):
        raise Malformed("settlement response is not a JSON object")

    success = obj.get("success")
    if not isinstance(success, bool):
        raise Malformed("settlement response has no boolean `success` member")
    if success is not True:
        # X402-1 "require success == true"; X402-4 "a non-success response ...
        # MUST be rejected". See ambiguity note (U4).
        raise Malformed("settlement response is not a success response")

    # "retain every received member, including `extensions` and unrecognised
    # members" -- obj is returned whole, nothing is stripped.
    return version, obj


def _x402_2_receipt_hash(settlement_response):
    """X402-2:
        paymentReceiptHash = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))
    """
    nfc_obj = nfc_normalise(settlement_response)          # CORE §B.2 CF-1
    canonical = jcs(nfc_obj)                              # RFC 8785
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _x402_3_consistency(version, response, evidence):
    """X402-3: transaction == settlementTxHash; network maps to chainId."""
    tx_hash = evidence.get("settlementTxHash")
    if tx_hash is not None:
        # "A successful response's `transaction` MUST equal `settlementTxHash`
        # when that field is recorded."
        want = _canonical_evm_hash(tx_hash, "settlementTxHash")
        got = _canonical_evm_hash(response.get("transaction"), "response.transaction")
        if got != want:
            raise Mismatch("response.transaction does not equal settlementTxHash")

    chain_id = evidence.get("chainId")
    if chain_id is not None:
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
            # SB-1: chainId "MUST additionally be greater than zero" and be a
            # non-negative safe integer; malformed -> error.
            raise Malformed("chainId is not a positive integer")
        network = response.get("network")
        if not isinstance(network, str):
            raise Malformed("response.network is not a string")
        if version == "2":
            # "directly from v2 `eip155:{chainId}`"
            m = _EIP155.match(network)
            if not m:
                raise Malformed("v2 response.network is not a well-formed eip155 id")
            if int(m.group(1)) != chain_id:
                raise Mismatch("response.network does not map to chainId")
        else:
            # "or through the registered v1 legacy-network mapping" -- see (U1)
            mapped = _V1_LEGACY_NETWORKS.get(network)
            if mapped is None:
                raise Malformed(
                    "v1 response.network %r is not in the registered legacy-network "
                    "mapping" % network
                )
            if mapped != chain_id:
                raise Mismatch("response.network does not map to chainId")


def evaluate(vector):
    """Return exactly one of "pass", "fail", "error" for a single vector."""
    try:
        # X402-1
        version, response = _x402_1_select_and_validate(vector)

        # X402-2 -- actually computed, never stubbed.
        computed = _x402_2_receipt_hash(response)

        # X402-4: "compare the resulting 32 bytes"
        evidence = vector.get("evidence")
        if not isinstance(evidence, dict) or "paymentReceiptHash" not in evidence:
            raise Malformed("no stored paymentReceiptHash to compare against")
        stored = evidence.get("paymentReceiptHash")
        if not isinstance(stored, str) or not _CANONICAL_HASH64.match(stored):
            # X402-2: "exactly 64 lower-case hexadecimal digits without `0x`";
            # X402-4: "a non-canonical stored hash ... MUST be rejected".
            raise Malformed("stored paymentReceiptHash is not canonical")
        if computed != stored:
            raise Mismatch("computed receipt hash does not equal stored hash")

        # X402-3
        _x402_3_consistency(version, response, evidence)

        return "pass"
    except Mismatch:
        return "fail"
    except Malformed:
        return "error"


# ===========================================================================
# Runner
# ===========================================================================

def main():
    import argparse
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors",
                    default=os.path.join(root, "blind", "x402-receipt-hash-v0.1.json"))
    ap.add_argument("--out",
                    default=os.path.join(root, "runs",
                                         "run-pathos-x402-receipt-hash-v0.1.json"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    with open(args.vectors, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    results = []
    for vec in doc["vectors"]:
        verdict = evaluate(vec)
        results.append({"name": vec["name"], "verdict": verdict})
        if args.verbose:
            detail = ""
            try:
                _v, resp = _x402_1_select_and_validate(vec)
                detail = "computed=%s" % _x402_2_receipt_hash(resp)
                stored = (vec.get("evidence") or {}).get("paymentReceiptHash")
                if stored:
                    detail += " stored=%s" % stored
            except Malformed as exc:
                detail = "malformed: %s" % exc
            print("%-46s %-6s %s" % (vec["name"], verdict, detail))

    out = {
        "set": doc.get("set", "x402-receipt-hash-v0.1"),
        "impl": "pathos-dacs-ref@cross-run-1",
        "results": results,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("wrote %s" % args.out)
    print("distribution: %s" % counts)


if __name__ == "__main__":
    main()
