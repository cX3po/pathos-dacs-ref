#!/usr/bin/env python3
"""Independent reference evaluator for DACS CORE §B.7 (SIG-6) — canonical signature value.

This is an INDEPENDENT second implementation written from the normative text alone.
No expected verdicts were consulted. Every branch below cites the sentence that
forces it.

Normative source: spec/CORE.md, §B.7 "Signature-value wire encoding" (lines
404-449) and the conformance clause (SIG-6) at line 458:

    (SIG-6) Canonical signature value. Producers and verifiers MUST apply the
    unpadded Base64URL wire encoding, canonicality check, algorithm-specific
    validation, and legacy-import boundary defined above.

SIG-6 decomposes into four distinct obligations. Each is a separate check here.

--- Obligation 1: the wire encoding (CORE.md:404-414) ---------------------------
  "The field MUST encode the raw signature bytes as RFC 4648 §5 Base64URL, using
   the URL-safe `-` and `_` alphabet and omitting all `=` padding"
       signature_value := base64url(signature_bytes).remove_trailing("=")
  "The canonical string is non-empty and contains only A-Z, a-z, 0-9, -, and _."
  -> _WIRE_ALPHABET below; empty string rejected.

--- Obligation 2: the canonicality check (CORE.md:416-422) ----------------------
  "A verifier MUST reject padding, whitespace, the standard-Base64 `+` or `/`
   characters, impossible lengths, invalid residual bits, and every other
   non-canonical spelling before cryptographic verification."
  "It MUST decode the value and compare it with an unpadded Base64URL re-encoding
   of the decoded bytes. The comparison MUST be exact."
  -> The charset scan rejects padding / whitespace / `+` / `/` explicitly.
  -> len % 4 == 1 is an impossible unpadded-Base64 length (no byte count produces
     a single leftover character), rejected as "impossible length".
  -> The decode-then-re-encode-then-compare round trip is what catches invalid
     residual bits (a trailing character whose unused low-order bits are non-zero
     re-encodes to a different character), and is written literally as the spec
     words it rather than as an equivalent bit-mask, so the check is auditable
     against the sentence.

--- Obligation 3: algorithm-specific validation (CORE.md:424-425) ---------------
  "Decoded length and internal signature format remain algorithm-specific. A
   verifier MUST validate them separately."
  The algorithm enum is fixed by the signature envelopes (DACS-1 §L535/L666,
  DACS-3 §L452/L633, DACS-4 §L1061):
       algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
  CORE does NOT state the decoded byte length for any of them and does not cite
  RFC 8032 / SEC1 in its normative references (see the divergence note in the
  companion reasoning file). The lengths in _ALGORITHM_SIG_LENGTHS therefore come
  from the underlying algorithm standards, not from CORE:
    - ed25519          : 64 bytes exactly (RFC 8032 §5.1.6 — R || S, 32 + 32).
    - ecdsa-secp256k1  : 64 (r || s) or 65 (r || s || v recovery byte) raw bytes.
    - sr1-aggregate    : length not fixed by any cited document -> not constrained.
  An absent or unrecognised `algorithm` cannot be validated against; this check is
  skipped in that case (the wire and canonicality checks still apply in full).
  "Internal signature format" (e.g. ECDSA low-s) needs the curve parameters and is
  out of scope for an encoding evaluator; only decoded length is asserted here.

--- Obligation 4: the legacy-import boundary (CORE.md:435-443) ------------------
  "Draft artifacts produced before SIG-6 used standard Base64, Base64URL, and hex.
   Those spellings are legacy inputs, not alternate conforming encodings."
  "An implementation MAY expose an explicitly selected legacy-import path supplied
   with the source encoding out of band. That path MUST strictly decode the
   declared encoding, preserve the exact signature bytes, and emit the canonical
   DACS value."
  "It MUST NOT auto-detect by trying decoders or accept the legacy spelling on the
   conforming verification path."
  -> mode "legacy-import" requires an out-of-band declared source encoding. With
     no declaration there is nothing to "strictly decode"; the only way to proceed
     would be to try decoders, which is prohibited outright. -> reject.
  -> The declared encoding must name one of the three legacy families the spec
     enumerates (standard Base64, Base64URL, hex), in padded/unpadded and
     lower/upper spellings. _LEGACY_DECODERS is keyed on the DECLARED ENCODING
     NAME carried in the vector data — never on a vector name.
  -> "strictly decode" means the input must be an exact, canonical member of the
     declared encoding: correct alphabet, correct padding for that spelling, and
     zero residual bits. A value that is merely "close" is not strictly decodable.
  -> "preserve the exact signature bytes, and emit the canonical DACS value" is
     verified by re-encoding the decoded bytes to the canonical form and decoding
     that back, asserting byte identity.
  Note the asymmetry SIG-6 creates and this evaluator honours: the SAME padded
  standard-Base64 string is a REJECT on the conforming path and an ACCEPT on the
  legacy-import path when its encoding is declared out of band. The mode is what
  distinguishes them, exactly as the last sentence of the boundary demands.

Verdict vocabulary: "accept" | "reject".
  accept  = this value is admissible on the path the vector declares.
  reject  = SIG-6 obliges refusal on that path.

Dependency-free, standard library only. No per-vector-name logic exists in this
file; every decision is a function of (mode, declaredEncoding, algorithm, value).
"""

from __future__ import annotations

import base64
import json
import os
import sys

# --- CORE.md:413-414 "contains only A-Z, a-z, 0-9, -, and _" -------------------
_WIRE_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789" "-_"
)

_STD_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789" "+/"
)

_HEX_LOWER = frozenset("0123456789abcdef")
_HEX_UPPER = frozenset("0123456789ABCDEF")

# --- CORE.md:424-425 algorithm-specific decoded length ------------------------
# None => the cited standards do not fix a single length; do not constrain.
_ALGORITHM_SIG_LENGTHS = {
    "ed25519": frozenset({64}),
    "ecdsa-secp256k1": frozenset({64, 65}),
    "sr1-aggregate": None,
}


class _Malformed(Exception):
    """Raised when a value is not a strict, canonical member of an encoding."""


# ---------------------------------------------------------------------------
# Strict decoders. Each raises _Malformed unless the input is an exact,
# canonical member of that encoding.
# ---------------------------------------------------------------------------


def _decode_base64_family(value: str, alphabet: frozenset, padded: bool, altchars: bytes) -> bytes:
    """Strictly decode one Base64 spelling.

    Enforces: alphabet membership, padding discipline for the spelling, no
    impossible length, and zero residual bits (via exact re-encode comparison).
    """
    if value == "":
        raise _Malformed("empty value")

    body = value
    pad_len = 0
    if padded:
        # Padding is only legal as a trailing run of at most two '='.
        while body.endswith("="):
            body = body[:-1]
            pad_len += 1
        if pad_len > 2:
            raise _Malformed("more than two padding characters")

    if any(ch not in alphabet for ch in body):
        raise _Malformed("character outside the declared alphabet (padding, whitespace, or wrong alphabet)")

    rem = len(body) % 4
    if rem == 1:
        # No number of bytes encodes to 4n+1 Base64 characters.
        raise _Malformed("impossible Base64 length")

    if padded:
        expected_pad = 0 if rem == 0 else 4 - rem
        if pad_len != expected_pad:
            raise _Malformed("padding does not match the declared padded spelling")
    # unpadded spelling: any '=' already fell out of the alphabet check above

    raw = base64.b64decode(body + "=" * ((4 - rem) % 4), altchars=altchars, validate=True)

    # CORE.md:420-422 — decode, re-encode unpadded, compare exactly.
    reencoded = base64.b64encode(raw, altchars=altchars).decode("ascii").rstrip("=")
    if reencoded != body:
        raise _Malformed("non-canonical spelling: invalid residual bits")
    return raw


def _decode_wire_base64url(value: str) -> bytes:
    """The canonical DACS wire form: unpadded Base64URL. CORE.md:404-422."""
    return _decode_base64_family(value, _WIRE_ALPHABET, padded=False, altchars=b"-_")


def _decode_hex(value: str, alphabet: frozenset) -> bytes:
    if value == "":
        raise _Malformed("empty value")
    if len(value) % 2 != 0:
        raise _Malformed("odd-length hex")
    if any(ch not in alphabet for ch in value):
        raise _Malformed("character outside the declared hex alphabet / wrong case")
    return bytes.fromhex(value)


# Keyed on the DECLARED ENCODING supplied out of band (CORE.md:438-440),
# covering the three legacy families the spec enumerates at CORE.md:435
# ("standard Base64, Base64URL, and hex") in their padded/unpadded and
# lower/upper spellings.
_LEGACY_DECODERS = {
    "standard-base64-padded": lambda v: _decode_base64_family(v, _STD_B64_ALPHABET, True, b"+/"),
    "standard-base64-unpadded": lambda v: _decode_base64_family(v, _STD_B64_ALPHABET, False, b"+/"),
    "standard-base64": lambda v: _decode_base64_family(v, _STD_B64_ALPHABET, True, b"+/"),
    "base64url-padded": lambda v: _decode_base64_family(v, _WIRE_ALPHABET, True, b"-_"),
    "base64url-unpadded": lambda v: _decode_base64_family(v, _WIRE_ALPHABET, False, b"-_"),
    "base64url": lambda v: _decode_base64_family(v, _WIRE_ALPHABET, False, b"-_"),
    "lowercase-hex": lambda v: _decode_hex(v, _HEX_LOWER),
    "uppercase-hex": lambda v: _decode_hex(v, _HEX_UPPER),
    "hex": lambda v: _decode_hex(v, _HEX_LOWER | _HEX_UPPER),
}


def _algorithm_length_ok(algorithm, decoded_len: int) -> bool:
    """CORE.md:424-425. Absent/unrecognised algorithm => nothing to validate against."""
    if not isinstance(algorithm, str):
        return True
    allowed = _ALGORITHM_SIG_LENGTHS.get(algorithm.strip().lower(), True)
    if allowed is None or allowed is True:
        return True
    return decoded_len in allowed


def _to_canonical_wire(raw: bytes) -> str:
    """signature_value := base64url(signature_bytes).remove_trailing('=')  — CORE.md:410."""
    return base64.b64encode(raw, altchars=b"-_").decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# The two paths SIG-6 defines.
# ---------------------------------------------------------------------------


def _evaluate_conforming_verifier(vector) -> str:
    value = vector.get("value")
    if not isinstance(value, str):
        return "reject"

    try:
        # Obligations 1 + 2: wire alphabet, no padding/whitespace/+//,
        # no impossible length, no invalid residual bits, exact round trip.
        raw = _decode_wire_base64url(value)
    except (_Malformed, Exception):
        return "reject"

    # Obligation 3: algorithm-specific decoded length, validated separately.
    if not _algorithm_length_ok(vector.get("algorithm"), len(raw)):
        return "reject"

    return "accept"


def _evaluate_legacy_import(vector) -> str:
    value = vector.get("value")
    if not isinstance(value, str):
        return "reject"

    declared = vector.get("declaredEncoding")
    if not isinstance(declared, str) or declared.strip() == "":
        # CORE.md:438-443 — the path is "supplied with the source encoding out of
        # band" and "MUST NOT auto-detect by trying decoders". With no declaration
        # there is no encoding to strictly decode, and guessing is prohibited.
        return "reject"

    decoder = _LEGACY_DECODERS.get(declared.strip().lower())
    if decoder is None:
        # Not one of the legacy spellings the spec admits; nothing to strictly
        # decode without auto-detection.
        return "reject"

    try:
        raw = decoder(value)
    except (_Malformed, Exception):
        # "MUST strictly decode the declared encoding" — a value that is not an
        # exact member of the declared encoding fails the import.
        return "reject"

    if len(raw) == 0:
        return "reject"

    # Algorithm-specific validation still applies when an algorithm is declared.
    if not _algorithm_length_ok(vector.get("algorithm"), len(raw)):
        return "reject"

    # "preserve the exact signature bytes, and emit the canonical DACS value"
    canonical = _to_canonical_wire(raw)
    try:
        if _decode_wire_base64url(canonical) != raw:
            return "reject"
    except (_Malformed, Exception):
        return "reject"

    return "accept"


def evaluate(vector) -> str:
    """Return "accept" or "reject" for one SIG-6 vector."""
    if not isinstance(vector, dict):
        return "reject"

    mode = vector.get("mode")
    mode = mode.strip().lower() if isinstance(mode, str) else ""

    if mode == "legacy-import":
        return _evaluate_legacy_import(vector)

    # Default is the conforming verification path. An unrecognised mode is
    # evaluated under the strict conforming rules rather than the permissive
    # legacy path, because SIG-6 forbids accepting legacy spellings anywhere
    # except an explicitly selected import path.
    return _evaluate_conforming_verifier(vector)


def main(argv) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    in_path = argv[1] if len(argv) > 1 else os.path.join(
        root, "blind", "signature-value-encoding-v0.1.json"
    )
    out_path = argv[2] if len(argv) > 2 else os.path.join(
        root, "runs", "run-pathos-signature-value-encoding-v0.1.json"
    )

    with open(in_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    results = []
    for vector in doc.get("vectors", []):
        verdict = evaluate(vector)
        results.append({"name": vector.get("name"), "verdict": verdict})
        print("{:<48} {}".format(str(vector.get("name")), verdict))

    run = {
        "set": "signature-value-encoding-v0.1",
        "impl": "pathos-dacs-ref@cross-run-1",
        "results": results,
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=2)
        fh.write("\n")

    accepts = sum(1 for r in results if r["verdict"] == "accept")
    print("\n{} vectors: {} accept / {} reject".format(len(results), accepts, len(results) - accepts))
    print("wrote {}".format(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
