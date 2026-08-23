#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent reference evaluator for DACS-4 §9.5.8 rule SB-3 — the byte-exact
EIP-3009 session-binding nonce derivation for the ``pay-x402`` rail.

Written from the normative text only (spec/DACS-4-SETTLE.md §9.5.8 and
spec/CORE.md §B.7 "Non-signature hash-domain tags"). No answer key was consulted.

=============================================================================
1. THE DERIVATION (byte-exact)
=============================================================================

DACS-4 §9.5.8, SB-3, EIP-3009 arm, verbatim::

    preimage = UTF8("dacs-sb3:v1:")
               || UTF8(NFC(jobId))
               || 0x3a
               || ASCII(decimal(phaseIndex))
    nonceBytes = SHA-256(preimage)

and the prose that pins every remaining degree of freedom, verbatim::

    `UTF8` is UTF-8 without a byte-order mark. `0x3a` is the single ASCII colon
    byte. `decimal(phaseIndex)` is the non-negative integer's minimal base-10
    ASCII representation (`0` for zero; no sign and no leading zeroes).
    `nonceBytes` is used directly as the 32-byte EIP-3009 value; when a DACS
    implementation serialises that value as text it MUST use `0x` followed by
    exactly 64 lower-case hexadecimal digits.

CORE.md §B.7 restates the same preimage independently, as the second of the two
sanctioned non-signature hash-domain tags, verbatim::

    - `dacs-sb3:v1:` — the EIP-3009 session-binding nonce preimage
      `sha256(UTF8("dacs-sb3:v1:") || UTF8(NFC(jobId)) || 0x3a ||
      ASCII(decimal(phaseIndex)))` (§9.5.8).

So, concretely, this module computes::

    preimage   = b"dacs-sb3:v1:"
               + unicodedata.normalize("NFC", jobId).encode("utf-8")
               + b"\\x3a"                       # one ASCII colon, not a separator string
               + str(phaseIndex).encode("ascii")
    nonceBytes = hashlib.sha256(preimage).digest()          # 32 bytes
    text form  = "0x" + nonceBytes.hex()                    # 64 lower-case hex digits

Note there is exactly ONE colon between jobId and phaseIndex and NO trailing
separator; the two colons inside the literal ``dacs-sb3:v1:`` are part of the
domain tag itself. UTF-8 is emitted without a BOM (Python's ``.encode("utf-8")``
never emits one).

=============================================================================
2. SB-3 RESOLUTION BRANCHES
=============================================================================

DACS-4 §9.5.8, verbatim::

    When a rail declares a binding, the verifier resolves it in three branches:
    - **present and matches** → the binding guarantee is satisfied;
    - **present and mismatches** → reject the evidence;
    - **absent or unverifiable** (the binding is missing, or the on-chain check
      cannot complete — RPC unavailable, pruned history, unresolvable
      `isValidSignature`) → the binding guarantee is **not established** for
      that record: fall back to the SB-1 + SB-2 + §9.5.1 amount/payee posture of
      an unbound rail. This is **never** an automatic accept and **never** a
      hard fail [...]

and, for the nonce specifically::

    The verifier MUST recover `phaseIndex` from the SB-1 payment-evidence
    anchor, independently recompute `nonceBytes` from `evidence.jobId`, and
    compare the decoded 32 bytes. A well-formed nonce that differs is a
    **present-and-mismatches** rejection under the branch rule below; a
    malformed nonce encoding is `error`.

Verdict mapping used here:
    present + matches           -> "pass"
    present + mismatches        -> "fail"
    malformed nonce encoding    -> "error"
    malformed derivation input  -> "error"
    absent / unverifiable       -> "pass"  (see CAVEAT below)

CAVEAT — the fallback branch does not fit a three-valued verdict.  The spec is
explicit that "absent or unverifiable" is "never an automatic accept and never
a hard fail": the binding guarantee is simply *not established* and the record
falls back to the unbound SB-1 + SB-2 + §9.5.1 posture.  A pass/fail/error
harness has no token for "not established but not rejected".  Because the
fallback is non-rejecting at the SB-3 layer, this evaluator returns "pass"
(i.e. SB-3 raised no objection), NOT because the binding was proven.  No vector
in sb3-eip3009-nonce-v0.1 exercises this branch, so the choice is inert here —
but it is a real expressiveness gap and is flagged rather than hidden.

=============================================================================
3. RETRY IDENTITY (the `retry` op)
=============================================================================

DACS-4 §9.5.8, verbatim::

    The derived nonce is also the retry identity. After an indeterminate
    submission, the handler MUST reconcile the token contract's authorization
    state before submitting again. If chain evidence proves that the same
    authorization and transfer parameters already settled this
    `(jobId, phaseIndex)`, the handler MUST resume with that existing settlement
    reference rather than charge again. A nonce that is used or cancelled but
    cannot be reconciled to that completed transfer MUST fail closed; the
    handler MUST NOT generate a fresh nonce for the same `(jobId, phaseIndex)`.

Verdict mapping:
    prior state used + same transfer parameters + a settlement reference
        -> reconcilable, resume            -> "pass"
    prior state used or cancelled, not reconcilable to a completed transfer
        -> MUST fail closed                -> "fail"
    prior state unused / no prior authorization
        -> free to submit the derived nonce -> "pass"
    "cancelled" is never reconcilable to a *completed* transfer, so it fails
    closed regardless of the sameTransferParameters flag.

=============================================================================
4. validationScope
=============================================================================

`validationScope` appears in the vector inputs but NOT anywhere in the
normative text (grep of spec/CORE.md + spec/DACS-*.md finds zero hits). It is
therefore read here as a harness-level knob selecting how much of the *input*
is validated, with the following interpretation:

  "derivation-only" — exercise the SB-3 derivation and branch rules only. The
      jobId is treated as an opaque string; its DACS well-formedness is NOT
      checked. (Necessary: a derivation-only fixture may use a human-readable
      or non-ASCII jobId that is not a ULID - indeed the NFC leg of the
      derivation can only be exercised by a non-ASCII jobId, which no ULID is.)

  "full-input" — additionally validate the jobId as a DACS session identifier.
      CORE.md §B.1 pins it: "In every case `{jobId}` is a ULID (no reserved
      delimiters)" (echoed by DACS-4 §9.5.1: "`jobId` (a ULID)"). A jobId that
      is not a canonical 26-character Crockford-base32 ULID is a malformed
      input -> "error".

Any other / missing value is treated as "full-input" (the strict reading), so an
unrecognised scope can never silently relax a check.

=============================================================================
5. INPUT WELL-FORMEDNESS -> "error"
=============================================================================

`decimal(phaseIndex)` is defined only for "the non-negative integer's minimal
base-10 ASCII representation (`0` for zero; no sign and no leading zeroes)".
An input for which that function is undefined has no byte-exact preimage, so
the derivation cannot be performed and the verdict is "error":
  - phaseIndex negative                          (no non-negative decimal)
  - phaseIndex non-integral / boolean / null / absent
  - phaseIndex carried as text that is not already the minimal form
    (e.g. "03" — a leading zero is exactly what the rule forbids)
  - phaseIndex outside the CORE §B.2 IEEE-754 safe-integer range
  - jobId absent or not a string
  - a nonce serialised as anything other than "0x" + exactly 64 lower-case hex

This module is standard-library only and contains no per-vector special cases:
it never reads the `name` field.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata

# --- constants pinned by the spec -------------------------------------------

SB3_DOMAIN_TAG = b"dacs-sb3:v1:"   # CORE §B.7 non-signature hash-domain tag
SB3_SEPARATOR = b"\x3a"            # "0x3a is the single ASCII colon byte"

MAX_SAFE_INTEGER = 2 ** 53 - 1     # CORE §B.2 numeric safe-integer constraint

# "0x followed by exactly 64 lower-case hexadecimal digits"
NONCE_TEXT_RE = re.compile(r"\A0x[0-9a-f]{64}\Z")

# "decimal(phaseIndex) is the non-negative integer's minimal base-10 ASCII
# representation (0 for zero; no sign and no leading zeroes)"
MINIMAL_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")

# ULID: 26 chars, Crockford base32, most-significant char bounded by 7 so the
# 48-bit timestamp cannot overflow 128 bits.
CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_RE = re.compile(r"\A[0-7][%s]{25}\Z" % CROCKFORD32)


class MalformedInput(Exception):
    """Input for which the spec's derivation / encoding is undefined -> error."""


# --- derivation --------------------------------------------------------------

def sb3_preimage(job_id: str, phase_decimal: str) -> bytes:
    """Build the exact SB-3 preimage bytes.

    preimage = UTF8("dacs-sb3:v1:") || UTF8(NFC(jobId)) || 0x3a
               || ASCII(decimal(phaseIndex))
    """
    job_nfc = unicodedata.normalize("NFC", job_id)
    return (
        SB3_DOMAIN_TAG
        + job_nfc.encode("utf-8")          # UTF-8, no BOM
        + SB3_SEPARATOR
        + phase_decimal.encode("ascii")
    )


def derive_nonce_bytes(job_id: str, phase_decimal: str) -> bytes:
    """nonceBytes = SHA-256(preimage) — the raw 32-byte EIP-3009 value."""
    return hashlib.sha256(sb3_preimage(job_id, phase_decimal)).digest()


def format_nonce(nonce_bytes: bytes) -> str:
    """Text serialisation: '0x' + exactly 64 lower-case hex digits."""
    return "0x" + nonce_bytes.hex()


# --- input normalisation -----------------------------------------------------

def normalize_phase_index(raw) -> str:
    """Return decimal(phaseIndex); raise MalformedInput where it is undefined."""
    if isinstance(raw, bool) or raw is None:
        raise MalformedInput("phaseIndex is not an integer")
    if isinstance(raw, int):
        if raw < 0:
            raise MalformedInput("phaseIndex is negative")
        if raw > MAX_SAFE_INTEGER:
            raise MalformedInput("phaseIndex exceeds the safe-integer range")
        return str(raw)               # str() of a non-negative int IS minimal
    if isinstance(raw, float):
        # A JSON number that is not integral has no decimal(phaseIndex).
        if not raw.is_integer():
            raise MalformedInput("phaseIndex is not an integer")
        return normalize_phase_index(int(raw))
    if isinstance(raw, str):
        # Text carriage is accepted only when it is ALREADY the minimal form;
        # "03" (leading zero) and "-1" and "+3" are rejected by construction.
        if not MINIMAL_DECIMAL_RE.match(raw):
            raise MalformedInput(
                "phaseIndex text is not the minimal base-10 representation")
        if int(raw) > MAX_SAFE_INTEGER:
            raise MalformedInput("phaseIndex exceeds the safe-integer range")
        return raw
    raise MalformedInput("phaseIndex has an unsupported type")


def normalize_job_id(raw, strict_identifier: bool) -> str:
    if not isinstance(raw, str) or raw == "":
        raise MalformedInput("jobId is missing or not a string")
    if strict_identifier and not ULID_RE.match(raw):
        # CORE §B.1: "In every case {jobId} is a ULID (no reserved delimiters)"
        raise MalformedInput("jobId is not a canonical ULID")
    return raw


def decode_nonce(raw) -> bytes:
    """Decode a serialised bytes32 nonce, or raise MalformedInput.

    'a malformed nonce encoding is error' (DACS-4 §9.5.8).
    """
    if not isinstance(raw, str) or not NONCE_TEXT_RE.match(raw):
        raise MalformedInput("nonce is not '0x' + 64 lower-case hex digits")
    return bytes.fromhex(raw[2:])


def _strict_identifier_scope(vector) -> bool:
    """validationScope -> whether to validate the jobId as a DACS identifier."""
    return vector.get("validationScope") != "derivation-only"


# --- SB-3 evaluation ---------------------------------------------------------

def _check_claimed_expected(vector, derived: bytes) -> None:
    """`expectedNonce` is an INPUT claim, not authority.

    The spec makes the verifier "independently recompute nonceBytes"; a record
    whose own claimed nonce disagrees with the recomputation is a
    present-and-mismatches rejection, not a silent re-anchor onto the claim.
    Raises _Mismatch on disagreement, MalformedInput on a bad encoding.
    """
    if "expectedNonce" not in vector:
        return
    claimed = decode_nonce(vector["expectedNonce"])
    if claimed != derived:
        raise _Mismatch("claimed expectedNonce disagrees with the derivation")


class _Mismatch(Exception):
    """A well-formed value that differs from the recomputation -> fail."""


def _evaluate_verify_binding(vector, derived: bytes) -> str:
    presented_raw = vector.get("presentedNonce")
    if presented_raw is None:
        # SB-3 branch 3: absent -> binding not established, fall back to the
        # unbound SB-1/SB-2/§9.5.1 posture. Never an accept, never a hard fail.
        # See the module CAVEAT: mapped to the non-rejecting token.
        return "pass"
    presented = decode_nonce(presented_raw)      # malformed -> error
    if presented == derived:
        return "pass"                            # present and matches
    return "fail"                                # present and mismatches


def _evaluate_derive(vector, derived: bytes) -> str:
    # Reaching here means the preimage was constructible and hashed.
    return "pass"


def _evaluate_retry(vector, derived: bytes) -> str:
    # The handler's own nonce must be the derived one; it "MUST NOT generate a
    # fresh nonce for the same (jobId, phaseIndex)".
    if "derivedNonce" in vector:
        handler_nonce = decode_nonce(vector["derivedNonce"])   # malformed -> error
        if handler_nonce != derived:
            return "fail"

    prior = vector.get("priorAuthorization")
    if not isinstance(prior, dict):
        # No prior authorization state -> nothing blocks submitting the nonce.
        return "pass"

    state = prior.get("state")
    if state in (None, "unused", "none"):
        return "pass"

    if state == "used":
        # "If chain evidence proves that the same authorization and transfer
        # parameters already settled this (jobId, phaseIndex), the handler MUST
        # resume with that existing settlement reference rather than charge
        # again."
        if prior.get("sameTransferParameters") is True and prior.get("settlementTxId"):
            return "pass"
        # "A nonce that is used [...] but cannot be reconciled to that completed
        # transfer MUST fail closed"
        return "fail"

    if state == "cancelled":
        # Cancelled means there is no completed transfer to reconcile to.
        return "fail"

    raise MalformedInput("unrecognised priorAuthorization.state")


_OPS = {
    "verify-binding": _evaluate_verify_binding,
    "derive": _evaluate_derive,
    "retry": _evaluate_retry,
}


def evaluate(vector) -> str:
    """Evaluate one SB-3 vector. Returns exactly 'pass', 'fail', or 'error'."""
    try:
        if not isinstance(vector, dict):
            raise MalformedInput("vector is not an object")

        op = vector.get("op")
        handler = _OPS.get(op)
        if handler is None:
            raise MalformedInput("unrecognised op")

        job_id = normalize_job_id(
            vector.get("jobId"), _strict_identifier_scope(vector))
        phase_decimal = normalize_phase_index(vector.get("phaseIndex"))

        derived = derive_nonce_bytes(job_id, phase_decimal)

        _check_claimed_expected(vector, derived)

        return handler(vector, derived)
    except MalformedInput:
        return "error"
    except _Mismatch:
        return "fail"


# --- CLI ---------------------------------------------------------------------

def main(argv):
    if len(argv) < 2:
        print("usage: eval_sb3_eip3009_nonce.py <vectors.json> [out.json]",
              file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    results = [{"name": v.get("name"), "verdict": evaluate(v)}
               for v in doc.get("vectors", [])]
    out = {
        "set": doc.get("set", "sb3-eip3009-nonce-v0.1"),
        "impl": "pathos-dacs-ref@cross-run-1",
        "results": results,
    }
    text = json.dumps(out, indent=2) + "\n"
    if len(argv) > 2:
        with open(argv[2], "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
