#!/usr/bin/env python3
"""Independent DACS conformance evaluator: artifact reference shapes.

Scope
-----
Structural ("shape") conformance of two DACS artifact-reference types:

  * ``AttestationRef``  -- DACS-2 (VET) sec 7.5 type block / sec 7.5.2 resolution
                           algorithm; summarised in CORE sec B.3.
  * ``ChainTxRef``      -- DACS-4 (SETTLE) sec 9.3 "Shared types"
                           (``type TxRef = ChainTxRef``, a discriminated union).

Verdict vocabulary is ``pass`` (shape-conformant) / ``fail`` (not conformant).

Normative rules implemented
---------------------------
R1. AttestationRef required/optional members (DACS-2 sec 7.5 type block)::

        type AttestationRef = {
          anchor: { kind: "storage-program" | "ipfs" | "https"; locator: string }
          contentHash: string
          signer?: ClaimReference
        }

    ``anchor`` and ``contentHash`` are REQUIRED; ``signer`` is OPTIONAL.
    ``anchor.kind`` is a closed three-value enum; ``anchor.locator`` is the
    fetch target of sec 7.5.2 step 1 ("fetching the anchor at
    AttestationRef.anchor.locator"), so it MUST be a non-empty string.

R2. contentHash encoding. CORE sec B.2 defines "Content hash" as "sha256 hex of
    the canonical form"; CORE sec B.7 pins the hex spelling of a sha256 digest
    ("MUST be the lowercase hex string of the sha256 digest"). DACS-2 sec 7.5.2
    states contentHash is "the sha256 of the anchored content's canonical form".
    Therefore: exactly 64 lower-case hexadecimal digits, no ``0x`` prefix.

R3. ClaimReference grammar (DACS-1 sec 6.3.1, restated in CORE sec B.1)::

        ClaimReference := Scheme ":" Identifier [ "?" Parameters ]
        Scheme         := lowercase-ascii ( lowercase-ascii | digit | "-" )*
        Identifier     := scheme-specific, non-empty

    Underscores "MUST NOT appear in v0.1 scheme names". Scheme is read
    case-insensitively. An *unregistered* scheme is deliberately NOT treated as
    a shape failure: DACS-1 sec 6.3.1 "Unknown-scheme handling" requires a reader
    to preserve the reference verbatim and treat it as unverified -- it does not
    authorise structural rejection. Only grammar is enforced here.

R4. ChainTxRef is a closed discriminated union on ``kind`` (DACS-4 sec 9.3, and
    CORE sec B.6 "Closed registries -- v0.1 scope"). The arm table below is
    transcribed verbatim from sec 9.3. A ``kind`` outside the table is an
    unknown/unsupported discriminator: CORE sec 11 "New-type refusal" requires
    an implementation that does not support a type to "reject it as unsupported"
    and forbids reinterpreting it as an existing type "by discarding an unknown
    discriminator or action-bearing field".

R5. Required arm members MUST be present with the declared JSON type; optional
    arm members, when present, MUST have the declared JSON type.

R6. Closed-shape rule: a member not declared by the matched arm is rejected.
    Basis: DACS-4 sec 9.3 enumerates each arm exhaustively; CORE sec B.6 makes
    the v0.1 registries closed with ``x-`` as the only sanctioned experimental
    escape hatch; and CORE sec 11 "New-type refusal" forbids acting on a record
    while discarding an unknown discriminator or action-bearing field. A
    ChainTxRef/AttestationRef carries no per-artifact version field, so a
    validator has no basis to attribute an undeclared member to a later minor
    version, and cannot distinguish an inert annotation from an act-requiring
    field. The conservative conformant behaviour is refusal.
    (See the reasoning note -- CORE sec 11 "Additivity contract" plus SIG-5
    preserve-unknown support the opposite, tolerant reading. Documented.)

R7. Numeric constraints. CORE sec B.2 "Numeric safe-integer constraint": every
    JSON number in a signed or content-hashed DACS document MUST lie within the
    IEEE-754 double safe-integer range. DACS-4 sec 9.5.8 SB-1 adds: "chainId,
    logIndex, and instructionIndex MUST be non-negative safe integers ...
    (chainId MUST additionally be greater than zero)"; a "non-integer, negative,
    non-safe-integer, or otherwise malformed signed coordinate" is malformed.
    Block-height / unix-ms members are likewise non-negative safe integers.
    JSON booleans are not integers.

R8. x402 field formats, cited directly by the sec 9.3 arm comment
    ("paymentReceiptHash and protocolVersion follow X402-1..X402-4"):
      * X402-2: ``paymentReceiptHash`` "MUST be exactly 64 lower-case
        hexadecimal digits without 0x"; X402-4 rejects "a non-canonical stored
        hash".
      * X402-1: ``protocolVersion`` "MUST be the negotiated x402 version as a
        minimal unsigned-decimal string" (no sign, no leading zeros).

R9. ``ap2.receiptAttestation``, when present, is an ``AttestationRef`` and is
    validated by R1-R3. DACS-4 sec 9.3 / AP2-2 make it REQUIRED only on a
    success-outcome record ("MAY be absent only on failure-outcome records");
    outcome is a property of the enclosing SettlementEvidence, not of the
    reference, so at reference-shape level it is optional.

Deliberately NOT enforced
-------------------------
N1. The SB-1 canonical-rendering rules ("EVM hashes are rendered as exactly 64
    lower-case hexadecimal digits without 0x ..."; "A Solana signature is base58
    that MUST decode to exactly 64 bytes") are projection-time rules, not shape
    rules. DACS-4 sec 9.5.8 sequences them explicitly: "After signature, SHAPE,
    anchor-address, and ledger-event verification, the consumer deterministically
    projects the verified signed arm to settlement-tx-id" -- projection is
    downstream of shape verification, and its failure mode is the sec 7.5.1
    verification outcome ``error``, not a shape verdict. The sec 9.3 type block
    declares these members as bare ``string`` with no format. The same text also
    accepts a "legacy spelling with 0x or upper-case characters", which
    "collapses" rather than being rejected.
N2. Cross-field / external-state rules (X402-3 receipt-vs-chain consistency,
    AP2-1/AP2-2 binding, SB-1 anchor-address tuple, sec 7.5.2 fetch + integrity
    + signature checks) require the enclosing record, the ledger, or the network.
    Out of scope for a standalone reference shape.

Standard library only. ``evaluate(vector) -> "pass" | "fail"``.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, Optional, Tuple

# --------------------------------------------------------------------------
# Primitive validators
# --------------------------------------------------------------------------

MAX_SAFE_INTEGER = 2 ** 53 - 1  # CORE sec B.2 numeric safe-integer constraint

_LOWER_HEX_64 = re.compile(r"\A[0-9a-f]{64}\Z")
# DACS-1 sec 6.3.1 grammar: Scheme := lowercase-ascii ( lowercase-ascii | digit | "-" )*
# Scheme is read case-insensitively (sec 6.3.1), hence the case-insensitive class.
_CLAIM_REF = re.compile(r"\A[A-Za-z][A-Za-z0-9-]*:[^\s]+\Z")
# X402-1: minimal unsigned-decimal string (no sign, no leading zeros).
_MINIMAL_UNSIGNED_DECIMAL = re.compile(r"\A(0|[1-9][0-9]*)\Z")


def _is_object(v: Any) -> bool:
    return isinstance(v, dict)


def _is_string(v: Any) -> bool:
    return isinstance(v, str)


def _is_nonempty_string(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def _is_safe_integer(v: Any) -> bool:
    """JSON number that is an integer inside the IEEE-754 safe range (R7).

    ``bool`` is a Python subclass of ``int`` and is excluded: a JSON boolean is
    not a JSON number.
    """
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= MAX_SAFE_INTEGER
    if isinstance(v, float):
        return v.is_integer() and abs(v) <= MAX_SAFE_INTEGER
    return False


def _is_nonneg_safe_integer(v: Any) -> bool:
    return _is_safe_integer(v) and v >= 0


def _is_positive_safe_integer(v: Any) -> bool:
    return _is_safe_integer(v) and v > 0


def _is_sha256_lower_hex(v: Any) -> bool:
    """R2 / R8: exactly 64 lower-case hex digits, no 0x prefix."""
    return isinstance(v, str) and bool(_LOWER_HEX_64.match(v))


def _is_claim_reference(v: Any) -> bool:
    """R3: ClaimReference grammar only (registration is not a shape gate)."""
    if not isinstance(v, str):
        return False
    if not _CLAIM_REF.match(v):
        return False
    scheme = v.split(":", 1)[0]
    # "Underscores are reserved for future use and MUST NOT appear in v0.1
    # scheme names." Already excluded by the character class; asserted here so
    # the rule is explicit rather than incidental.
    if "_" in scheme:
        return False
    identifier = v.split(":", 1)[1]
    # Identifier is "scheme-specific, non-empty"; strip optional ?Parameters.
    identifier = identifier.split("?", 1)[0]
    return identifier != ""


def _is_minimal_unsigned_decimal(v: Any) -> bool:
    return isinstance(v, str) and bool(_MINIMAL_UNSIGNED_DECIMAL.match(v))


# --------------------------------------------------------------------------
# AttestationRef -- DACS-2 sec 7.5 / sec 7.5.2  (R1, R2, R3)
# --------------------------------------------------------------------------

ANCHOR_KINDS = ("storage-program", "ipfs", "https")


def _check_anchor(anchor: Any) -> Optional[str]:
    if not _is_object(anchor):
        return "anchor is not a JSON object"
    declared = {"kind", "locator"}
    extra = set(anchor) - declared
    if extra:
        return "anchor carries undeclared member(s): %s" % sorted(extra)
    if "kind" not in anchor:
        return "anchor.kind missing (required)"
    if "locator" not in anchor:
        return "anchor.locator missing (required)"
    if anchor["kind"] not in ANCHOR_KINDS:
        return "anchor.kind %r outside the closed enum %s" % (
            anchor["kind"],
            list(ANCHOR_KINDS),
        )
    if not _is_nonempty_string(anchor["locator"]):
        return "anchor.locator is not a non-empty string"
    return None


def check_attestation_ref(value: Any) -> Optional[str]:
    """Return None when shape-conformant, else a one-line reason."""
    if not _is_object(value):
        return "value is not a JSON object"

    declared = {"anchor", "contentHash", "signer"}
    extra = set(value) - declared
    if extra:
        # R6 closed-shape rule.
        return "undeclared member(s) for AttestationRef: %s" % sorted(extra)

    if "anchor" not in value:
        return "anchor missing (required by the DACS-2 sec 7.5 type block)"
    reason = _check_anchor(value["anchor"])
    if reason:
        return reason

    if "contentHash" not in value:
        return "contentHash missing (required)"
    if not _is_sha256_lower_hex(value["contentHash"]):
        return "contentHash is not 64 lower-case hex digits (CORE sec B.2/B.7)"

    if "signer" in value and not _is_claim_reference(value["signer"]):
        return "signer is not a well-formed ClaimReference (DACS-1 sec 6.3.1)"

    return None


# --------------------------------------------------------------------------
# ChainTxRef -- DACS-4 sec 9.3  (R4, R5, R6, R7, R8, R9)
# --------------------------------------------------------------------------

# Member-name -> validator, transcribed arm-by-arm from the sec 9.3 union.
# Value is (required_members, optional_members); each maps name -> predicate.

_CLUSTERS = ("mainnet", "devnet", "testnet")


def _is_cluster(v: Any) -> bool:
    return v in _CLUSTERS


def _is_attestation_ref(v: Any) -> bool:
    """R9: nested AttestationRef validated by the same R1-R3 rules."""
    return check_attestation_ref(v) is None


CHAIN_TX_REF_ARMS: Dict[str, Tuple[Dict[str, Any], Dict[str, Any]]] = {
    # | { kind: "evm"; chainId: number; txHash: string }
    "evm": (
        {"chainId": _is_positive_safe_integer, "txHash": _is_nonempty_string},
        {},
    ),
    # | { kind: "evm-event"; chainId: number; txHash: string; logIndex: number }
    "evm-event": (
        {
            "chainId": _is_positive_safe_integer,
            "txHash": _is_nonempty_string,
            "logIndex": _is_nonneg_safe_integer,
        },
        {},
    ),
    # | { kind: "solana"; cluster: ...; signature: string }
    "solana": (
        {"cluster": _is_cluster, "signature": _is_nonempty_string},
        {},
    ),
    # | { kind: "solana-instruction"; cluster: ...; signature: string;
    #     instructionIndex: number }
    "solana-instruction": (
        {
            "cluster": _is_cluster,
            "signature": _is_nonempty_string,
            "instructionIndex": _is_nonneg_safe_integer,
        },
        {},
    ),
    # | { kind: "demos"; txHash: string; blockNumber?: number }
    "demos": (
        {"txHash": _is_nonempty_string},
        {"blockNumber": _is_nonneg_safe_integer},
    ),
    # | { kind: "storage-program"; address: string; writeTxHash: string }
    "storage-program": (
        {"address": _is_nonempty_string, "writeTxHash": _is_nonempty_string},
        {},
    ),
    # | { kind: "ap2"; mandateId: string; providerRef: string;
    #     protocolVersion: string; receiptAttestation?: AttestationRef }
    "ap2": (
        {
            "mandateId": _is_nonempty_string,
            "providerRef": _is_nonempty_string,
            "protocolVersion": _is_nonempty_string,
        },
        {"receiptAttestation": _is_attestation_ref},
    ),
    # | { kind: "x402"; httpResource: string; paymentReceiptHash: string;
    #     settlementTxHash?: string; chainId?: number; protocolVersion: string }
    "x402": (
        {
            "httpResource": _is_nonempty_string,
            "paymentReceiptHash": _is_sha256_lower_hex,      # X402-2
            "protocolVersion": _is_minimal_unsigned_decimal,  # X402-1
        },
        {
            "settlementTxHash": _is_nonempty_string,
            "chainId": _is_positive_safe_integer,
        },
    ),
    # | { kind: "x402-event"; httpResource: string; paymentReceiptHash: string;
    #     settlementTxHash: string; chainId: number; logIndex: number;
    #     protocolVersion: string }
    "x402-event": (
        {
            "httpResource": _is_nonempty_string,
            "paymentReceiptHash": _is_sha256_lower_hex,      # X402-2
            "settlementTxHash": _is_nonempty_string,
            "chainId": _is_positive_safe_integer,
            "logIndex": _is_nonneg_safe_integer,
            "protocolVersion": _is_minimal_unsigned_decimal,  # X402-1
        },
        {},
    ),
    # | { kind: "htlc-lock"; chainId: number; contractAddress: string;
    #     lockTxHash: string }
    "htlc-lock": (
        {
            "chainId": _is_positive_safe_integer,
            "contractAddress": _is_nonempty_string,
            "lockTxHash": _is_nonempty_string,
        },
        {},
    ),
    # | { kind: "htlc-reveal"; ...; revealTxHash: string }
    "htlc-reveal": (
        {
            "chainId": _is_positive_safe_integer,
            "contractAddress": _is_nonempty_string,
            "revealTxHash": _is_nonempty_string,
        },
        {},
    ),
    # | { kind: "htlc-claim"; ...; claimTxHash: string }
    "htlc-claim": (
        {
            "chainId": _is_positive_safe_integer,
            "contractAddress": _is_nonempty_string,
            "claimTxHash": _is_nonempty_string,
        },
        {},
    ),
    # | { kind: "htlc-refund"; ...; refundTxHash: string }
    "htlc-refund": (
        {
            "chainId": _is_positive_safe_integer,
            "contractAddress": _is_nonempty_string,
            "refundTxHash": _is_nonempty_string,
        },
        {},
    ),
    # | { kind: "liquidity-tank"; bridgeId: string; sourceChainId: number;
    #     destChainId: number; lockTxHash: string; releaseTxHash?: string;
    #     recoveryDeadline?: number }
    "liquidity-tank": (
        {
            "bridgeId": _is_nonempty_string,
            "sourceChainId": _is_positive_safe_integer,
            "destChainId": _is_positive_safe_integer,
            "lockTxHash": _is_nonempty_string,
        },
        {
            "releaseTxHash": _is_nonempty_string,
            "recoveryDeadline": _is_nonneg_safe_integer,  # unix ms
        },
    ),
}


def check_chain_tx_ref(value: Any) -> Optional[str]:
    """Return None when shape-conformant, else a one-line reason."""
    if not _is_object(value):
        return "value is not a JSON object"

    if "kind" not in value:
        return "kind discriminator missing (DACS-4 sec 9.3 discriminated union)"
    kind = value["kind"]
    if not _is_string(kind):
        return "kind discriminator is not a string"
    if kind not in CHAIN_TX_REF_ARMS:
        # R4: unknown/unsupported discriminator -> refuse, never reinterpret.
        return "kind %r is not a ChainTxRef arm in the closed sec 9.3 union" % kind

    required, optional = CHAIN_TX_REF_ARMS[kind]

    declared = {"kind"} | set(required) | set(optional)
    extra = set(value) - declared
    if extra:
        # R6 closed-shape rule.
        return "undeclared member(s) for arm %r: %s" % (kind, sorted(extra))

    for name, predicate in sorted(required.items()):
        if name not in value:
            return "arm %r: required member %r missing" % (kind, name)
        if not predicate(value[name]):
            return "arm %r: member %r fails its declared type/format" % (kind, name)

    for name, predicate in sorted(optional.items()):
        if name in value and not predicate(value[name]):
            return "arm %r: optional member %r fails its declared type/format" % (
                kind,
                name,
            )

    return None


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

CHECKERS = {
    "AttestationRef": check_attestation_ref,
    "ChainTxRef": check_chain_tx_ref,
    "TxRef": check_chain_tx_ref,  # DACS-4 sec 9.3: "type TxRef = ChainTxRef"
}


def explain(vector: Dict[str, Any]) -> Tuple[str, str]:
    """Return (verdict, reason)."""
    declared_type = vector.get("type")
    checker = CHECKERS.get(declared_type)
    if checker is None:
        return "fail", "unknown declared reference type %r" % (declared_type,)
    reason = checker(vector.get("value"))
    if reason is None:
        return "pass", "conforms to the declared %s shape" % declared_type
    return "fail", reason


def evaluate(vector: Dict[str, Any]) -> str:
    """Return "pass" or "fail" for one conformance vector."""
    return explain(vector)[0]


def main(argv):
    if len(argv) < 2:
        print("usage: eval_artifact_reference_shapes.py <vectors.json> [--out FILE]")
        return 2
    with open(argv[1], "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    results = []
    for vector in doc["vectors"]:
        verdict, reason = explain(vector)
        results.append({"name": vector["name"], "verdict": verdict})
        print("%-52s %-5s  %s" % (vector["name"], verdict, reason))

    out = None
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    run = {
        "set": doc.get("set"),
        "impl": "pathos-dacs-ref@cross-run-1",
        "results": results,
    }
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(run, fh, indent=2)
            fh.write("\n")
        print("\nwrote %s (%d results)" % (out, len(results)))
    npass = sum(1 for r in results if r["verdict"] == "pass")
    print("pass=%d fail=%d total=%d" % (npass, len(results) - npass, len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
