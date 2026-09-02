#!/usr/bin/env python3
"""Independent evaluator for dacs-transcript-mlkem768-a256gcm v1.

Implemented solely from ``.crossrun-input/profile.md`` sections 1--9.  It
does not read an answer key and ``evaluate`` does not inspect vector names.

Cryptographic mapping (explicit, per the supplied profile):

* ML-KEM-768 is ``kyber_py.ml_kem.ML_KEM_768``.  Deterministic keygen calls
  ``_keygen_internal(seed[0:32], seed[32:64])``; deterministic encapsulation
  calls ``_encaps_internal(ek, m)``, whose kyber-py 1.2.0 return order is
  ``(shared_secret, ciphertext)``; decapsulation calls ``decaps(dk, ct)``.
* Ed25519 is cryptography's ``Ed25519PrivateKey.from_private_bytes(seed32)``.
* AES-256-GCM is cryptography's ``AESGCM``.  The ML-KEM shared secret is used
  directly as the wrap key, wrap AAD is empty, and content AAD is precisely
  UTF8(JCS(header)).

The repository's standard JCS adapter wraps an external checkout and is not
importable as a canonicalisation library.  This module therefore implements
RFC 8785 for the profile's value subset (strings, safe integers, booleans,
null, arrays and objects), including CORE CF-1 values-only NFC, in ``jcs``.
Object member names are not normalised and sort by UTF-16 code units.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_768

SUITE_ID = "dacs-transcript-mlkem768-a256gcm"
SUITE_VERSION = 1
ENVELOPE_KEYS = {
    "envelopeVersion", "suiteId", "suiteVersion", "channelId",
    "memberSetHash", "recipientBindingsHash", "plaintextHash",
    "recipientBindings", "wraps", "iv", "ciphertext", "tag", "contentHash",
}
BINDING_KEYS = {
    "keyBindingVersion", "member", "keyId", "kem", "publicKey",
    "validFrom", "expiresAt", "keySig",
}
SIG_KEYS = {"signatureVersion", "signer", "algorithm", "value"}
WRAP_KEYS = {"member", "keyId", "kemCiphertext", "wrapped"}
SAFE_MAX = 2**53 - 1
LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
CCI = re.compile(r"cci:[0-9a-f]{64}\Z")
KEY_ID = re.compile(r".+", re.DOTALL)
_B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")


class Malformed(ValueError):
    """The envelope is structurally malformed (profile step 1)."""


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def _string(value: str) -> str:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("lone surrogate is outside the JCS input domain")
    return json.dumps(unicodedata.normalize("NFC", value), ensure_ascii=False,
                      separators=(",", ":"))


def jcs(value: Any) -> str:
    """RFC 8785 serialization for the profile subset, with CF-1 values NFC."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > SAFE_MAX:
            raise ValueError("integer is outside the interoperable safe range")
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        parts = []
        for key in sorted(value, key=_utf16_key):
            # CF-1 applies only to string values, never member names.
            encoded_key = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            parts.append(encoded_key + ":" + jcs(value[key]))
        return "{" + ",".join(parts) + "}"
    raise ValueError(f"unsupported JCS value type: {type(value).__name__}")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: Any, length: int | None = None) -> bytes:
    if not isinstance(value, str) or "=" in value or not _B64URL.fullmatch(value):
        raise Malformed("non-canonical base64url")
    if len(value) % 4 == 1:
        raise Malformed("invalid base64url length")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    except Exception as exc:
        raise Malformed("invalid base64url") from exc
    if _b64e(raw) != value:
        raise Malformed("non-canonical base64url trailing bits")
    if length is not None and len(raw) != length:
        raise Malformed(f"decoded field must be {length} bytes")
    return raw


def _hex(value: Any, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2 or not re.fullmatch(
            r"[0-9a-f]+", value):
        raise ValueError(f"expected {length}-byte lowercase hex")
    return bytes.fromhex(value)


def _hash_jcs(value: Any) -> str:
    return hashlib.sha256(jcs(value).encode()).hexdigest()


def derive_kem_keypair(seed64: bytes | str) -> tuple[bytes, bytes]:
    """FIPS 203 KeyGen_internal(d,z), with the required d||z seed split."""
    if isinstance(seed64, str):
        seed64 = _hex(seed64, 64)
    if not isinstance(seed64, bytes) or len(seed64) != 64:
        raise ValueError("ML-KEM seed must be exactly 64 bytes")
    return ML_KEM_768._keygen_internal(seed64[:32], seed64[32:])


def _ed_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def make_binding(unsigned: dict[str, Any], ed25519_seed: bytes | str) -> dict[str, Any]:
    """Sign one unsigned binding using the profile section 2 preimage."""
    if set(unsigned) != BINDING_KEYS - {"keySig"}:
        raise ValueError("unsigned binding has the wrong shape")
    if isinstance(ed25519_seed, str):
        ed25519_seed = _hex(ed25519_seed, 32)
    if not isinstance(ed25519_seed, bytes) or len(ed25519_seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    digest = hashlib.sha256(jcs(unsigned).encode()).hexdigest()
    message = b"dacs-transcript-kem-key:v1:" + digest.encode("ascii")
    signature = Ed25519PrivateKey.from_private_bytes(ed25519_seed).sign(message)
    signed = copy.deepcopy(unsigned)
    signed["keySig"] = {
        "signatureVersion": "1", "signer": unsigned["member"],
        "algorithm": "ed25519", "value": _b64e(signature),
    }
    return signed


def _header(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "suiteId": envelope["suiteId"], "suiteVersion": envelope["suiteVersion"],
        "transcriptVersion": "1", "channelId": envelope["channelId"],
        "memberSetHash": envelope["memberSetHash"],
        "recipientBindingsHash": envelope["recipientBindingsHash"],
        "plaintextHash": envelope["plaintextHash"],
    }


def _content_hash(envelope: dict[str, Any]) -> str:
    preimage = (jcs(_header(envelope)).encode() + jcs(envelope["wraps"]).encode()
                + _b64d(envelope["iv"], 12) + _b64d(envelope["ciphertext"])
                + _b64d(envelope["tag"], 16))
    return hashlib.sha256(preimage).hexdigest()


def _result(outcome: str, step: int, code: str, transcript: Any = None) -> dict[str, Any]:
    result = {"outcome": outcome, "step": step, "code": code}
    if transcript is not None:
        result["transcript"] = transcript
    return result


def _is_safe_nonnegative(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= SAFE_MAX


def _validate_shape(e: Any) -> None:
    if not isinstance(e, dict) or set(e) != ENVELOPE_KEYS:
        raise Malformed("envelope has the wrong exact shape")
    if e["envelopeVersion"] != "1" or e["suiteId"] != SUITE_ID or e["suiteVersion"] != 1:
        raise Malformed("unsupported envelope or suite version")
    if not isinstance(e["channelId"], str) or not e["channelId"] or unicodedata.normalize("NFC", e["channelId"]) != e["channelId"]:
        raise Malformed("channelId must be a non-empty NFC string")
    for key in ("memberSetHash", "recipientBindingsHash", "plaintextHash", "contentHash"):
        if not isinstance(e[key], str) or not LOWER_HEX_32.fullmatch(e[key]):
            raise Malformed(f"{key} is not canonical lowercase SHA-256 hex")
    _b64d(e["iv"], 12); _b64d(e["ciphertext"]); _b64d(e["tag"], 16)
    bindings, wraps = e["recipientBindings"], e["wraps"]
    if not isinstance(bindings, list) or not bindings or not isinstance(wraps, list):
        raise Malformed("recipient bindings and wraps must be non-empty arrays")
    if len(bindings) != len(wraps):
        raise Malformed("binding/wrap length mismatch")
    coordinates: list[tuple[str, str]] = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != BINDING_KEYS:
            raise Malformed("binding has the wrong exact shape")
        if binding["keyBindingVersion"] != "1" or binding["kem"] != "ml-kem-768":
            raise Malformed("unsupported binding version or KEM")
        member, key_id = binding["member"], binding["keyId"]
        if not isinstance(member, str) or not CCI.fullmatch(member):
            raise Malformed("member is not the supported canonical CCI form")
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id) or unicodedata.normalize("NFC", key_id) != key_id:
            raise Malformed("keyId must be a non-empty NFC string")
        if not _is_safe_nonnegative(binding["validFrom"]) or not _is_safe_nonnegative(binding["expiresAt"]) or binding["expiresAt"] <= binding["validFrom"]:
            raise Malformed("invalid binding validity window")
        _b64d(binding["publicKey"], 1184)
        sig = binding["keySig"]
        if not isinstance(sig, dict) or set(sig) != SIG_KEYS:
            raise Malformed("keySig has the wrong exact shape")
        if sig["signatureVersion"] != "1" or sig["signer"] != member or sig["algorithm"] != "ed25519":
            raise Malformed("keySig metadata is invalid")
        _b64d(sig["value"], 64)
        coordinates.append((member, key_id))
    members = [member for member, _ in coordinates]
    if len(set(coordinates)) != len(coordinates) or len(set(members)) != len(members):
        raise Malformed("duplicate recipient")
    if members != sorted(members, key=lambda s: s.encode("utf-8")):
        raise Malformed("recipient bindings are not canonically ordered")
    for index, wrap in enumerate(wraps):
        if not isinstance(wrap, dict) or set(wrap) != WRAP_KEYS:
            raise Malformed("wrap has the wrong exact shape")
        if (wrap["member"], wrap["keyId"]) != coordinates[index]:
            raise Malformed("wrap/binding coordinate mismatch")
        _b64d(wrap["kemCiphertext"], 1088)
        _b64d(wrap["wrapped"], 60)


def _step2(envelope: dict[str, Any], authority: dict[str, Any]) -> dict[str, Any] | None:
    authenticated_at = authority.get("authenticatedAt")
    if not _is_safe_nonnegative(authenticated_at):
        return _result("indeterminate", 2, "AUTHENTICATED_TIME_UNAVAILABLE")
    signing_keys = authority.get("signingKeys")
    statuses = authority.get("keyStatus")
    if not isinstance(signing_keys, dict) or not isinstance(statuses, dict):
        return _result("indeterminate", 2, "AUTHORITY_UNAVAILABLE")
    for binding in envelope["recipientBindings"]:
        member = binding["member"]
        public_hex = signing_keys.get(member)
        if public_hex is None:
            return _result("indeterminate", 2, "SIGNING_KEY_UNAVAILABLE")
        try:
            public = _hex(public_hex, 32)
        except ValueError:
            return _result("indeterminate", 2, "SIGNING_KEY_UNAVAILABLE")
        unsigned = {key: value for key, value in binding.items() if key != "keySig"}
        digest = hashlib.sha256(jcs(unsigned).encode()).hexdigest()
        message = b"dacs-transcript-kem-key:v1:" + digest.encode("ascii")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                _b64d(binding["keySig"]["value"], 64), message)
        except (InvalidSignature, ValueError):
            return _result("fail", 2, "BAD_KEY_SIGNATURE")
        if not (binding["validFrom"] <= authenticated_at < binding["expiresAt"]):
            return _result("fail", 2, "KEY_OUTSIDE_VALIDITY_WINDOW")
        status = statuses.get(member + "|" + binding["keyId"])
        if status in (None, "unavailable", "indeterminate"):
            return _result("indeterminate", 2, "KEY_STATUS_UNAVAILABLE")
        if status != "current":
            return _result("fail", 2, "KEY_REVOKED")
    return None


def verify_integrity(envelope: dict[str, Any]) -> dict[str, Any]:
    """Run the authority-independent verifier steps 1, 3 and 4."""
    try:
        _validate_shape(envelope)
    except (Malformed, ValueError, TypeError, KeyError):
        return _result("error", 1, "MALFORMED_ENVELOPE")
    members = [binding["member"] for binding in envelope["recipientBindings"]]
    if _hash_jcs(members) != envelope["memberSetHash"]:
        return _result("fail", 3, "MEMBER_SET_HASH_MISMATCH")
    if _hash_jcs(envelope["recipientBindings"]) != envelope["recipientBindingsHash"]:
        return _result("fail", 3, "RECIPIENT_BINDINGS_HASH_MISMATCH")
    try:
        actual = _content_hash(envelope)
    except (Malformed, ValueError, TypeError, KeyError):
        return _result("error", 1, "MALFORMED_ENVELOPE")
    if actual != envelope["contentHash"]:
        return _result("fail", 4, "CONTENT_HASH_MISMATCH")
    return _result("pass", 4, "INTEGRITY_VERIFIED")


def seal(transcript: dict[str, Any], channel_id: str, bindings: list[dict[str, Any]],
         randomness: dict[str, Any], authority: dict[str, Any]) -> dict[str, Any]:
    """Seal a transcript using deterministic randomness supplied for testing."""
    if not isinstance(transcript, dict) or transcript.get("authenticatedTranscriptVersion") != "1":
        raise ValueError("plaintext must be an authenticated transcript v1 object")
    if transcript.get("channelId") != channel_id:
        raise ValueError("transcript channelId does not match")
    ordered = sorted(copy.deepcopy(bindings), key=lambda b: b["member"].encode("utf-8"))
    members = [binding["member"] for binding in ordered]
    if len(set(members)) != len(members) or transcript.get("members") != members:
        raise ValueError("bindings must bijectively match the ordered transcript roster")
    cek = _hex(randomness["cek"], 32)
    iv = _hex(randomness["iv"], 12)
    encapsulations = randomness["encapsulations"]
    wrap_ivs = randomness["wrapIvs"]
    if len(encapsulations) != len(ordered) or len(wrap_ivs) != len(ordered):
        raise ValueError("randomness count must equal recipient count")
    probe = {
        "envelopeVersion": "1", "suiteId": SUITE_ID, "suiteVersion": 1,
        "channelId": channel_id, "memberSetHash": _hash_jcs(members),
        "recipientBindingsHash": _hash_jcs(ordered),
        "plaintextHash": hashlib.sha256(jcs(transcript).encode()).hexdigest(),
        "recipientBindings": ordered, "wraps": [], "iv": "", "ciphertext": "",
        "tag": "", "contentHash": "0" * 64,
    }
    try:
        _validate_shape({**probe, "wraps": [
            {"member": b["member"], "keyId": b["keyId"],
             "kemCiphertext": _b64e(b"\0" * 1088), "wrapped": _b64e(b"\0" * 60)}
            for b in ordered], "iv": _b64e(b"\0" * 12), "tag": _b64e(b"\0" * 16)})
    except Malformed as exc:
        raise ValueError(str(exc)) from exc
    auth_failure = _step2(probe, authority)
    if auth_failure:
        raise ValueError(f"binding authority rejected sealing: {auth_failure['code']}")
    wraps = []
    for index, binding in enumerate(ordered):
        ek = _b64d(binding["publicKey"], 1184)
        m = _hex(encapsulations[index], 32)
        shared_secret, kem_ciphertext = ML_KEM_768._encaps_internal(ek, m)
        wrap_iv = _hex(wrap_ivs[index], 12)
        wrapped = wrap_iv + AESGCM(shared_secret).encrypt(wrap_iv, cek, b"")
        wraps.append({"member": binding["member"], "keyId": binding["keyId"],
                      "kemCiphertext": _b64e(kem_ciphertext), "wrapped": _b64e(wrapped)})
    probe["wraps"] = wraps
    aad = jcs(_header(probe)).encode()
    encrypted = AESGCM(cek).encrypt(iv, jcs(transcript).encode(), aad)
    probe["iv"], probe["ciphertext"], probe["tag"] = (
        _b64e(iv), _b64e(encrypted[:-16]), _b64e(encrypted[-16:]))
    probe["contentHash"] = _content_hash(probe)
    return probe


def _json_object(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON member")
            out[key] = value
        return out
    text = raw.decode("utf-8", "strict")
    value = json.loads(text, object_pairs_hook=pairs,
                       parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")),
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    if not isinstance(value, dict) or jcs(value).encode() != raw:
        raise ValueError("plaintext is not one canonical JSON object")
    return value


def open_envelope(envelope: dict[str, Any], recipient: dict[str, Any],
                  authority: dict[str, Any]) -> dict[str, Any]:
    """Run all eight profile verification steps, stopping at the first failure."""
    try:
        _validate_shape(envelope)
    except (Malformed, ValueError, TypeError, KeyError):
        return _result("error", 1, "MALFORMED_ENVELOPE")
    authority_result = _step2(envelope, authority)
    if authority_result:
        return authority_result
    members = [binding["member"] for binding in envelope["recipientBindings"]]
    if _hash_jcs(members) != envelope["memberSetHash"]:
        return _result("fail", 3, "MEMBER_SET_HASH_MISMATCH")
    if _hash_jcs(envelope["recipientBindings"]) != envelope["recipientBindingsHash"]:
        return _result("fail", 3, "RECIPIENT_BINDINGS_HASH_MISMATCH")
    if _content_hash(envelope) != envelope["contentHash"]:
        return _result("fail", 4, "CONTENT_HASH_MISMATCH")
    try:
        member, key_id = recipient["member"], recipient["keyId"]
        dk = _hex(recipient["secretKeyHex"], 2400)
    except (KeyError, TypeError, ValueError):
        return _result("fail", 5, "RECIPIENT_KEY_UNUSABLE")
    indexes = [i for i, wrap in enumerate(envelope["wraps"])
               if wrap["member"] == member and wrap["keyId"] == key_id]
    if len(indexes) != 1:
        return _result("fail", 5, "RECIPIENT_NOT_FOUND")
    wrap = envelope["wraps"][indexes[0]]
    try:
        secret = ML_KEM_768.decaps(dk, _b64d(wrap["kemCiphertext"], 1088))
        wrapped = _b64d(wrap["wrapped"], 60)
        cek = AESGCM(secret).decrypt(wrapped[:12], wrapped[12:], b"")
    except Exception:
        return _result("fail", 5, "CEK_WRAP_AUTHENTICATION_FAILED")
    try:
        encrypted = _b64d(envelope["ciphertext"]) + _b64d(envelope["tag"], 16)
        plaintext = AESGCM(cek).decrypt(_b64d(envelope["iv"], 12), encrypted,
                                        jcs(_header(envelope)).encode())
        transcript = _json_object(plaintext)
    except Exception:
        return _result("fail", 6, "CONTENT_AUTHENTICATION_FAILED")
    if hashlib.sha256(plaintext).hexdigest() != envelope["plaintextHash"]:
        return _result("fail", 7, "PLAINTEXT_HASH_MISMATCH")
    if (transcript.get("authenticatedTranscriptVersion") != "1"
            or transcript.get("channelId") != envelope["channelId"]
            or transcript.get("members") != members):
        return _result("fail", 8, "TRANSCRIPT_ROSTER_MISMATCH")
    return _result("pass", 8, "OPENED", transcript)


def _fixture_material(inputs: dict[str, Any], key_id: str, valid_from: int,
                      expires_at: int, authenticated_at: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    bindings = []
    signing_keys: dict[str, str] = {}
    statuses: dict[str, str] = {}
    for label in sorted(inputs["ed25519Seeds"]):
        ed_seed = _hex(inputs["ed25519Seeds"][label], 32)
        member = "cci:" + _ed_public(ed_seed).hex()
        ek, _ = derive_kem_keypair(inputs["mlKemSeeds"][label])
        unsigned = {"keyBindingVersion": "1", "member": member, "keyId": key_id,
                    "kem": "ml-kem-768", "publicKey": _b64e(ek),
                    "validFrom": valid_from, "expiresAt": expires_at}
        bindings.append(make_binding(unsigned, ed_seed))
        signing_keys[member] = _ed_public(ed_seed).hex()
        statuses[member + "|" + key_id] = "current"
    return bindings, {"authenticatedAt": authenticated_at,
                      "signingKeys": signing_keys, "keyStatus": statuses}


def evaluate(vector: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one blind vector solely from its data (never its name/answers)."""
    kind = vector.get("kind")
    if kind == "seal":
        bindings, authority = _fixture_material(
            vector["inputs"], vector["keyId"], vector["validFrom"],
            vector["expiresAt"], vector["authenticatedAt"])
        envelope = seal(vector["transcript"], vector["channelId"], bindings,
                        vector["inputs"]["randomness"], authority)
        hashes = {key: envelope[key] for key in
                  ("memberSetHash", "recipientBindingsHash", "plaintextHash", "contentHash")}
        return {"outcome": "pass", "step": 8, "code": "SEALED",
                "envelope": envelope, "hashes": hashes}
    if kind == "open":
        opened = open_envelope(vector["envelope"], vector["recipient"], vector["authority"])
        return {key: opened[key] for key in ("outcome", "step", "code")}
    return _result("error", 1, "UNKNOWN_VECTOR_KIND")


COMPARE_FIELDS = ("memberSetHash", "recipientBindingsHash", "plaintextHash",
                  "contentHash", "iv", "ciphertext", "tag")


def reproduce(path: Path) -> tuple[bool, list[tuple[str, bool]]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    source_bindings = fixture["envelope"]["recipientBindings"]
    bindings, authority = _fixture_material(
        fixture["inputs"], source_bindings[0]["keyId"],
        source_bindings[0]["validFrom"], source_bindings[0]["expiresAt"],
        fixture["authenticatedAt"])
    got = seal(fixture["transcript"], fixture["transcript"]["channelId"], bindings,
               fixture["inputs"]["randomness"], authority)
    rows: list[tuple[str, bool]] = []
    for field in COMPARE_FIELDS:
        rows.append((field, got[field] == fixture["envelope"][field]
                     and (field not in fixture["expected"] or got[field] == fixture["expected"][field])))
    for index, binding in enumerate(got["recipientBindings"]):
        rows.append((f"binding[{index}].publicKey",
                     binding["publicKey"] == source_bindings[index]["publicKey"]))
        rows.append((f"binding[{index}].keySig.value",
                     binding["keySig"]["value"] == source_bindings[index]["keySig"]["value"]))
    for index, wrap in enumerate(got["wraps"]):
        rows.append((f"wrap[{index}].kemCiphertext",
                     wrap["kemCiphertext"] == fixture["envelope"]["wraps"][index]["kemCiphertext"]))
        rows.append((f"wrap[{index}].wrapped",
                     wrap["wrapped"] == fixture["envelope"]["wraps"][index]["wrapped"]))
    return all(equal for _, equal in rows), rows


def _run_blind(input_path: Path, output_path: Path) -> None:
    blind = json.loads(input_path.read_text(encoding="utf-8"))
    results = []
    for vector in blind["vectors"]:
        evaluated = evaluate(vector)
        results.append({"name": vector.get("name"), "outcome": evaluated["outcome"],
                        "step": evaluated["step"], "code": evaluated["code"]})
    run = {"set": blind["set"], "impl": "pathos-dacs-ref@cross-run-2",
           "results": results}
    output_path.write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--reproduce", type=Path)
    args = parser.parse_args(argv)
    if args.reproduce:
        equal, rows = reproduce(args.reproduce)
        print("field                                      result")
        print("-----------------------------------------  -----")
        for field, matches in rows:
            print(f"{field:41}  {'EQUAL' if matches else 'NOT EQUAL'}")
        print(f"TOTAL                                      {'ALL EQUAL' if equal else 'DIFFERENT'}")
        return 0 if equal else 1
    if args.input is None or args.out is None:
        parser.error("blind input and --out are required")
    _run_blind(args.input, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
