#!/usr/bin/env python3
"""Build the transcript-suite blind set from the pinned upstream fixture."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent
CROSS_RUN = HERE.parent
MODULE_PATH = CROSS_RUN / "impl" / "eval_transcript_suite_mlkem768.py"
FIXTURE_PATH = CROSS_RUN / "upstream" / "sdks-130-31389e51-transcript-encryption-v0.1.json"
BLIND_PATH = CROSS_RUN / "blind" / "transcript-suite-mlkem768-v0.1.json"
ANSWERS_PATH = CROSS_RUN / "keys" / "transcript-suite-mlkem768-v0.1.answers.json"
SEAL_OUTPUT_FIELDS = (
    "memberSetHash", "recipientBindingsHash", "plaintextHash", "contentHash",
    "ciphertext", "tag",
)

SPEC = importlib.util.spec_from_file_location("eval_transcript_suite_mlkem768", MODULE_PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


def _flip_b64(value: str) -> str:
    raw = suite._b64d(value)
    return suite._b64e(bytes([raw[0] ^ 1]) + raw[1:])


def _different_hash(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


def _reseal_content(envelope: dict[str, Any], transcript: dict[str, Any], cek_hex: str) -> None:
    """Encrypt plaintext under the envelope's current header and refresh contentHash."""
    iv = suite._b64d(envelope["iv"], 12)
    encrypted = AESGCM(bytes.fromhex(cek_hex)).encrypt(
        iv, suite.jcs(transcript).encode(), suite.jcs(suite._header(envelope)).encode())
    envelope["ciphertext"] = suite._b64e(encrypted[:-16])
    envelope["tag"] = suite._b64e(encrypted[-16:])
    envelope["contentHash"] = suite._content_hash(envelope)


def _open_vector(envelope: dict[str, Any], recipient: dict[str, Any],
                 authority: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "open", "envelope": copy.deepcopy(envelope),
            "recipient": copy.deepcopy(recipient), "authority": copy.deepcopy(authority)}


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    inputs = fixture["inputs"]
    source_bindings = fixture["envelope"]["recipientBindings"]
    key_id = source_bindings[0]["keyId"]
    valid_from = source_bindings[0]["validFrom"]
    expires_at = source_bindings[0]["expiresAt"]
    authenticated_at = fixture["authenticatedAt"]
    bindings, authority = suite._fixture_material(
        inputs, key_id, valid_from, expires_at, authenticated_at)
    envelope = suite.seal(fixture["transcript"], fixture["transcript"]["channelId"],
                          bindings, inputs["randomness"], authority)
    if any(envelope[field] != fixture["expected"][field] for field in SEAL_OUTPUT_FIELDS):
        raise RuntimeError("profile-derived seal no longer reproduces the pinned fixture")

    recipients: dict[str, dict[str, str]] = {}
    for label, ed_seed_hex in inputs["ed25519Seeds"].items():
        member = "cci:" + suite._ed_public(bytes.fromhex(ed_seed_hex)).hex()
        _, secret = suite.derive_kem_keypair(inputs["mlKemSeeds"][label])
        recipients[label] = {"member": member, "keyId": key_id,
                             "secretKeyHex": secret.hex()}

    vectors: list[dict[str, Any]] = []
    answers: dict[str, dict[str, Any]] = {}

    def add(name: str, vector: dict[str, Any], outcome: str, step: int, code: str,
            justification: str) -> None:
        vector = {"name": name, **vector}
        vectors.append(vector)
        answers[name] = {"outcome": outcome, "step": step, "code": code,
                         "justification": justification}

    seal_vector = {
        "kind": "seal", "inputs": copy.deepcopy(inputs),
        "transcript": copy.deepcopy(fixture["transcript"]),
        "channelId": fixture["transcript"]["channelId"], "keyId": key_id,
        "validFrom": valid_from, "expiresAt": expires_at,
        "authenticatedAt": authenticated_at,
    }
    add("seal-golden-inputs", seal_vector, "pass", 8, "SEALED",
        "The profile inputs reproduce the golden bytes and the resulting envelope opens for every member through step 8.")
    answers["seal-golden-inputs"]["outputs"] = {
        field: envelope[field] for field in SEAL_OUTPUT_FIELDS
    }

    base_a = _open_vector(envelope, recipients["memberA"], authority)
    base_b = _open_vector(envelope, recipients["memberB"], authority)
    add("exact-open-member-a", base_a, "pass", 8, "OPENED",
        "Member A passes all eight verification steps.")
    add("exact-open-member-b", base_b, "pass", 8, "OPENED",
        "Member B passes all eight verification steps.")

    vector = copy.deepcopy(base_a)
    vector["recipient"]["keyId"] += "-other"
    add("wrong-recipient-coordinate", vector, "fail", 5, "RECIPIENT_NOT_FOUND",
        "The exact recipient coordinate cannot be located at step 5.")

    vector = copy.deepcopy(base_a)
    _, outsider_secret = suite.derive_kem_keypair(inputs["mlKemSeeds"]["outsider"])
    vector["recipient"]["secretKeyHex"] = outsider_secret.hex()
    add("wrong-mlkem-secret", vector, "fail", 5, "CEK_WRAP_AUTHENTICATION_FAILED",
        "The wrong decapsulation key cannot authenticate the CEK wrap at step 5.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["ciphertext"] = _flip_b64(vector["envelope"]["ciphertext"])
    add("ciphertext-tamper-stale-content-hash", vector, "fail", 4, "CONTENT_HASH_MISMATCH",
        "The stale public content commitment mismatches at step 4.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["ciphertext"] = _flip_b64(vector["envelope"]["ciphertext"])
    vector["envelope"]["contentHash"] = suite._content_hash(vector["envelope"])
    add("ciphertext-tamper-recomputed-content-hash", vector, "fail", 6,
        "CONTENT_AUTHENTICATION_FAILED",
        "The recomputed public hash passes, but content GCM authentication fails at step 6.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["wraps"][0]["wrapped"] = _flip_b64(
        vector["envelope"]["wraps"][0]["wrapped"])
    add("wrap-tamper-stale-content-hash", vector, "fail", 4, "CONTENT_HASH_MISMATCH",
        "The stale commitment exposes the changed wrap at step 4.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["wraps"][0]["wrapped"] = _flip_b64(
        vector["envelope"]["wraps"][0]["wrapped"])
    vector["envelope"]["contentHash"] = suite._content_hash(vector["envelope"])
    add("wrap-tamper-recomputed-content-hash", vector, "fail", 5,
        "CEK_WRAP_AUTHENTICATION_FAILED",
        "The recomputed commitment passes, but wrap GCM authentication fails at step 5.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["channelId"] += "-changed"
    vector["envelope"]["contentHash"] = suite._content_hash(vector["envelope"])
    add("channel-id-change-recomputed-content-hash", vector, "fail", 6,
        "CONTENT_AUTHENTICATION_FAILED",
        "The changed header produces different AAD, so content authentication fails at step 6.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindings"][0]["keySig"]["value"] = _flip_b64(
        vector["envelope"]["recipientBindings"][0]["keySig"]["value"])
    add("modified-key-signature", vector, "fail", 2, "BAD_KEY_SIGNATURE",
        "The canonical but altered binding signature fails at step 2.")

    vector = copy.deepcopy(base_a)
    coordinate = recipients["memberA"]["member"] + "|" + key_id
    vector["authority"]["keyStatus"][coordinate] = "revoked"
    add("revoked-key", vector, "fail", 2, "KEY_REVOKED",
        "Authenticated revoked status fails at step 2.")

    vector = copy.deepcopy(base_a)
    vector["authority"]["keyStatus"][coordinate] = "unavailable"
    add("unavailable-key-status", vector, "indeterminate", 2, "KEY_STATUS_UNAVAILABLE",
        "Unavailable authenticated status is indeterminate at step 2.")

    vector = copy.deepcopy(base_a)
    vector["authority"]["authenticatedAt"] = expires_at
    add("expired-key", vector, "fail", 2, "KEY_OUTSIDE_VALIDITY_WINDOW",
        "The exclusive expiry boundary fails at step 2.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["suiteId"] += "-other"
    add("unsupported-suite-id", vector, "error", 1, "MALFORMED_ENVELOPE",
        "An unsupported suite selector is malformed at step 1.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["suiteVersion"] = 2
    add("unsupported-suite-version", vector, "error", 1, "MALFORMED_ENVELOPE",
        "An unsupported suite version is malformed at step 1.")

    vector = copy.deepcopy(base_a)
    del vector["envelope"]["recipientBindings"][0]
    del vector["envelope"]["wraps"][0]
    members = [item["member"] for item in vector["envelope"]["recipientBindings"]]
    vector["envelope"]["memberSetHash"] = suite._hash_jcs(members)
    vector["envelope"]["recipientBindingsHash"] = suite._hash_jcs(
        vector["envelope"]["recipientBindings"])
    vector["envelope"]["contentHash"] = suite._content_hash(vector["envelope"])
    add("missing-recipient-binding", vector, "fail", 5, "RECIPIENT_NOT_FOUND",
        "After self-consistent public hashes, the removed exact coordinate is absent at step 5.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindings"].append(copy.deepcopy(
        vector["envelope"]["recipientBindings"][0]))
    vector["envelope"]["wraps"].append(copy.deepcopy(vector["envelope"]["wraps"][0]))
    add("duplicate-recipient", vector, "error", 1, "MALFORMED_ENVELOPE",
        "The recipient roster is not duplicate-free at step 1.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindings"].reverse()
    vector["envelope"]["wraps"].reverse()
    add("reordered-bindings", vector, "error", 1, "MALFORMED_ENVELOPE",
        "Bindings are not in canonical member-byte order at step 1.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["tag"] += "="
    add("noncanonical-base64url-tag", vector, "error", 1, "MALFORMED_ENVELOPE",
        "Padded Base64URL is non-canonical and malformed at step 1.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["wraps"][0]["keyId"] += "-other"
    add("wrap-binding-coordinate-mismatch", vector, "error", 1, "MALFORMED_ENVELOPE",
        "The positional wrap/binding bijection is broken at step 1.")

    # Isolated semantic hash failures: re-encrypt under the deliberately stale
    # header so content AAD and contentHash remain otherwise consistent.
    vector = copy.deepcopy(base_a)
    vector["envelope"]["memberSetHash"] = _different_hash(
        vector["envelope"]["memberSetHash"])
    _reseal_content(vector["envelope"], fixture["transcript"], inputs["randomness"]["cek"])
    add("stale-member-set-hash-resealed-content", vector, "fail", 3,
        "MEMBER_SET_HASH_MISMATCH",
        "The memberSetHash is stale while content is sealed under that header and its contentHash is current, isolating step 3.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindingsHash"] = _different_hash(
        vector["envelope"]["recipientBindingsHash"])
    _reseal_content(vector["envelope"], fixture["transcript"], inputs["randomness"]["cek"])
    add("stale-recipient-bindings-hash-resealed-content", vector, "fail", 3,
        "RECIPIENT_BINDINGS_HASH_MISMATCH",
        "The recipientBindingsHash is stale while content is sealed under that header and its contentHash is current, isolating step 3.")

    vector = copy.deepcopy(base_a)
    coordinate_b = recipients["memberB"]["member"] + "|" + key_id
    vector["authority"]["keyStatus"][coordinate_b] = "revoked"
    add("member-b-revoked-open-member-a", vector, "fail", 2, "KEY_REVOKED",
        "Opening as member A still checks member B's authenticated status at step 2.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindings"][1]["keySig"]["value"] = _flip_b64(
        vector["envelope"]["recipientBindings"][1]["keySig"]["value"])
    vector["envelope"]["recipientBindingsHash"] = suite._hash_jcs(
        vector["envelope"]["recipientBindings"])
    _reseal_content(vector["envelope"], fixture["transcript"], inputs["randomness"]["cek"])
    add("member-b-bad-key-signature-open-member-a", vector, "fail", 2,
        "BAD_KEY_SIGNATURE",
        "Opening as member A still verifies member B's binding signature at step 2; later hashes and encryption are consistent.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["plaintextHash"] = _different_hash(
        vector["envelope"]["plaintextHash"])
    _reseal_content(vector["envelope"], fixture["transcript"], inputs["randomness"]["cek"])
    add("wrong-plaintext-hash-resealed-content", vector, "fail", 7,
        "PLAINTEXT_HASH_MISMATCH",
        "Content authenticates under a header containing the wrong plaintextHash, so only the recomputation at step 7 fails.")

    vector = copy.deepcopy(base_a)
    changed_transcript = copy.deepcopy(fixture["transcript"])
    changed_transcript["members"].reverse()
    vector["envelope"]["plaintextHash"] = hashlib.sha256(
        suite.jcs(changed_transcript).encode()).hexdigest()
    _reseal_content(vector["envelope"], changed_transcript, inputs["randomness"]["cek"])
    add("transcript-member-order-mismatch-resealed-content", vector, "fail", 8,
        "TRANSCRIPT_ROSTER_MISMATCH",
        "The decrypted transcript has a correct plaintextHash but its member order differs from the envelope roster at step 8.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["tag"] += "="
    vector["authority"]["keyStatus"][coordinate_b] = "revoked"
    add("malformed-plus-revoked-key", vector, "error", 1, "MALFORMED_ENVELOPE",
        "Malformed encoding at step 1 precedes the independently revoked member B key at step 2.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["recipientBindings"][0]["keySig"]["value"] = _flip_b64(
        vector["envelope"]["recipientBindings"][0]["keySig"]["value"])
    vector["envelope"]["recipientBindingsHash"] = suite._hash_jcs(
        vector["envelope"]["recipientBindings"])
    _reseal_content(vector["envelope"], fixture["transcript"], inputs["randomness"]["cek"])
    vector["envelope"]["contentHash"] = _different_hash(vector["envelope"]["contentHash"])
    add("bad-key-signature-plus-stale-content-hash", vector, "fail", 2,
        "BAD_KEY_SIGNATURE",
        "The bad binding signature at step 2 precedes the independently stale contentHash at step 4.")

    vector = copy.deepcopy(base_a)
    vector["envelope"]["memberSetHash"] = _different_hash(
        vector["envelope"]["memberSetHash"])
    add("stale-member-set-hash-plus-stale-content-hash", vector, "fail", 3,
        "MEMBER_SET_HASH_MISMATCH",
        "The stale memberSetHash at step 3 precedes the resulting stale contentHash at step 4.")

    blind = {"set": "transcript-suite-mlkem768-v0.1",
             "spec": "Candidate encrypted-transcript suite profile sections 1-9",
             "count": len(vectors), "vectors": vectors}
    return blind, answers


def _serialized(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail instead of writing if generated files differ")
    args = parser.parse_args(argv)
    blind, answers = build()
    generated = {BLIND_PATH: _serialized(blind), ANSWERS_PATH: _serialized(answers)}
    if args.check:
        stale = [path for path, text in generated.items()
                 if not path.exists() or path.read_text(encoding="utf-8") != text]
        if stale:
            for path in stale:
                print(f"DIFFERENT: {path.relative_to(CROSS_RUN)}")
            return 1
        print(f"PASS — blind set and answer key are reproducible ({blind['count']} vectors)")
        return 0
    for path, text in generated.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {blind['count']} vectors and {len(answers)} answer entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
