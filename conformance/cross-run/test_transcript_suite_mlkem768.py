from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "impl" / "eval_transcript_suite_mlkem768.py"
SPEC = importlib.util.spec_from_file_location("eval_transcript_suite_mlkem768", MODULE_PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)

FIXTURE_PATH = HERE / "upstream" / "sdks-130-31389e51-transcript-encryption-v0.1.json"
BLIND_PATH = HERE / "blind" / "transcript-suite-mlkem768-v0.1.json"
ANSWERS_PATH = HERE / "keys" / "transcript-suite-mlkem768-v0.1.answers.json"


class TranscriptSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_reproduction_equality_on_every_compared_field(self):
        equal, rows = suite.reproduce(FIXTURE_PATH)
        self.assertTrue(equal)
        self.assertEqual(15, len(rows))
        self.assertTrue(all(matches for _, matches in rows))

    def test_keypair_determinism_and_fixture_public_keys(self):
        for label, binding in zip(
                ("memberA", "memberB"), self.fixture["envelope"]["recipientBindings"]):
            seed = bytes.fromhex(self.fixture["inputs"]["mlKemSeeds"][label])
            first = suite.derive_kem_keypair(seed)
            second = suite.derive_kem_keypair(seed)
            self.assertEqual(first, second)
            self.assertEqual(1184, len(first[0]))
            self.assertEqual(2400, len(first[1]))
            self.assertEqual(binding["publicKey"], suite._b64e(first[0]))

    def test_canonical_base64url_rejections(self):
        for bad in ("AA==", "AA+", "A", "AB"):
            with self.subTest(value=bad):
                with self.assertRaises(suite.Malformed):
                    suite._b64d(bad)

    def test_jcs_distinguishes_booleans_from_integers(self):
        self.assertEqual("true", suite.jcs(True))
        self.assertEqual("false", suite.jcs(False))
        self.assertEqual("1", suite.jcs(1))
        self.assertEqual("0", suite.jcs(0))

    def test_suite_version_boolean_true_is_malformed(self):
        vector = self._blind_vector("suite-version-boolean-true")
        self.assertIs(type(vector["envelope"]["suiteVersion"]), bool)
        self.assertEqual(("error", 1, "MALFORMED_ENVELOPE"),
                         self._verdict(vector))

    def test_suite_version_float_one_is_malformed(self):
        vector = self._blind_vector("suite-version-float-one")
        self.assertIs(type(vector["envelope"]["suiteVersion"]), float)
        self.assertEqual(("error", 1, "MALFORMED_ENVELOPE"),
                         self._verdict(vector))

    def test_binding_valid_from_boolean_is_malformed(self):
        vector = self._blind_vector("binding-valid-from-boolean")
        valid_from = vector["envelope"]["recipientBindings"][0]["validFrom"]
        self.assertIs(type(valid_from), bool)
        self.assertEqual(("error", 1, "MALFORMED_ENVELOPE"),
                         self._verdict(vector))

    def test_other_integer_fields_require_exact_int(self):
        base = self._blind_vector("exact-open-member-a")
        for field, value in (("expiresAt", 2000000000000.0),):
            with self.subTest(field=field):
                vector = copy.deepcopy(base)
                vector["envelope"]["recipientBindings"][0][field] = value
                self.assertEqual(("error", 1, "MALFORMED_ENVELOPE"),
                                 self._verdict(vector))
        for value in (True, 1900000000000.0):
            with self.subTest(authenticatedAt=value):
                vector = copy.deepcopy(base)
                vector["authority"]["authenticatedAt"] = value
                self.assertEqual(("error", 2, "AUTHENTICATED_TIME_INVALID"),
                                 self._verdict(vector))

    def test_each_blind_vector_matches_answer_key(self):
        blind = json.loads(BLIND_PATH.read_text(encoding="utf-8"))
        answers = json.loads(ANSWERS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(blind["count"], len(blind["vectors"]))
        for vector in blind["vectors"]:
            with self.subTest(vector=vector["name"]):
                got = suite.evaluate(vector)
                want = answers[vector["name"]]
                self.assertEqual((want["outcome"], want["step"], want["code"]),
                                 (got["outcome"], got["step"], got["code"]))
                if vector["kind"] == "seal":
                    self.assertEqual(want["outputs"], {
                        field: got["envelope"][field] for field in want["outputs"]
                    })

    def test_step_1_precedes_revocation(self):
        blind = json.loads(BLIND_PATH.read_text(encoding="utf-8"))
        base = next(v for v in blind["vectors"] if v["kind"] == "open")
        vector = copy.deepcopy(base)
        vector["envelope"]["tag"] += "="
        coordinate = (vector["envelope"]["recipientBindings"][0]["member"] + "|"
                      + vector["envelope"]["recipientBindings"][0]["keyId"])
        vector["authority"]["keyStatus"][coordinate] = "revoked"
        got = suite.evaluate(vector)
        self.assertEqual(("error", 1), (got["outcome"], got["step"]))

    def test_step_2_precedes_stale_content_hash(self):
        blind = json.loads(BLIND_PATH.read_text(encoding="utf-8"))
        base = next(v for v in blind["vectors"] if v["kind"] == "open")
        vector = copy.deepcopy(base)
        signature = vector["envelope"]["recipientBindings"][0]["keySig"]["value"]
        vector["envelope"]["recipientBindings"][0]["keySig"]["value"] = suite._b64e(
            bytes([suite._b64d(signature)[0] ^ 1]) + suite._b64d(signature)[1:])
        ciphertext = suite._b64d(vector["envelope"]["ciphertext"])
        vector["envelope"]["ciphertext"] = suite._b64e(
            bytes([ciphertext[0] ^ 1]) + ciphertext[1:])
        got = suite.evaluate(vector)
        self.assertEqual(("fail", 2), (got["outcome"], got["step"]))

    @staticmethod
    def _blind_vector(name):
        blind = json.loads(BLIND_PATH.read_text(encoding="utf-8"))
        return next(copy.deepcopy(vector) for vector in blind["vectors"]
                    if vector["name"] == name)

    @staticmethod
    def _verdict(vector):
        got = suite.evaluate(vector)
        return got["outcome"], got["step"], got["code"]


if __name__ == "__main__":
    unittest.main()
