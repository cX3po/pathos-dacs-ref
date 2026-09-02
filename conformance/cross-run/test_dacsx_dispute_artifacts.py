from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "impl" / "eval_dacsx_dispute_artifacts.py"
SPEC = importlib.util.spec_from_file_location("eval_dacsx_dispute_artifacts", MODULE_PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)

BLIND_PATH = HERE / "blind" / "dacsx-dispute-artifacts-v0.1.json"
ANSWERS_PATH = HERE / "keys" / "dacsx-dispute-artifacts-v0.1.answers.json"


class DeliveryRemedyArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blind = json.loads(BLIND_PATH.read_text(encoding="utf-8"))
        cls.answers = json.loads(ANSWERS_PATH.read_text(encoding="utf-8"))
        suite.configure_bases(cls.blind["fixtures"], cls.blind["manifests"])

    def vector(self, name):
        return next(copy.deepcopy(vector) for vector in self.blind["vectors"]
                    if vector["name"] == name)

    def rebind_mutated_funding(self, value):
        value["artifacts"]["terminal"]["fundingEvidenceRef"]["contentHash"] = (
            suite._content_hash(value["artifacts"]["funding"]))

    def test_patch_application_add_remove_replace_and_deep_copy(self):
        base = {"items": ["a", "c"], "nested": {"value": 1}}
        got = suite.apply_patch(base, [
            {"op": "add", "path": ["items", 1], "value": "b"},
            {"op": "replace", "path": ["nested", "value"], "value": 2},
            {"op": "remove", "path": ["items", 0]},
        ])
        self.assertEqual({"items": ["b", "c"], "nested": {"value": 2}}, got)
        self.assertEqual({"items": ["a", "c"], "nested": {"value": 1}}, base)

    def test_dreb_exact_mapping_accepts(self):
        got = suite.evaluate(self.vector("release-complete-budget"))
        self.assertEqual(("verified", "DRV"), (got["result"], got["rule"]))

    def test_dreb_rehash_prefix_truncation_and_zero_are_rejected(self):
        names = (
            "description-sha256-prefix", "delivery-hash-text-rehash",
            "delivery-padding-truncation", "zero-deliverable",
            "decision-hash-text-rehash", "zero-decision-reason",
        )
        for name in names:
            with self.subTest(vector=name):
                self.assertEqual("rejected", suite.evaluate(self.vector(name))["result"])

    def test_signature_tamper_is_rejected(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        signature = value["artifacts"]["agreement"]["signatures"][0]["value"]
        value["artifacts"]["agreement"]["signatures"][0]["value"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:])
        got = suite.evaluate_protocol(value)
        self.assertEqual(("rejected", "DRA-3"), (got["result"], got["rule"]))

    def test_pending_funding_finality_is_not_verified(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["artifacts"]["funding"]["finality"]["status"] = "pending"
        self.rebind_mutated_funding(value)
        got = suite.evaluate_protocol(value, _skip_signatures_for_tests=True)
        self.assertEqual(("indeterminate", "DRF-6"), (got["result"], got["rule"]))

    def test_empty_funding_event_set_is_not_verified(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["artifacts"]["funding"]["fundingEventRefs"] = []
        self.rebind_mutated_funding(value)
        got = suite.evaluate_protocol(value, _skip_signatures_for_tests=True)
        self.assertEqual(("rejected", "DRF-3"), (got["result"], got["rule"]))

    def test_duplicate_funding_event_set_is_rejected(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["artifacts"]["funding"]["fundingEventRefs"].append(copy.deepcopy(
            value["artifacts"]["funding"]["fundingEventRefs"][0]))
        self.rebind_mutated_funding(value)
        got = suite.evaluate_protocol(value, _skip_signatures_for_tests=True)
        self.assertEqual(("rejected", "DRF-3"), (got["result"], got["rule"]))

    def test_empty_terminal_event_set_is_not_verified(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["artifacts"]["terminal"]["terminalEventRefs"] = []
        got = suite.evaluate_protocol(value, _skip_signatures_for_tests=True)
        self.assertEqual(("rejected", "DRT-4"), (got["result"], got["rule"]))

    def test_signature_test_seam_refuses_non_fixture_material(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["fixtureOnly"] = False
        got = suite.evaluate_protocol(value, _skip_signatures_for_tests=True)
        self.assertEqual(("error", "DRV-3"), (got["result"], got["rule"]))

    def test_delivery_body_substitution_is_hash_bound(self):
        value = copy.deepcopy(self.blind["fixtures"]["release"])
        value["artifacts"]["delivery"]["outcome"] = "substituted"
        got = suite.evaluate_protocol(value)
        self.assertEqual(("rejected", "DREB-2"), (got["result"], got["rule"]))

    def test_evaluation_sequence_must_start_at_zero(self):
        got = suite.evaluate(self.vector("evaluation-seq-not-zero"))
        self.assertEqual(("rejected", "DRAA-6"), (got["result"], got["rule"]))

    def test_shipped_lifecycles_exercise_events_and_funding_finality(self):
        for base_name in ("release", "rejected-refund", "pre-submission-rejected-refund"):
            with self.subTest(base=base_name):
                value = self.blind["fixtures"][base_name]
                self.assertTrue(value["artifacts"]["funding"]["fundingEventRefs"])
                self.assertEqual("finalized", value["artifacts"]["funding"]["finality"]["status"])
                self.assertTrue(value["artifacts"]["terminal"]["terminalEventRefs"])
                self.assertEqual("verified", suite.evaluate_protocol(value)["result"])

    def test_drc_synthetic_all_pass_is_still_ineligible(self):
        got = suite.evaluate_deployment(self.blind["manifests"]["synthetic-control"])
        self.assertTrue(all(got[f"DRC-{index}"] == "pass" for index in range(1, 13)))
        self.assertEqual("verified", got["result"])
        self.assertFalse(got["registrationEligible"])

    def test_each_blind_vector_exact_result_and_rule_matches_key(self):
        self.assertEqual(self.blind["count"], len(self.blind["vectors"]))
        for vector in self.blind["vectors"]:
            with self.subTest(vector=vector["name"]):
                got = suite.evaluate(vector)
                want = self.answers[vector["name"]]
                self.assertEqual(
                    (want["expected"], want["crossRunExpectedRule"]),
                    (got["result"], got["rule"]),
                )


if __name__ == "__main__":
    unittest.main()
