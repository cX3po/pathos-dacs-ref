#!/usr/bin/env python3
"""Derive the delivery-or-remedy blind set and steward answer key."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
CROSS_RUN = HERE.parent
UPSTREAM = CROSS_RUN / "upstream" / "dacs-standard-372-e5384514-delivery-remedy"
PROTOCOL_PATH = UPSTREAM / "candidate-vectors-v0.1.json"
DEPLOYMENT_PATH = UPSTREAM / "deployment-capabilities-v0.1.json"
BLIND_PATH = CROSS_RUN / "blind" / "dacsx-dispute-artifacts-v0.1.json"
ANSWERS_PATH = CROSS_RUN / "keys" / "dacsx-dispute-artifacts-v0.1.answers.json"
STRIP = {"expected", "expectedRule", "expectedFailedRules", "registrationEligible",
         "note", "rules"}

ADDITIONAL_PROTOCOL_VECTORS = [{
    "name": "evaluation-seq-not-zero",
    "base": "release",
    "expected": "rejected",
    "expectedRule": "DRAA-6",
    "rules": ["DRAA-6"],
    "note": "the first evaluation sequence must be zero",
    "patch": [{
        "op": "replace",
        "path": ["artifacts", "evaluation", "evaluationSeq"],
        "value": 1,
    }],
}]

# Rules emitted by this independent implementation where the steward key uses
# absent vocabulary or selects a different applicable/precedence rule.
CROSS_RUN_RULE_OVERRIDES = {
    "release-complete-budget": "DRV",
    "evaluator-rejection-refund": "DRV",
    "pre-submission-evaluator-rejection": "DRV",
    "expiry-before-submission": "DRV",
    "expiry-after-submission-grace": "DRV",
    "evaluator-primary-claim-collision": "DRA-3",
    "nonpositive-evaluation-window": "DRA-14",
    "evaluation-deadline-divergence": "DRA-14",
    "relayed-outer-submitter": "DRV",
    "eip1271-relayed-execution": "DRV",
    "rail-resolution-unavailable": "DRV-1",
    "runtime-code-unavailable": "DRJ-7",
    "terminal-finality-unavailable": "DRT-8",
    "decision-finalized-after-terminal": "DRD-11",
    "decision-artifact-unavailable": "DRD-4",
    "authenticated-native-contradiction": "DRJ-7",
    "malformed-native-bytes32": "DRV-3",
    "unsupported-profile-discriminator": "DRV-3",
}

DEPLOYMENT_RULE_OVERRIDES = {
    "synthetic-all-rules-control": "DRC",
    "source-to-bytecode-evidence-unavailable": "DRC-10",
    "malformed-deployment-manifest": "DRC-1",
}


def _blind_vector(vector: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in vector.items() if key not in STRIP}


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    deployment = json.loads(DEPLOYMENT_PATH.read_text(encoding="utf-8"))
    source_protocol_vectors = protocol["vectors"] + ADDITIONAL_PROTOCOL_VECTORS
    protocol_vectors = [_blind_vector(vector) for vector in source_protocol_vectors]
    deployment_vectors = [_blind_vector(case) for case in deployment["cases"]]
    names = [vector["name"] for vector in protocol_vectors + deployment_vectors]
    if len(names) != len(set(names)):
        raise ValueError("vector names are not unique across the two source packs")
    blind = {
        "set": "dacsx-dispute-artifacts-v0.1",
        "spec": "Delivery-or-remedy candidate sections 2-10",
        "count": len(names),
        "protocolCount": len(protocol_vectors),
        "deploymentCount": len(deployment_vectors),
        "fixtures": copy.deepcopy(protocol["fixtures"]),
        "manifests": copy.deepcopy(deployment["manifests"]),
        "vectors": protocol_vectors + deployment_vectors,
    }
    answers: dict[str, Any] = {}
    for vector in source_protocol_vectors:
        answers[vector["name"]] = {
            "suite": "protocol",
            "expected": vector["expected"],
            "expectedRule": vector["expectedRule"],
            "crossRunExpectedRule": CROSS_RUN_RULE_OVERRIDES.get(
                vector["name"], vector["expectedRule"]),
            "rules": copy.deepcopy(vector["rules"]),
            "note": vector["note"],
        }
    for case in deployment["cases"]:
        cross_run_rule = DEPLOYMENT_RULE_OVERRIDES.get(case["name"])
        if cross_run_rule is None:
            cross_run_rule = (case["expectedFailedRules"][0]
                              if case["expectedFailedRules"] else "DRC")
        answers[case["name"]] = {
            "suite": "deployment",
            "expected": case["expected"],
            "crossRunExpectedRule": cross_run_rule,
            "registrationEligible": case["registrationEligible"],
            "expectedFailedRules": copy.deepcopy(case["expectedFailedRules"]),
            "note": case["note"],
        }
    return blind, answers


def _serialized(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="report stale generated files without rewriting them")
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
        print(f"PASS — blind set and steward answer key are reproducible "
              f"({blind['protocolCount']} protocol + {blind['deploymentCount']} deployment)")
        return 0
    for path, text in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(f"wrote {blind['protocolCount']} protocol and {blind['deploymentCount']} deployment vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
