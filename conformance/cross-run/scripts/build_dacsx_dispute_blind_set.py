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


def _blind_vector(vector: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in vector.items() if key not in STRIP}


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    deployment = json.loads(DEPLOYMENT_PATH.read_text(encoding="utf-8"))
    protocol_vectors = [_blind_vector(vector) for vector in protocol["vectors"]]
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
    for vector in protocol["vectors"]:
        answers[vector["name"]] = {
            "suite": "protocol",
            "expected": vector["expected"],
            "expectedRule": vector["expectedRule"],
            "rules": copy.deepcopy(vector["rules"]),
            "note": vector["note"],
        }
    for case in deployment["cases"]:
        answers[case["name"]] = {
            "suite": "deployment",
            "expected": case["expected"],
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
