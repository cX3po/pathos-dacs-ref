#!/usr/bin/env python3
"""Mechanically re-check the independence claims made for this cross-run.

A cross-run is only evidence if the second implementation did not read the first one's
answers. That is a claim about *code*, so it is checked by running the code rather than
by trusting the description.

Three checks, all of which must pass:

  1. NO ANSWER FIELDS IN THE INPUTS.
     `expected`, `want` and `note` carry the authored verdict or its rationale. None may
     appear in any blinded input.

  2. NO NAME DEPENDENCE.
     The runners hand the whole vector to `evaluate()`, so `name` IS present in the object
     the evaluator receives. What must hold is that nothing *reads or branches on* it:
     re-evaluating every vector with `name` deleted must change zero verdicts, and no
     vector name may appear anywhere in evaluator source. (The second check matters on its
     own: in signature-value-encoding-v0.1, seven of ten names end in `-rejected`, so a
     name-reading evaluator would score 10/10 while proving nothing.)

  3. NO SUPPLIED-EXPECTATION DEPENDENCE.
     `sb3-eip3009-nonce-v0.1` carries `expectedNonce` — the nonce the record claims. It is
     an input field rather than a verdict, but it is still a supplied expected *result*, so
     the evaluator must not depend on it: it derives the nonce from (jobId, phaseIndex) per
     §9.5.8 and only then compares. Deleting `expectedNonce` outright must change zero
     verdicts.

Exit 0 if every check passes; 1 otherwise. Standard library only.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANSWER_FIELDS = ("expected", "want", "note")
SUPPLIED_EXPECTATION_FIELDS = ("expectedNonce",)

SETS = {
    "signature-value-encoding-v0.1": "eval_signature_value_encoding",
    "artifact-reference-shapes-v0.1": "eval_artifact_reference_shapes",
    "sb3-eip3009-nonce-v0.1": "eval_sb3_eip3009_nonce",
    "x402-receipt-hash-v0.1": "eval_x402_receipt_hash",
    "transcript-suite-mlkem768-v0.1": "eval_transcript_suite_mlkem768",
}


def load_evaluator(module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name, HERE / "impl" / f"{module_name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    failures: list[str] = []
    checked = 0

    sources = {name: (HERE / "impl" / f"{name}.py").read_text(encoding="utf-8")
               for name in SETS.values()}

    for set_name, module_name in SETS.items():
        blind = json.loads((HERE / "blind" / f"{set_name}.json").read_text(encoding="utf-8"))
        vectors = blind["vectors"]
        evaluate = load_evaluator(module_name).evaluate

        # 1 — no answer fields survived blinding.
        for vector in vectors:
            for field in ANSWER_FIELDS:
                if field in vector:
                    failures.append(f"{set_name}/{vector.get('name')}: answer field {field!r} present")

        # 2b — no vector name appears in ANY evaluator source (not just its own).
        for vector in vectors:
            name = vector.get("name")
            for other, source in sources.items():
                if name and name in source:
                    failures.append(f"{set_name}: vector name {name!r} appears in {other}.py")

        for vector in vectors:
            checked += 1
            baseline = evaluate(vector)

            # 2a — deleting `name` must not move the verdict.
            without_name = {k: v for k, v in vector.items() if k != "name"}
            if evaluate(without_name) != baseline:
                failures.append(
                    f"{set_name}/{vector.get('name')}: verdict depends on the vector NAME")

            # 3 — deleting a supplied expectation must not move the verdict.
            without_expectation = {k: v for k, v in vector.items()
                                   if k not in SUPPLIED_EXPECTATION_FIELDS}
            if without_expectation != vector and evaluate(without_expectation) != baseline:
                failures.append(
                    f"{set_name}/{vector.get('name')}: verdict depends on a SUPPLIED EXPECTATION")

    print(f"independence checks over {checked} vectors in {len(SETS)} sets")
    if failures:
        print(f"FAILED — {len(failures)} problem(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS — no answer fields, no name dependence, no supplied-expectation dependence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
