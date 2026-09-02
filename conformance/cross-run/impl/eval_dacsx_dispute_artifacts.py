#!/usr/bin/env python3
"""Independent verifier for the delivery-or-remedy candidate artifacts.

Implemented from ``.crossrun-input/candidate.md`` and the steward-authored
fixture shapes only.  The fixture format does not carry resolvers: section 9
resolution is therefore supplied by authenticated-status labels in
``externalEvidence``.  A ``verified`` label is never allowed to replace the
artifact, hash, signature, event-set, finality, or native-fact checks that can
be performed from the fixture itself.

The candidate requires signed phase-bound delivery ``SettlementEvidence`` but
does not pin that dependency's signing domain.  Delivery substitution is still
caught by recomputing its content hash and checking every carried reference and
native mapping.  The public fixture pack carries no signing seeds, so direct
rule tests may pass ``_skip_signatures_for_tests=True`` to ``evaluate_protocol``;
the seam is refused unless the materialized artifact set is marked
``fixtureOnly: true`` and is never used by the blind runner.

``evaluate`` never reads a vector name or an answer field.  The runner supplies
the pack's immutable base maps with ``configure_bases``; the vector contributes
only its ``base`` selector and patch operations.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROFILE = "delivery-or-remedy-v1"
LOWER_HASH = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
BYTES32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
JID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
UINT = re.compile(r"0|[1-9][0-9]*\Z")
EIP155 = re.compile(r"cci-xm:evm:(0|[1-9][0-9]*):(0x[0-9a-fA-F]{40})\Z")
STATUS = {"verified", "unavailable", "contradictory", "not-applicable"}
DOMAINS = {
    "agreement": "dacs-delivery-remedy-agreement:v1:",
    "job": "dacs-escrow-job-ref:v1:",
    "funding": "dacs-escrow-funding-evidence:v1:",
    "evaluation": "dacs-execution-evaluation:v1:",
    "decision": "dacs-escrow-decision:v1:",
    "dispute": "dacs-dispute-outcome:v1:",
    "terminal": "dacs-escrow-terminal-evidence:v1:",
}

_FIXTURES: dict[str, Any] = {}
_MANIFESTS: dict[str, Any] = {}


def configure_bases(fixtures: dict[str, Any], manifests: dict[str, Any]) -> None:
    """Install the base maps belonging to one blind pack."""
    global _FIXTURES, _MANIFESTS
    _FIXTURES = copy.deepcopy(fixtures)
    _MANIFESTS = copy.deepcopy(manifests)


def apply_patch(base: Any, operations: list[dict[str, Any]]) -> Any:
    """Apply the pack's add/remove/replace operations to a deep copy."""
    value = copy.deepcopy(base)
    if not isinstance(operations, list):
        raise ValueError("patch must be a list")
    for operation in operations:
        if not isinstance(operation, dict) or operation.get("op") not in {
                "add", "remove", "replace"}:
            raise ValueError("unsupported patch operation")
        path = operation.get("path")
        if not isinstance(path, list) or not path:
            raise ValueError("patch path must be a non-empty list")
        parent = value
        for segment in path[:-1]:
            if isinstance(parent, list):
                if type(segment) is not int or not 0 <= segment < len(parent):
                    raise ValueError("invalid list path")
                parent = parent[segment]
            elif isinstance(parent, dict):
                if not isinstance(segment, str) or segment not in parent:
                    raise ValueError("invalid object path")
                parent = parent[segment]
            else:
                raise ValueError("patch traverses a scalar")
        leaf = path[-1]
        op = operation["op"]
        if isinstance(parent, list):
            if type(leaf) is not int:
                raise ValueError("list index must be an integer")
            if op == "add":
                if not 0 <= leaf <= len(parent):
                    raise ValueError("invalid insertion index")
                parent.insert(leaf, copy.deepcopy(operation.get("value")))
            else:
                if not 0 <= leaf < len(parent):
                    raise ValueError("invalid list index")
                if op == "remove":
                    parent.pop(leaf)
                else:
                    parent[leaf] = copy.deepcopy(operation.get("value"))
        elif isinstance(parent, dict):
            if not isinstance(leaf, str):
                raise ValueError("object key must be a string")
            if op == "add":
                if leaf in parent:
                    raise ValueError("add target already exists")
                parent[leaf] = copy.deepcopy(operation.get("value"))
            else:
                if leaf not in parent:
                    raise ValueError("patch target does not exist")
                if op == "remove":
                    del parent[leaf]
                else:
                    parent[leaf] = copy.deepcopy(operation.get("value"))
        else:
            raise ValueError("patch parent is a scalar")
    return value


def _result(result: str, rule: str, detail: str) -> dict[str, str]:
    return {"result": result, "rule": rule, "detail": detail}


def _reject(rule: str, detail: str) -> dict[str, str]:
    return _result("rejected", rule, detail)


def _error(rule: str, detail: str) -> dict[str, str]:
    return _result("error", rule, detail)


def _indeterminate(rule: str, detail: str) -> dict[str, str]:
    return _result("indeterminate", rule, detail)


def _jcs(value: Any) -> bytes:
    """RFC-8785 serialization for the integer-only fixture value domain."""
    if isinstance(value, bool) or value is None or isinstance(value, (str, list, dict)):
        pass
    elif type(value) is int:
        if abs(value) > 2**53 - 1:
            raise ValueError("integer outside interoperable range")
    else:
        raise ValueError("unsupported canonical JSON value")
    if isinstance(value, list):
        return b"[" + b",".join(_jcs(item) for item in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("non-string object key")
        parts = []
        for key in sorted(value, key=lambda item: item.encode("utf-16-be", "surrogatepass")):
            encoded = json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode()
            parts.append(encoded + b":" + _jcs(value[key]))
        return b"{" + b",".join(parts) + b"}"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _unsigned(artifact: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in artifact.items()
            if key not in {"signature", "signatures"}}


def _content_hash(artifact: dict[str, Any]) -> str:
    return hashlib.sha256(_jcs(_unsigned(artifact))).hexdigest()


def _b64url(value: Any, length: int) -> bytes:
    if not isinstance(value, str) or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("non-canonical base64url")
    if len(value) % 4 == 1:
        raise ValueError("invalid base64url length")
    raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value or len(raw) != length:
        raise ValueError("invalid base64url value")
    return raw


def _verify_signature(public_keys: dict[str, Any], signer: Any, signature: Any,
                      domain: str, digest: str) -> bool:
    if not isinstance(signer, str) or not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519" or signer not in public_keys:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64url(public_keys[signer], 32))
        key.verify(_b64url(signature.get("value"), 64),
                   domain.encode() + digest.encode())
        return True
    except (ValueError, InvalidSignature):
        return False


def _hash(value: Any) -> bool:
    return isinstance(value, str) and LOWER_HASH.fullmatch(value) is not None


def _uint(value: Any) -> bool:
    return isinstance(value, str) and UINT.fullmatch(value) is not None


def _int(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**53 - 1


def _ref(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"kind", "locator", "contentHash"}
            and isinstance(value["kind"], str) and isinstance(value["locator"], str)
            and _hash(value["contentHash"]))


def _event_ref(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"kind", "chainId", "txHash", "logIndex"}
            and value["kind"] == "evm-event" and _int(value["chainId"])
            and isinstance(value["txHash"], str)
            and re.fullmatch(r"0x[0-9a-fA-F]{64}", value["txHash"]) is not None
            and _int(value["logIndex"]))


def _sig_shape(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("algorithm") != "ed25519":
        return False
    try:
        _b64url(value.get("value"), 64)
    except ValueError:
        return False
    return isinstance(value.get("signer", value.get("party")), str)


def _claim_account(claim: Any) -> tuple[int, str] | None:
    if not isinstance(claim, str):
        return None
    match = EIP155.fullmatch(claim)
    return (int(match.group(1)), match.group(2)) if match else None


def _required_shape(value: dict[str, Any]) -> dict[str, str] | None:
    """Section 9 steps 1-2: discriminators, required fields and encodings."""
    if value.get("candidateProfile") != PROFILE:
        return _error("DRV-3", "unsupported candidate profile discriminator")
    required_top = {"pipeline", "artifacts", "publicKeys", "orchestratorClaim",
                    "bundleRequiredSigners", "evaluatorVetResult", "profileParameters",
                    "mappingSources", "native", "externalEvidence", "deliveryBinding",
                    "reputationProjection", "submittedBeforeExpiry", "consumedDecisionHashes"}
    if not required_top.issubset(value) or not isinstance(value.get("artifacts"), dict):
        return _error("DRV-3", "missing required fixture fields")
    artifacts = value["artifacts"]
    required_artifacts = {"bilateralAgreement", "railDefinition", "agreement", "job",
                          "funding", "terminal"}
    if not required_artifacts.issubset(artifacts):
        return _error("DRV-3", "missing required artifact")
    versions = {
        "agreement": ("deliveryOrRemedyAgreementVersion", "1"),
        "job": ("escrowJobRefVersion", "1"),
        "funding": ("escrowFundingEvidenceVersion", "1"),
        "evaluation": ("executionEvaluationVersion", "1"),
        "decision": ("escrowDecisionVersion", "1"),
        "dispute": ("disputeOutcomeVersion", "1"),
        "terminal": ("escrowTerminalEvidenceVersion", "1"),
    }
    for label, (field, expected) in versions.items():
        if label in artifacts and artifacts[label].get(field) != expected:
            return _error("DRV-3", f"unsupported {label} artifact discriminator")
    agreement = artifacts["agreement"]
    job_id = agreement.get("jobId")
    if not isinstance(job_id, str) or JID.fullmatch(job_id) is None:
        return _error("DRAA-1", "jobId is not a canonical JID")
    if not all(_int(agreement.get(field)) for field in
               ("fundPhaseIndex", "deliveryPhaseIndex", "terminalPhaseIndex")):
        return _error("DRAA-2", "phase indexes must be unsigned integers")
    if not _uint(agreement.get("budgetBaseUnits")):
        return _error("DRA-10", "budgetBaseUnits is not minimal unsigned decimal")
    if not _uint(artifacts["job"].get("nativeJobId")):
        return _error("DRJ-1", "nativeJobId is not minimal unsigned decimal")
    if not _event_ref(artifacts["job"].get("creationEvent")):
        return _error("DRV-3", "malformed creation event reference")
    if agreement.get("disclosurePolicy") not in {
            "public-evidence-only", "explicit-party-supplied"}:
        return _error("DRQ-1", "unsupported disclosure policy")
    if agreement.get("preSubmissionRefundPolicy") not in {
            "expiry-only", "evaluator-rejection"}:
        return _error("DRA-15", "unsupported pre-submission refund policy")
    for role in ("buyer", "seller", "evaluator"):
        binding = agreement.get(role)
        if not isinstance(binding, dict) or not all(key in binding for key in
                ("primaryClaim", "bundleHash", "vetRecordRef", "evmAccountClaim")):
            return _error("DRA-4", f"malformed {role} binding")
        if not _hash(binding["bundleHash"]) or not _ref(binding["vetRecordRef"]):
            return _error("DRA-4", f"malformed {role} bundle or Vet reference")
    evaluator = agreement["evaluator"]
    if "requirement" not in evaluator or not _hash(evaluator.get("requirementHash")):
        return _error("DRA-8", "malformed evaluator requirement binding")
    if not isinstance(agreement.get("signatures"), list) or not all(
            _sig_shape(item) for item in agreement["signatures"]):
        return _error("DRA-3", "malformed overlay signatures")
    for label, artifact in artifacts.items():
        if label in DOMAINS and label != "agreement" and not _sig_shape(artifact.get("signature")):
            return _error("DRV-3", f"malformed {label} signature")
    for label in ("agreementHash", "deliveryHash", "decisionHash"):
        if label in value["mappingSources"] and not _hash(value["mappingSources"][label]):
            return _reject("DREB-3", f"{label} is not 64 lowercase hexadecimal characters")
    native = value["native"]
    for field in ("chainId", "expiredAt", "evaluationDeadlineSec"):
        if not _int(native.get(field)):
            return _error("DRV-3", f"native {field} is not an unsigned integer")
    for field in ("client", "provider", "evaluator", "token", "contractAddress"):
        if not isinstance(native.get(field), str) or ADDRESS.fullmatch(native[field]) is None:
            return _error("DRV-3", f"native {field} is not an EVM address")
    for field in ("deliverable", "reason"):
        if native.get(field) is not None and (not isinstance(native[field], str)
                or BYTES32.fullmatch(native[field]) is None):
            return _error("DRV-3", f"native {field} is not bytes32")
    if not _uint(native.get("amountBaseUnits")) or not _uint(
            native.get("preterminalProviderPayoutBaseUnits")):
        return _error("DRV-3", "native amounts are not minimal unsigned decimals")
    for label in ("funding", "terminal"):
        artifact = artifacts[label]
        events = artifact.get("fundingEventRefs" if label == "funding" else "terminalEventRefs")
        if not isinstance(events, list) or not all(_event_ref(item) for item in events):
            return _error("DRV-3", f"malformed {label} event set")
        finality = artifact.get("finality")
        if not isinstance(finality, dict) or finality.get("status") not in {
                "pending", "finalized", "unavailable"}:
            return _error("DRV-3", f"malformed {label} finality record")
    for status in value["externalEvidence"].values():
        if status not in STATUS:
            return _error("DRV-3", "unsupported resolution status")
    if "dispute" in artifacts:
        dispute = artifacts["dispute"]
        if not isinstance(dispute.get("caseId"), str) or JID.fullmatch(dispute["caseId"]) is None:
            return _error("DRAA-1", "caseId is not a canonical JID")
        if not _int(dispute.get("revision")):
            return _error("DRAA-2", "dispute revision is not unsigned")
    return None


def _pipeline(value: dict[str, Any]) -> dict[str, str] | None:
    pipeline = value["pipeline"]
    if not isinstance(pipeline, list) or not all(isinstance(step, dict) for step in pipeline):
        return _error("DRV-3", "pipeline is malformed")
    escrows = [(index, step) for index, step in enumerate(pipeline)
               if step.get("kind") == "job-escrow"]
    if len(escrows) != 2:
        return _reject("DRP-1", "pipeline must contain exactly two job-escrow steps")
    (fund_i, fund), (terminal_i, terminal) = escrows
    if fund.get("parameters", {}).get("action") != "fund" or terminal.get(
            "parameters", {}).get("action") != "terminal":
        return _reject("DRP-2", "paired escrow actions are not fund then terminal")
    deliveries = [(i, step) for i, step in enumerate(pipeline)
                  if isinstance(step.get("kind"), str) and step["kind"].startswith("deliver-")]
    between = [item for item in deliveries if fund_i < item[0] < terminal_i]
    if len(between) != 1:
        return _reject("DRP-3", "exactly one supported delivery must be inside the pair")
    forbidden = []
    for index, step in enumerate(pipeline):
        kind = step.get("kind", "")
        if index not in {fund_i, terminal_i, between[0][0]} and (
                kind.startswith("pay-") or kind.startswith("deliver-")
                or kind == "pay-alternative"):
            forbidden.append(index)
    if forbidden:
        return _reject("DRP-4", "an additional payment or delivery appears alongside the pair")
    fund_rail = fund.get("parameters", {}).get("rail")
    terminal_rail = terminal.get("parameters", {}).get("rail")
    rail = value["artifacts"]["railDefinition"]
    if fund_rail != terminal_rail or fund_rail != rail.get("railId"):
        return _reject("DRP-5", "escrow invocations do not bind the same complete rail")
    agreement = value["artifacts"]["agreement"]
    indexes = (agreement["fundPhaseIndex"], agreement["deliveryPhaseIndex"],
               agreement["terminalPhaseIndex"])
    if indexes != (fund_i, between[0][0], terminal_i):
        return _reject("DRA-11", "signed phase indexes do not match the pipeline")
    if value["deliveryBinding"].get("containsNativeSubmissionObservation") is True:
        return _reject("DRP-9", "delivery hash circularly includes native submission evidence")
    return None


def _artifact_authentication(
        value: dict[str, Any], *, skip_signatures: bool = False,
) -> tuple[dict[str, str] | None, dict[str, str]]:
    artifacts = value["artifacts"]
    public_keys = value["publicKeys"]
    hashes: dict[str, str] = {}
    try:
        bilateral_hash = hashlib.sha256(_jcs(artifacts["bilateralAgreement"])).hexdigest()
        rail_hash = hashlib.sha256(_jcs(artifacts["railDefinition"])).hexdigest()
        for label in DOMAINS:
            if label in artifacts:
                hashes[label] = _content_hash(artifacts[label])
    except (TypeError, ValueError):
        return _error("DRV-3", "artifact lies outside the canonical JSON domain"), hashes
    agreement = artifacts["agreement"]
    evaluation = artifacts.get("evaluation")
    if evaluation is not None and evaluation.get("evaluationSeq") != 0:
        return (_reject("DRAA-6", "first evaluation sequence is not zero"), hashes)
    if (agreement.get("agreementHash") != bilateral_hash
            or agreement.get("agreementRef", {}).get("contentHash") != bilateral_hash):
        return _reject("DRA-2", "bilateral agreement content hash mismatch"), hashes
    if agreement.get("railDefinitionRef", {}).get("contentHash") != rail_hash:
        return _reject("DRP-5", "rail definition reference hash mismatch"), hashes
    if not skip_signatures:
        signatures = agreement["signatures"]
        roles = {"buyer": agreement["buyer"]["primaryClaim"],
                 "seller": agreement["seller"]["primaryClaim"],
                 "evaluator": agreement["evaluator"]["primaryClaim"]}
        if len(signatures) != 3 or sorted(item.get("role") for item in signatures) != sorted(roles):
            return _reject("DRA-3", "overlay lacks exactly one signature per role"), hashes
        for signature in signatures:
            party = signature.get("party")
            if party != roles[signature["role"]] or not _verify_signature(
                    public_keys, party, signature, DOMAINS["agreement"], hashes["agreement"]):
                return _reject("DRA-3", "invalid delivery-or-remedy overlay signature"), hashes
        orchestrator = value["orchestratorClaim"]
        for label in ("job", "funding", "terminal"):
            signature = artifacts[label]["signature"]
            if signature.get("signer") != orchestrator or not _verify_signature(
                    public_keys, orchestrator, signature, DOMAINS[label], hashes[label]):
                rule = {"job": "DRJ-9", "funding": "DRF-7", "terminal": "DRT-10"}[label]
                return _reject(rule, f"invalid {label} orchestrator signature"), hashes
        evaluator = agreement["evaluator"]["primaryClaim"]
        for label in ("evaluation", "decision", "dispute"):
            if label not in artifacts:
                continue
            signature = artifacts[label]["signature"]
            role_rule = {"evaluation": "DRE-1", "decision": "DRD-1", "dispute": "DRX-2"}[label]
            if signature.get("signer") != evaluator:
                return _reject(role_rule, f"{label} signer is not the bound evaluator"), hashes
            if not _verify_signature(public_keys, evaluator, signature, DOMAINS[label], hashes[label]):
                return _reject(role_rule, f"invalid {label} signature"), hashes

    # References are checked only after all carried signatures, per section 9 step 3.
    agreement_hash = hashes["agreement"]
    job_hash = hashes["job"]
    funding_hash = hashes["funding"]
    job_id = agreement["jobId"]
    if value["mappingSources"].get("agreementHash") != agreement_hash:
        return _reject("DREB-2", "agreement mapping source is not the recomputed hash"), hashes
    for label in ("job", "funding", "delivery", "evaluation", "decision", "dispute", "terminal"):
        if label not in artifacts:
            continue
        artifact = artifacts[label]
        if artifact.get("jobId") != job_id:
            return _reject("DRD-8", f"{label} belongs to another job"), hashes
        if label not in {"job", "delivery"} and artifact.get(
                "deliveryOrRemedyAgreementHash") != agreement_hash:
            return _reject("DRA-1", f"{label} does not bind the exact overlay"), hashes
    job = artifacts["job"]
    if job.get("deliveryOrRemedyAgreementHash") != agreement_hash:
        return _reject("DRJ-3", "job reference does not bind the exact overlay"), hashes
    for label in ("funding", "evaluation", "decision", "terminal"):
        if label in artifacts and artifacts[label].get("escrowJobRef", {}).get(
                "contentHash") != job_hash:
            return _reject("DRD-8", f"{label} job reference mismatch"), hashes
    terminal = artifacts["terminal"]
    if terminal.get("fundingEvidenceRef", {}).get("contentHash") != funding_hash:
        return _reject("DRT-11", "terminal evidence does not bind the funding record"), hashes
    delivery = artifacts.get("delivery")
    if delivery is not None:
        delivery_hash = hashlib.sha256(_jcs(_unsigned(delivery))).hexdigest()
        hashes["delivery"] = delivery_hash
        if value["mappingSources"].get("deliveryHash") != delivery_hash:
            return _reject("DREB-2", "delivery mapping source is not the recomputed hash"), hashes
        for owner, field in ((artifacts.get("evaluation"), "deliveryEvidenceRef"),
                             (artifacts.get("decision"), "deliveryEvidenceRef"),
                             (terminal, "deliveryEvidenceRef")):
            if owner is not None and field in owner and owner[field].get("contentHash") != delivery_hash:
                return _reject("DRD-8", "cross-job or substituted delivery reference"), hashes
    decision = artifacts.get("decision")
    if decision is not None:
        if value["mappingSources"].get("decisionHash") != hashes["decision"]:
            return _reject("DREB-2", "decision mapping source is not the recomputed hash"), hashes
        if terminal.get("decisionRef", {}).get("contentHash") != hashes["decision"]:
            return _reject("DRD-8", "terminal decision reference mismatch"), hashes
        if hashes["decision"] in value["consumedDecisionHashes"]:
            return _reject("DRD-8", "decision was already consumed"), hashes
        basis = decision.get("basisRef", {})
        expected_label = {"execution-evaluation": "evaluation",
                          "dispute-outcome": "dispute"}.get(basis.get("kind"))
        if expected_label is None or expected_label not in hashes:
            return _reject("DRD-2", "decision basis is unsupported or absent"), hashes
        if basis.get("ref", {}).get("contentHash") != hashes[expected_label]:
            return _reject("DRD-2", "decision basis reference hash mismatch"), hashes
    requirement_hash = hashlib.sha256(_jcs(agreement["evaluator"]["requirement"])).hexdigest()
    if requirement_hash != agreement["evaluator"]["requirementHash"]:
        return _reject("DRA-8", "evaluator requirement hash mismatch"), hashes
    prefix = f"dacsx:delivery-remedy:{job_id}:"
    address_refs = (
        (artifacts["funding"].get("escrowJobRef"), prefix + "job"),
        (artifacts["terminal"].get("escrowJobRef"), prefix + "job"),
        (artifacts["terminal"].get("fundingEvidenceRef"), prefix + "funding"),
    )
    for reference, locator in address_refs:
        if not _ref(reference) or reference["locator"] != locator:
            return _reject("DRAA-3", "artifact reference does not use its complete logical address"), hashes
    if evaluation is not None:
        if artifacts.get("evaluationRef", {}).get("locator") != prefix + "evaluation:0":
            return _reject("DRAA-3", "evaluation reference uses the wrong logical address"), hashes
    if decision is not None and artifacts.get("decisionRef", {}).get("locator") != prefix + "decision":
        return _reject("DRAA-3", "decision reference uses the wrong logical address"), hashes
    dispute = artifacts.get("dispute")
    if dispute is not None:
        expected = (f"dacsx:dispute:{job_id}:{dispute['caseId']}:outcome:"
                    f"{dispute['revision']}")
        if artifacts.get("disputeRef", {}).get("locator") != expected:
            return _reject("DRAA-3", "dispute reference uses the wrong logical address"), hashes
        if dispute["revision"] == 0 and "supersedesOutcomeRef" in dispute:
            return _reject("DRAA-7", "initial dispute revision supersedes another outcome"), hashes
    return None, hashes


def _roles_and_semantics(value: dict[str, Any], hashes: dict[str, str]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    rail = artifacts["railDefinition"]
    native = value["native"]
    job = artifacts["job"]
    if (job.get("chainId") != rail.get("chainId")
            or job.get("contractAddress", "").lower() != rail.get("contractAddress", "").lower()):
        return _reject("DRJ-3", "job chain or contract differs from the pinned rail")
    if (job.get("runtimeBytecodeHash") != rail.get("runtimeBytecodeHash")
            or native.get("runtimeBytecodeHash") != rail.get("runtimeBytecodeHash")):
        return _reject("DRJ-5", "runtime bytecode differs from the pinned authenticated code")
    if (native.get("chainId") != rail.get("chainId")
            or native.get("contractAddress", "").lower() != rail.get("contractAddress", "").lower()):
        return _reject("DRJ-3", "resolved native job is on another chain or contract")
    roles: dict[str, tuple[int, str]] = {}
    for role in ("buyer", "seller", "evaluator"):
        parsed = _claim_account(agreement[role]["evmAccountClaim"])
        if parsed is None or parsed[0] != rail["chainId"]:
            return _reject("DRA-5", f"{role} EVM claim is not the selected-chain EIP-155 form")
        roles[role] = parsed
    claims = [agreement[role]["primaryClaim"] for role in ("buyer", "seller", "evaluator")]
    if claims[2] in claims[:2]:
        return _reject("DRA-6", "evaluator primary identity collides with a commercial party")
    if roles["evaluator"][1].lower() in {roles["buyer"][1].lower(), roles["seller"][1].lower()}:
        return _reject("DRA-7", "evaluator account collides with client or provider")
    if value["bundleRequiredSigners"] != claims[:2]:
        return _reject("DRA-13", "evaluator was added to the bilateral signer set")
    if value["evaluatorVetResult"] != "pass":
        return _reject("DRA-9", "evaluator Vet result is not pass and fresh")
    if agreement["budgetBaseUnits"] != artifacts["bilateralAgreement"].get("price", {}).get("amount"):
        return _reject("DRA-10", "budget does not equal the bilateral agreement price")
    funding = artifacts["funding"]
    if funding.get("fundPhaseIndex") != agreement["fundPhaseIndex"]:
        return _reject("DRF-1", "funding phase index mismatch")
    if (funding.get("token") != rail.get("paymentToken")
            or funding.get("amountBaseUnits") != agreement["budgetBaseUnits"]):
        return _reject("DRF-2", "funding token or amount mismatch")
    if not funding.get("fundingEventRefs"):
        return _reject("DRF-3", "empty funding event set cannot prove the complete budget entered escrow")
    funding_event_keys = {
        (event["chainId"], event["txHash"].lower(), event["logIndex"])
        for event in funding["fundingEventRefs"]
    }
    if len(funding_event_keys) != len(funding["fundingEventRefs"]):
        return _reject("DRF-3", "funding event set is ambiguous or duplicated")
    if (any(event["chainId"] != rail["chainId"] for event in funding["fundingEventRefs"])
            or funding.get("finality", {}).get("chainId") != rail["chainId"]):
        return _reject("DRF-3", "funding events do not identify the pinned chain")
    if funding.get("finality", {}).get("status") != "finalized":
        return _indeterminate("DRF-6", "funding has not reached the exact finality profile")
    if native.get("preterminalProviderPayoutBaseUnits") != "0":
        return _reject("DRL-7", "provider value moved before release")
    if value["deliveryBinding"].get("status") == "verified":
        if not value["deliveryBinding"].get("finalizedBeforeNativeSubmission"):
            return _reject("DRP-6", "delivery began before finalized funding")
    if agreement["deliveryPhaseIndex"] >= agreement["terminalPhaseIndex"]:
        return _reject("DRA-11", "phase indexes are not ordered")
    if agreement["evaluationDeadlineSec"] - agreement["submissionCutoffSec"] <= 0:
        return _reject("DREB-14", "evaluation window is not positive")
    params = value["profileParameters"]
    if params != rail.get("profileParameters"):
        return _reject("DRA-14", "mutable profile parameters differ from the signed rail")
    minimum = params.get("minimumEvaluationWindowSec")
    grace = params.get("evaluationGracePeriodSec")
    if not _int(minimum) or minimum <= 0:
        return _reject("DREB-14", "pinned minimum evaluation window is not positive")
    if agreement["evaluationDeadlineSec"] != agreement["submissionCutoffSec"] + grace:
        return _reject("DREB-13", "evaluation deadline does not equal cutoff plus pinned grace")
    if agreement["evaluationDeadlineSec"] - agreement["submissionCutoffSec"] < minimum:
        return _reject("DREB-14", "evaluation window is shorter than the pinned minimum")
    if native["expiredAt"] != agreement["submissionCutoffSec"]:
        return _reject("DREB-12", "native expiry does not equal submission cutoff")
    account_fields = {"client": "buyer", "provider": "seller", "evaluator": "evaluator"}
    account_rules = {"client": "DREB-7", "provider": "DREB-8", "evaluator": "DREB-9"}
    for field, role in account_fields.items():
        if native[field].lower() != roles[role][1].lower():
            return _reject(account_rules[field], f"native {field} differs from the controlled account")
    if native["token"].lower() != rail["paymentToken"].lower() or native[
            "amountBaseUnits"] != agreement["budgetBaseUnits"]:
        return _reject("DREB-11", "native token or budget mismatch")
    if native.get("evaluatorAccountType") not in {"eoa", "eip1271"}:
        return _reject("DREB-18", "unsupported evaluator account type")
    if native.get("terminalAction") in {"complete", "reject"}:
        if native.get("terminalCaller", "").lower() != roles["evaluator"][1].lower():
            return _reject("DREB-21", "native evaluator action was called by another account")
        # DREB-19/DREB-22 distinguish the outer submitter from the authenticated
        # caller.  A relayer is permitted; it simply must not replace
        # ``terminalCaller`` as the evaluator identity.

    zero = "0x" + "00" * 32
    if native.get("deliverable") == zero or native.get("reason") == zero:
        return _reject("DREB-5", "zero bytes32 is forbidden for deliverable or reason")
    expected_description = "dacs-delivery-remedy:v1:" + hashes["agreement"]
    if native.get("description") != expected_description:
        return _reject("DREB-1", "native description is not the byte-exact agreement binding")
    if "delivery" in hashes:
        if native.get("deliverable") != "0x" + hashes["delivery"]:
            return _reject("DREB-4", "deliverable is not decode_hex_32 of the recomputed delivery hash")
    elif native.get("deliverable") is not None:
        return _reject("DREB-4", "native deliverable exists without delivery evidence")
    if "decision" in hashes:
        if native.get("reason") != "0x" + hashes["decision"]:
            return _reject("DREB-4", "reason is not decode_hex_32 of the recomputed decision hash")
    elif native.get("reason") is not None:
        return _reject("DREB-4", "native reason exists without an escrow decision")
    return _terminal_semantics(value, roles)


def _finding_valid(finding: Any, agreement: dict[str, Any]) -> bool:
    if not isinstance(finding, dict) or not isinstance(finding.get("rationaleCode"), str):
        return False
    classification = finding.get("classification")
    party = finding.get("faultedParty")
    if classification == "seller-fault":
        return party == agreement["seller"]["primaryClaim"]
    if classification == "buyer-fault":
        return party == agreement["buyer"]["primaryClaim"]
    return classification in {"seller-fulfilled", "evaluator-unavailable", "substrate-failure",
                              "no-fault", "indeterminate"} and "faultedParty" not in finding


def _terminal_semantics(value: dict[str, Any], roles: dict[str, tuple[int, str]]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    terminal = artifacts["terminal"]
    state = terminal.get("terminalState")
    decision = artifacts.get("decision")
    delivery = artifacts.get("delivery")
    if state not in {"released", "rejected-refund", "expired-refund"}:
        return _error("DRV-3", "unsupported terminal-state discriminator")
    if terminal.get("disposition") != ({"released": "release-to-provider"}.get(
            state, "refund-to-client")):
        return _reject("DRT-1" if state == "released" else "DRT-2",
                       "terminal state and disposition disagree")
    if state == "released":
        if decision is None or delivery is None or "decisionRef" not in terminal or "deliveryEvidenceRef" not in terminal:
            return _indeterminate("DRT-1", "release lacks decision, basis, or delivery evidence")
    elif state == "rejected-refund":
        if decision is None or "decisionRef" not in terminal:
            return _indeterminate("DRT-2", "rejected refund lacks decision or basis")
    else:
        if decision is not None or "decisionRef" in terminal:
            return _reject("DRD-7", "expiry recovery invented an evaluator decision")
    if value["submittedBeforeExpiry"]:
        if delivery is not None and "deliveryEvidenceRef" not in terminal:
            return _reject("DRT-12", "post-submission terminal evidence omits delivery")
    elif "deliveryEvidenceRef" in terminal:
        return _reject("DRT-12", "pre-submission refund carries delivery evidence")
    if decision is not None:
        pre_submission = not value["submittedBeforeExpiry"]
        if pre_submission:
            if (agreement["preSubmissionRefundPolicy"] != "evaluator-rejection"
                    or decision.get("basisRef", {}).get("kind") != "dispute-outcome"
                    or "deliveryEvidenceRef" in decision):
                return _reject("DRD-12", "pre-submission rejection is not policy-and-dispute authorized")
        else:
            if "deliveryEvidenceRef" not in decision:
                return _reject("DRD-3", "post-submission decision omits delivery evidence")
        basis_kind = decision.get("basisRef", {}).get("kind")
        basis = artifacts.get("evaluation" if basis_kind == "execution-evaluation" else "dispute")
        if basis is None:
            return _indeterminate("DRD-10", "decision basis artifact is unavailable")
        if basis_kind == "execution-evaluation":
            expected = {"accept": "release-to-provider", "reject": "refund-to-client"}.get(
                basis.get("result"))
            if expected is None:
                return _indeterminate("DRE-5", "indeterminate evaluation cannot authorize terminal action")
            if decision["disposition"] != expected:
                return _reject("DRD-2", "evaluation result does not authorize the disposition")
            if not _finding_valid(basis.get("finding"), agreement):
                return _reject("DRX-5", "evaluation finding/faulted party is invalid")
        else:
            if basis.get("recommendedDisposition") != decision["disposition"]:
                return _reject("DRD-2", "dispute outcome does not authorize the disposition")
            if not _finding_valid(basis.get("finding"), agreement):
                return _reject("DRX-5", "dispute finding/faulted party is invalid")
    if not terminal.get("terminalEventRefs"):
        return _reject("DRT-4", "empty terminal event set cannot identify a terminal action")
    event_keys = {(event["chainId"], event["txHash"].lower(), event["logIndex"])
                  for event in terminal["terminalEventRefs"]}
    if len(event_keys) != len(terminal["terminalEventRefs"]):
        return _reject("DRT-4", "terminal event set is ambiguous or duplicated")
    if terminal.get("finality", {}).get("status") != "finalized":
        return _indeterminate("DRT-8", "terminal event has not reached exact finality")
    chain_id = artifacts["railDefinition"]["chainId"]
    if (any(event["chainId"] != chain_id for event in terminal["terminalEventRefs"])
            or terminal.get("finality", {}).get("chainId") != chain_id):
        return _reject("DRT-4", "terminal events do not identify the pinned chain")
    budget = agreement["budgetBaseUnits"]
    if terminal.get("amountBaseUnits") != budget:
        return _reject("DRT-5" if state == "released" else "DRT-6",
                       "terminal amount is not the complete funded budget")
    recipient = roles["seller" if state == "released" else "buyer"][1]
    if terminal.get("recipient", "").lower() != recipient.lower():
        return _reject("DRT-5" if state == "released" else "DRT-6",
                       "terminal recipient is not the agreement-bound account")
    if terminal.get("token", "").lower() != value["native"]["token"].lower():
        return _reject("DRT-4", "terminal event token differs from the pinned native token")
    if value["native"].get("platformFeeBP") != 0 or value["native"].get("evaluatorFeeBP") != 0:
        return _reject("DRT-7", "escrow fees are not zero")
    if value["native"].get("terminalState") != state:
        return _reject("DRT-4", "native and artifact terminal states differ")
    if state == "expired-refund" and value["reputationProjection"].get("sellerFault"):
        return _reject("DRT-13", "expiry projected seller fault without authenticated finding")
    return None


def _resolution(value: dict[str, Any]) -> dict[str, str] | None:
    """Section 9 steps 4-5 over the fixture's supplied status labels."""
    statuses = value["externalEvidence"]
    applicable = {
        "agreementResolution": "DRA-1", "railResolution": "DRV-1",
        "codeResolution": "DRJ-7", "authorityResolution": "DRJ-7",
        "fundingFinality": "DRF-6", "terminalFinality": "DRT-8",
    }
    if value["artifacts"].get("delivery") is not None:
        applicable["deliveryFinality"] = "DRE-2"
    if (value["artifacts"].get("decision") is not None
            or value["artifacts"]["terminal"].get("terminalState") in {
                "released", "rejected-refund"}):
        applicable["decisionFinality"] = "DRD-4"
        applicable["decisionOrdering"] = "DRD-10"
    for field, rule in applicable.items():
        status = statuses.get(field)
        if status == "contradictory":
            # Candidate text has no DRV-6; use the closest named source rule.
            contradiction_rule = "DRD-11" if field == "decisionOrdering" else rule
            return _reject(contradiction_rule, f"authenticated {field} is contradictory")
    for field, rule in applicable.items():
        if statuses.get(field) == "unavailable":
            return _indeterminate(rule, f"authenticated {field} is unavailable")
    return None


def evaluate_protocol(value: Any, *, _skip_signatures_for_tests: bool = False) -> dict[str, str]:
    """Evaluate one fully materialized protocol fixture in section 9 order."""
    if not isinstance(value, dict):
        return _error("DRV-3", "protocol input is not an object")
    if _skip_signatures_for_tests and value.get("fixtureOnly") is not True:
        return _error("DRV-3", "signature-test seam requires fixtureOnly material")
    shape = _required_shape(value)
    if shape:
        return shape
    pipeline = _pipeline(value)
    if pipeline:
        return pipeline
    authenticated, hashes = _artifact_authentication(
        value, skip_signatures=_skip_signatures_for_tests)
    if authenticated:
        return authenticated
    resolution = _resolution(value)
    if resolution:
        return resolution
    semantic = _roles_and_semantics(value, hashes)
    if semantic:
        return semantic
    return _result("verified", "DRV",
                   "all applicable checks succeeded; the candidate names no numbered verified-result rule")


def _drc_status(ok: bool | None) -> str:
    return "pass" if ok is True else "rejected" if ok is False else "indeterminate"


def evaluate_deployment(manifest: Any) -> dict[str, Any]:
    """Evaluate DRC-1..DRC-12 and the non-deployment registration guard."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("capabilities"), dict):
        result: dict[str, Any] = {f"DRC-{index}": "error" for index in range(1, 13)}
        result.update(result="error", rule="DRC-1", detail="malformed deployment manifest",
                      registrationEligible=False)
        return result
    caps = manifest["capabilities"]
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        result = {f"DRC-{index}": "error" for index in range(1, 13)}
        result.update(result="error", rule="DRC-10", detail="missing deployment evidence",
                      registrationEligible=False)
        return result
    token = caps.get("paymentTokenSemantics", {})
    def empty_list(field: str) -> bool | None:
        value = caps.get(field)
        return len(value) == 0 if isinstance(value, list) else None
    checks: dict[str, bool | None] = {
        "DRC-1": empty_list("preterminalProviderPayoutPaths"),
        "DRC-2": (caps.get("platformFeeBP") == 0 and caps.get("evaluatorFeeBP") == 0
                  and empty_list("feeMutationAuthorities") is True),
        "DRC-3": (all(caps.get(field) is False for field in
                      ("expiryRecoveryPauseGated", "expiryRecoveryHookGated",
                       "evaluatorCanBlockExpiryRecovery", "pendingClaimCanDelayFundedRecovery"))
                  if all(field in caps for field in
                         ("expiryRecoveryPauseGated", "expiryRecoveryHookGated",
                          "evaluatorCanBlockExpiryRecovery", "pendingClaimCanDelayFundedRecovery")) else None),
        "DRC-4": empty_list("lockedFundAlternateWithdrawalAuthorities"),
        "DRC-5": empty_list("logicReplacementAuthorities"),
        "DRC-6": (not caps.get("upgradeableSyntactically") or (
            caps.get("upgradeAuthorityIrreversiblyDisabled") is True
            and evidence.get("upgradeDisablementAuthenticated") is True)),
        "DRC-7": (caps.get("hookMutable") is False
                  and caps.get("expiryRecoveryHookGated") is False
                  and caps.get("hookMode") in {"absent", "immutable-nonblocking"}),
        "DRC-8": None,
        "DRC-9": caps.get("eventIdentityComplete") if type(caps.get("eventIdentityComplete")) is bool else None,
        "DRC-10": None,
        "DRC-11": None,
        "DRC-12": None,
    }
    token_fields = ("transferFees", "rebasing", "callbacks", "pause", "blacklist",
                    "externalBalanceMutation")
    if isinstance(token, dict) and all(token.get(field) is False for field in token_fields) \
            and token.get("independentlyVerified") is True:
        checks["DRC-8"] = True
    elif isinstance(token, dict) and (any(token.get(field) is True for field in token_fields)
                                     or token.get("independentlyVerified") is False):
        checks["DRC-8"] = False
    bytecode = evidence.get("runtimeBytecodeHash")
    resolved = evidence.get("independentlyResolvedRuntimeBytecodeHash")
    reproducible = evidence.get("sourceToBytecodeReproducible")
    if reproducible is True and _hash(bytecode) and _hash(resolved):
        checks["DRC-10"] = bytecode == resolved
    elif reproducible is False or (_hash(bytecode) and _hash(resolved) and bytecode != resolved):
        checks["DRC-10"] = False
    if evidence.get("conflict") is True:
        checks["DRC-11"] = False
    elif evidence.get("complete") is True and evidence.get("conflict") is False:
        checks["DRC-11"] = True
    ordering = caps.get("decisionOrderingProfile")
    authenticated = evidence.get("decisionOrderingEvidenceAuthenticated")
    if isinstance(ordering, str) and ordering and authenticated is True:
        checks["DRC-12"] = True
    elif authenticated is False:
        checks["DRC-12"] = False
    statuses = {rule: _drc_status(ok) for rule, ok in checks.items()}
    failed = [rule for rule, status in statuses.items() if status == "rejected"]
    unknown = [rule for rule, status in statuses.items() if status == "indeterminate"]
    if failed:
        overall, rule, detail = "rejected", failed[0], "failed: " + ", ".join(failed)
    elif unknown:
        overall, rule, detail = "indeterminate", unknown[0], "unavailable: " + ", ".join(unknown)
    else:
        overall, rule, detail = "verified", "DRC", "all DRC capability checks pass"
    eligible = (overall == "verified" and manifest.get("fixtureOnly") is False
                and manifest.get("registrationStatus") == "registered")
    return {**statuses, "result": overall, "rule": rule, "detail": detail,
            "registrationEligible": eligible}


def evaluate(vector: dict[str, Any]) -> dict[str, Any]:
    """Materialize and evaluate one blind vector without reading its name/answers."""
    if not isinstance(vector, dict):
        return _error("DRV-3", "vector is not an object")
    selector = vector.get("base")
    try:
        if selector in _FIXTURES:
            return evaluate_protocol(apply_patch(_FIXTURES[selector], vector.get("patch", [])))
        if selector in _MANIFESTS:
            return evaluate_deployment(apply_patch(_MANIFESTS[selector], vector.get("patch", [])))
    except (KeyError, TypeError, ValueError) as exc:
        return _error("DRV-3", f"invalid vector patch: {exc}")
    return _error("DRV-3", "unknown base fixture")


def run_blind(input_path: Path, output_path: Path) -> dict[str, Any]:
    blind = json.loads(input_path.read_text(encoding="utf-8"))
    configure_bases(blind.get("fixtures", {}), blind.get("manifests", {}))
    results = []
    for vector in blind["vectors"]:
        got = evaluate(vector)
        item = {"name": vector.get("name"), "result": got["result"],
                "rule": got["rule"], "detail": got["detail"]}
        if vector.get("base") in blind.get("manifests", {}):
            item["registrationEligible"] = got["registrationEligible"]
            item["rules"] = {f"DRC-{index}": got[f"DRC-{index}"] for index in range(1, 13)}
        results.append(item)
    run = {"set": blind["set"], "impl": "pathos-dacs-ref@cross-run-2",
           "results": results}
    output_path.write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    run_blind(args.input, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
