#!/usr/bin/env python3
"""Official Python MCP 2.2.0 client probe for the read-only verifier MCP server."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import importlib.metadata
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


EXPECTED_PROTOCOL = "2024-11-05"
EXPECTED_SERVER = {"name": "@pathos-labs/dacs-verifier", "version": "0.1.0"}
TIMEOUT_SECONDS = 8.0
ROOT = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="absolute path to dacs-verifier-mcp")
    parser.add_argument("--fixture", default=str(ROOT / "fixture-valid.json"))
    parser.add_argument("--indeterminate-fixture", default=str(ROOT / "fixture-indeterminate.json"))
    args = parser.parse_args()
    server = Path(args.server)
    if not server.is_absolute():
        parser.error("--server must be an absolute path")
    if not server.is_file():
        parser.error(f"server does not exist: {server}")
    args.server = server
    return args


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_fixture(path: str) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    value = json.loads(raw)
    return {
        "path": str(Path(path).resolve()),
        "value": value,
        "fileSha256": hashlib.sha256(raw).hexdigest(),
        "canonicalSha256": sha256_text(canonical(value)),
    }


async def with_timeout(awaitable: Any, label: str) -> Any:
    try:
        return await asyncio.wait_for(awaitable, timeout=TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise RuntimeError(f"{label} timed out after {TIMEOUT_SECONDS:g}s") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def content_text(result: Any) -> str:
    content = getattr(result, "content", None)
    require(isinstance(content, list) and len(content) == 1 and getattr(content[0], "type", None) == "text", f"unexpected tool result content: {result!r}")
    return content[0].text


def parse_tool_json(result: Any, label: str) -> dict[str, Any]:
    require(not getattr(result, "is_error", False), f"{label} unexpectedly returned an MCP error: {content_text(result)}")
    return json.loads(content_text(result))


def tool_result_json(result: Any) -> dict[str, Any]:
    return json.loads(content_text(result))


def assert_verdict_shape(result: dict[str, Any], decision: str, exit_code: int, job_id: str) -> None:
    require(result.get("apiVersion") == "pathos-dacs-verifier:1", "verdict apiVersion mismatch")
    require(result.get("bundleKind") == "v1", f"verdict bundleKind mismatch: {result.get('bundleKind')}")
    verdict = result.get("verdict", {})
    require(verdict.get("decision") == decision, f"expected decision {decision}, got {verdict.get('decision')}")
    require(result.get("exitCode") == exit_code, f"expected exitCode {exit_code}, got {result.get('exitCode')}")
    require(verdict.get("jobId") == job_id, f"expected jobId {job_id}, got {verdict.get('jobId')}")


def signature_step(verdict: dict[str, Any]) -> dict[str, Any] | None:
    return next((step for step in verdict.get("steps", []) if step.get("step") == "signatures"), None)


async def run_session(server: Path, valid: dict[str, Any], indeterminate: dict[str, Any]) -> dict[str, Any]:
    node = shutil.which("node")
    require(node is not None, "node executable is required")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DACS_VERIFIER_MCP_POLICY": "offline-enforcing",
        "DACS_VERIFIER_RPC": "http://127.0.0.1:9",
    }
    params = StdioServerParameters(command=node, args=[str(server)], env=env)
    with open(os.devnull, "w", encoding="utf-8") as stderr:
        async with stdio_client(params, errlog=stderr) as (read_stream, write_stream):
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=TIMEOUT_SECONDS,
                client_info=types.Implementation(name="dacs-verifier-python-e2e", version="1.0.0"),
            ) as session:
                initialized = await with_timeout(session.initialize(), "initialize")
                server_info = {"name": initialized.server_info.name, "version": initialized.server_info.version}
                require(server_info == EXPECTED_SERVER, f"server identity mismatch: {server_info!r}")
                require(initialized.protocol_version == EXPECTED_PROTOCOL, f"protocol mismatch: {initialized.protocol_version}")

                listed = await with_timeout(session.list_tools(), "tools/list")
                tool_names = sorted(tool.name for tool in listed.tools)
                require(tool_names == ["verifier_info", "verify_bundle"], f"tool list mismatch: {tool_names!r}")
                verify_tool = next(tool for tool in listed.tools if tool.name == "verify_bundle")
                require(verify_tool.input_schema.get("additionalProperties") is False, "verify_bundle schema is not closed")

                info = parse_tool_json(await with_timeout(session.call_tool("verifier_info", {}), "verifier_info"), "verifier_info")
                require(info.get("name") == EXPECTED_SERVER["name"] and info.get("version") == EXPECTED_SERVER["version"] and info.get("apiVersion") == "pathos-dacs-verifier:1", f"verifier_info identity mismatch: {info!r}")
                policy = info.get("verificationPolicy", {})
                require(policy.get("name") == "offline-enforcing", f"unexpected verification policy: {policy!r}")
                require(policy.get("fixtureMode") is False and policy.get("requireSignatures") is True and policy.get("offline") is True, "offline-enforcing policy disclosure mismatch")
                require(policy.get("signaturePolicy") == "v1-cryptographic-required", "signature policy disclosure mismatch")
                require(policy.get("anchoringPolicy") == "two-sided-lookup-skipped", "anchoring policy disclosure mismatch")

                valid_result = parse_tool_json(await with_timeout(session.call_tool("verify_bundle", {"bundle": valid["value"]}), "valid verify_bundle"), "valid")
                assert_verdict_shape(valid_result, "pass", 0, valid["value"]["jobId"])
                require(signature_step(valid_result["verdict"] or {}).get("outcome") == "pass", "valid signature step did not pass")
                require(len(valid_result["verdict"].get("signersVerified", [])) == 2, "valid result did not verify two signers")
                require(any(step.get("step") == "two-sided-anchoring" and step.get("outcome") == "skipped" for step in valid_result["verdict"].get("steps", [])), "offline scope was not disclosed in valid result")

                tampered = copy.deepcopy(valid["value"])
                tampered["jobId"] = f"{tampered['jobId']}-tampered"
                tampered_result = parse_tool_json(await with_timeout(session.call_tool("verify_bundle", {"bundle": tampered}), "tampered verify_bundle"), "tampered")
                assert_verdict_shape(tampered_result, "fail", 1, tampered["jobId"])
                require(signature_step(tampered_result["verdict"] or {}).get("outcome") == "fail", "tampered signature step did not fail")

                indeterminate_result = parse_tool_json(await with_timeout(session.call_tool("verify_bundle", {"bundle": indeterminate["value"]}), "indeterminate verify_bundle"), "indeterminate")
                assert_verdict_shape(indeterminate_result, "indeterminate", 2, indeterminate["value"]["jobId"])
                require(signature_step(indeterminate_result["verdict"] or {}).get("outcome") == "pass", "indeterminate fixture signatures did not verify")
                require(any(step.get("step") == "attestation[0]" and step.get("outcome") == "indeterminate" for step in indeterminate_result["verdict"].get("steps", [])), "missing-evidence step was not indeterminate")

                downgrade_signature = await with_timeout(session.call_tool("verify_bundle", {"bundle": valid["value"], "requireSignatures": False}), "requireSignatures downgrade")
                require(getattr(downgrade_signature, "is_error", False) and "conflicts with server policy" in content_text(downgrade_signature), "requireSignatures=false was not refused")
                downgrade_offline = await with_timeout(session.call_tool("verify_bundle", {"bundle": valid["value"], "offline": False}), "offline downgrade")
                require(getattr(downgrade_offline, "is_error", False) and "conflicts with server policy" in content_text(downgrade_offline), "offline=false was not refused")
                unknown_argument = await with_timeout(session.call_tool("verify_bundle", {"bundle": valid["value"], "unknown": True}), "unknown argument")
                require(getattr(unknown_argument, "is_error", False) and "unknown argument" in content_text(unknown_argument), "unknown argument was not refused")
                info_unknown = await with_timeout(session.call_tool("verifier_info", {"unknown": True}), "verifier_info unknown argument")
                require(getattr(info_unknown, "is_error", False) and "unknown argument" in content_text(info_unknown), "verifier_info unknown argument was not refused")

                return {
                    "serverInfo": server_info,
                    "protocolVersion": initialized.protocol_version,
                    "tools": tool_names,
                    "policy": policy,
                    "verdicts": {"valid": valid_result, "tampered": tampered_result, "indeterminate": indeterminate_result},
                    "admission": {"requireSignaturesFalse": "refused", "offlineFalse": "refused", "unknownArgument": "refused", "verifierInfoUnknownArgument": "refused"},
                }


async def main_async() -> None:
    args = parse_args()
    valid = load_fixture(args.fixture)
    indeterminate = load_fixture(args.indeterminate_fixture)
    first = await run_session(args.server, valid, indeterminate)
    repeat = await run_session(args.server, valid, indeterminate)
    require(canonical(first["verdicts"]["valid"]) == canonical(repeat["verdicts"]["valid"]), "fresh-process valid verdict differs")
    result = {
        "client": "python",
        "sdk": f"mcp@{importlib.metadata.version('mcp')}",
        "server": str(args.server.resolve()),
        "fixtureSha256": {"validFile": valid["fileSha256"], "validCanonical": valid["canonicalSha256"], "indeterminateFile": indeterminate["fileSha256"], "indeterminateCanonical": indeterminate["canonicalSha256"]},
        **first,
        "freshProcessRepeat": {"validVerdictMatches": True},
        "runtimeAssertions": {
            "networkNamespace": "runner-enforced-bwrap-unshare-net",
            "verifierPolicy": "offline-enforcing",
            "rpcSink": "http://127.0.0.1:9",
            "walletPaymentModelCalls": "not instrumented; probe exposes no wallet, payment, or model interface",
        },
    }
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))


def main() -> None:
    try:
        asyncio.run(main_async())
    except Exception as exc:  # noqa: BLE001 - CLI reports an evidence-bound failure and exits non-zero.
        print(f"python-client failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
