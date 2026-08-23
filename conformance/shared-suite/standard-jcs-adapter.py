#!/usr/bin/env python3
"""dacs-adapter/1 process adapter over the DACS-Standard's OWN `scripts/jcs.py`.

WHY THIS EXISTS. Proposal #270 stalled on one thing: every run was `SELF-CHECK`, because only
one implementation participated. Agreement between an implementation and its own expected values
is not interop evidence. This adapter puts a *second, independently authored* implementation on
the runner — the DACS-Standard's own RFC 8785 canonicaliser, written in Python by the Standard,
sharing no code with this repository's TypeScript canonicaliser.

WHAT IT IS AND IS NOT — stated plainly, because the distinction is the whole point of #270:

  * The IMPLEMENTATION under test is the DACS-Standard's `scripts/jcs.py`. It is not ours. It was
    authored independently, in a different language, from the RFC.
  * The ADAPTER — this file — was authored by PATH-OS, not by the Standard. An adapter written by
    the implementation's own maintainers would be stronger evidence, because it removes us from
    the boundary entirely. We are not claiming otherwise, and #270 should record this.
  * Nothing here is vendored or copied. The Standard's module is imported from a checkout the
    caller supplies, at a pinned revision, and executed as-is.

Independence is asserted via `provenanceCodebase`, not inferred from a repository URL — exactly
the mechanism the steward asked for when they wrote that if independence "requires a steward
assertion rather than something the runner can prove, record that explicitly instead of deriving
it from an unverified string."

SCOPE. `scripts/jcs.py` implements canonicalisation only, so this adapter declares exactly the
two canonicalisation families and the single `canonicalize` operation. It abstains on
signed-scope hashing, SIG-6 encoding and domain-separated signing rather than faking coverage:
the Standard ships no callable implementation of those, and an adapter that answered anyway
would be reporting a verdict it cannot support.

USAGE
    DACS_STANDARD_ROOT=/path/to/DACS-Standard \
    DACS_STANDARD_REVISION=<immutable commit sha> \
    python3 standard-jcs-adapter.py

No third-party Python packages; requires Git to verify the wrapped revision.
Reads JSON Lines on stdin, writes exactly one JSON line per request on stdout.
Diagnostics go to stderr; stdout carries protocol traffic only.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

PROTOCOL = "dacs-adapter/1"

# The implementation being wrapped. Independence is asserted against THIS, not against the
# repository the adapter file happens to live in.
STANDARD_REPO = "https://github.com/DACS-Agent-commerce/DACS-Standard"


def _load_standard_jcs(root: Path):
    """Import the Standard's own jcs module from a caller-supplied checkout.

    Deliberately not vendored: a copy in this repository would be our artifact, and a divergence
    against a copy we control proves nothing about the Standard's implementation.
    """
    module_path = root / "scripts" / "jcs.py"
    if not module_path.is_file():
        raise SystemExit(f"DACS_STANDARD_ROOT does not contain scripts/jcs.py: {module_path}")
    spec = importlib.util.spec_from_file_location("dacs_standard_jcs", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "canonicalize"):
        raise SystemExit(f"{module_path} exposes no canonicalize()")
    return module


def _revision(root: Path) -> str:
    """Immutable revision of the wrapped implementation.

    A branch or a mutable tag is not a revision, per the protocol, so this resolves to a commit
    sha or fails loudly rather than reporting something unpinnable.
    """
    supplied = os.environ.get("DACS_STANDARD_REVISION", "").strip()
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=15)
        head = out.stdout.strip() if out.returncode == 0 else ""
    except Exception:  # noqa: BLE001 - handled by the explicit failures below
        head = ""
    # A supplied revision is CHECKED against the checkout, never trusted. An unverified string
    # pinning nothing is exactly the provenance weakness blocker 2 objected to.
    # HEAD equality is not enough: an edited jcs.py would still report a clean revision while
    # executing different bytes. Compare the working file against the COMMITTED BLOB by hash —
    # `git status --porcelain` is a proxy for this and its failures are easy to swallow.
    # (Codex review, 2026-08-19.)
    module_path = root / "scripts" / "jcs.py"
    try:
        blob = subprocess.run(["git", "-C", str(root), "show", "HEAD:scripts/jcs.py"],
                              capture_output=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"cannot read the committed blob for scripts/jcs.py: {exc}") from exc
    if blob.returncode != 0:
        raise SystemExit("cannot read HEAD:scripts/jcs.py; refusing to report an unverified revision")
    on_disk = hashlib.sha256(module_path.read_bytes()).hexdigest()
    committed = hashlib.sha256(blob.stdout).hexdigest()
    if on_disk != committed:
        raise SystemExit(
            f"scripts/jcs.py on disk ({on_disk[:12]}) differs from its committed blob "
            f"({committed[:12]}); refusing to report a revision that does not describe the "
            "bytes actually executed")

    if supplied:
        if head and supplied != head:
            raise SystemExit(
                f"DACS_STANDARD_REVISION={supplied} does not match the checkout HEAD {head}")
        if not head:
            raise SystemExit(
                "cannot verify DACS_STANDARD_REVISION against the checkout (not a git work tree); "
                "refusing to report an unverified revision")
        return supplied
    if head:
        return head
    raise SystemExit("cannot resolve an immutable revision from the checkout")


def _decode(value):
    """Tagged-value decoding per the protocol ($dacsType bytes/bigint)."""
    if isinstance(value, list):
        return [_decode(v) for v in value]
    if isinstance(value, dict):
        tag = value.get("$dacsType")
        if tag == "bytes" and isinstance(value.get("hex"), str):
            return bytes.fromhex(value["hex"])
        if tag == "bigint" and isinstance(value.get("decimal"), str):
            # Do NOT silently widen to a Python int. `cr-bigint` asserts "BigInt is not
            # JSON-encodable" — a distinction that exists in JavaScript's type system and not in
            # Python's, where every integer is an int. Converting here made `jcs.py` canonicalise
            # happily and the runner recorded IMPLEMENTATION-DIVERGENCE for a difference between
            # two LANGUAGES, not between two implementations of the spec. Refusing the parameter
            # records an honest adapter limitation instead. (Codex review, 2026-08-19.)
            raise ValueError(
                "tagged bigint is not representable as a distinct type in this implementation; "
                "the adapter abstains rather than report a language difference as a divergence")
        return {k: _decode(v) for k, v in value.items()}
    return value


def main() -> int:
    root = Path(os.environ.get("DACS_STANDARD_ROOT", "")).expanduser()
    if not root.is_dir():
        raise SystemExit("set DACS_STANDARD_ROOT to a DACS-Standard checkout")
    # Revision + blob verification runs FIRST. Importing before verifying would execute the
    # module's top-level code against bytes we had not yet checked. (Codex review, 2026-08-19.)
    revision = _revision(root)
    jcs = _load_standard_jcs(root)

    metadata = {
        "name": "dacs-standard-jcs",
        "version": "1.0.0",
        # Where the ADAPTER lives, and the ADAPTER's own immutable identity — a content hash of
        # this file, matching the reference adapter's `sha256:` precedent. Reporting the wrapped
        # implementation's commit here would pin neither cleanly: the protocol says `revision`
        # pins the exact adapter. (Codex review, 2026-08-19.)
        "repository": "https://github.com/cX3po/pathos-dacs-ref",
        "revision": f"sha256:{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
        # The wrapped implementation, pinned separately and verified against its committed blob.
        "wrappedImplementationRevision": revision,
        # The recorded codebase-identity assertion: the implementation under test is the
        # Standard's, at this exact commit. This is the field the protocol provides precisely so
        # independence is asserted rather than guessed from a URL.
        "provenanceCodebase": f"{STANDARD_REPO}@{revision}#scripts/jcs.py",
        "supportedFamilies": ["canonical-accept", "canonical-reject"],
        "operations": ["canonicalize"],
    }

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = None
        try:
            request = json.loads(line)
            if request.get("protocol") != PROTOCOL:
                raise ValueError(f"unsupported protocol: {request.get('protocol')}")
            if request.get("type") == "metadata":
                reply = {"protocol": PROTOCOL, "id": request.get("id"), "ok": True,
                         "result": metadata}
            elif request.get("type") == "execute":
                operation = request.get("operation")
                if operation not in metadata["operations"]:
                    # Abstain honestly rather than answer for an implementation that has no such
                    # function. The runner records this as an abstention, not a pass.
                    raise ValueError(f"unsupported operation: {operation}")
                params = _decode(request.get("params") or [])
                canonical = jcs.canonicalize(*params)
                if isinstance(canonical, str):
                    canonical = canonical.encode("utf-8")
                reply = {"protocol": PROTOCOL, "id": request.get("id"), "ok": True,
                         "result": {"hex": canonical.hex()}}
            else:
                raise ValueError(f"unsupported request type: {request.get('type')}")
        except Exception as exc:  # noqa: BLE001 - every failure is a protocol-level error reply
            reply = {"protocol": PROTOCOL,
                     "id": (request or {}).get("id"),
                     "ok": False,
                     "error": {"code": "OPERATION-ERROR", "message": f"{type(exc).__name__}: {exc}"}}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
