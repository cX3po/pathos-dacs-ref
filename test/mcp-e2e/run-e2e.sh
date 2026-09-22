#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SERVER=''
PYTHON_ENV="${DACS_MCP_PYTHON_ENV:-/tmp/dacs-mcp-python-e2e-venv}"
OUTPUT_DIR="${DACS_MCP_OUTPUT_DIR:-/tmp/dacs-mcp-e2e-run-$$}"
BOOTSTRAP_NODE=0
BOOTSTRAP_PYTHON=0

usage() {
  cat <<'EOF'
Usage: run-e2e.sh --server ABSOLUTE_PATH [--python-env PATH] [--output-dir PATH]
                  [--bootstrap-node] [--bootstrap-python] [--bootstrap]

Dependency bootstrapping happens before bwrap. Runtime probes always require
bwrap --unshare-net and write only their JSON outputs to --output-dir.
EOF
}

while (($#)); do
  case "$1" in
    --server) SERVER=${2:?--server requires a value}; shift 2 ;;
    --python-env) PYTHON_ENV=${2:?--python-env requires a value}; shift 2 ;;
    --output-dir) OUTPUT_DIR=${2:?--output-dir requires a value}; shift 2 ;;
    --bootstrap-node) BOOTSTRAP_NODE=1; shift ;;
    --bootstrap-python) BOOTSTRAP_PYTHON=1; shift ;;
    --bootstrap) BOOTSTRAP_NODE=1; BOOTSTRAP_PYTHON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$SERVER" || "$SERVER" != /* || ! -f "$SERVER" ]]; then
  echo "--server must name an existing absolute MCP server path" >&2
  exit 2
fi
command -v bwrap >/dev/null || { echo "bwrap is required for the network-isolated runtime" >&2; exit 2; }
command -v node >/dev/null || { echo "node is required" >&2; exit 2; }

if ((BOOTSTRAP_NODE)); then
  (cd "$SCRIPT_DIR" && npm ci --ignore-scripts)
fi
if [[ ! -f "$SCRIPT_DIR/node_modules/@modelcontextprotocol/sdk/package.json" ]]; then
  echo "Node dependencies are absent; rerun with --bootstrap-node outside the runtime jail" >&2
  exit 2
fi

if ((BOOTSTRAP_PYTHON)); then
  command -v python3 >/dev/null || { echo "python3 is required for bootstrap" >&2; exit 2; }
  python3 -m venv "$PYTHON_ENV"
  "$PYTHON_ENV/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r "$SCRIPT_DIR/requirements.lock"
  "$PYTHON_ENV/bin/python" -m pip check
fi
if [[ ! -x "$PYTHON_ENV/bin/python" ]]; then
  echo "Python environment is absent; rerun with --bootstrap-python outside the runtime jail" >&2
  exit 2
fi
"$PYTHON_ENV/bin/python" -c 'import mcp; import importlib.metadata; assert importlib.metadata.version("mcp") == "2.2.0"'

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd -- "$OUTPUT_DIR" && pwd)

echo "runtime: bwrap --unshare-net"
echo "server: $SERVER"
echo "python: $PYTHON_ENV"
echo "outputs: $OUTPUT_DIR"

bwrap --die-with-parent --unshare-net --ro-bind / / --proc /proc --dev /dev \
  --bind "$OUTPUT_DIR" "$OUTPUT_DIR" -- \
  node "$SCRIPT_DIR/node-client.mjs" --server "$SERVER" >"$OUTPUT_DIR/node.json"

bwrap --die-with-parent --unshare-net --ro-bind / / --proc /proc --dev /dev \
  --bind "$OUTPUT_DIR" "$OUTPUT_DIR" -- \
  env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_ENV/bin/python" "$SCRIPT_DIR/python-client.py" --server "$SERVER" >"$OUTPUT_DIR/python.json"

python3 - "$OUTPUT_DIR/node.json" "$OUTPUT_DIR/python.json" <<'PY'
import json
import sys

node = json.load(open(sys.argv[1], encoding="utf-8"))
python = json.load(open(sys.argv[2], encoding="utf-8"))
assert node["fixtureSha256"] == python["fixtureSha256"]
assert node["verdicts"] == python["verdicts"]
assert node["policy"] == python["policy"]
assert node["runtimeAssertions"] == python["runtimeAssertions"]
print("normalized verdicts byte-equivalent: yes")
print("decisions:", {name: node["verdicts"][name]["verdict"]["decision"] for name in ("valid", "tampered", "indeterminate")})
print("runtime assertions:", node["runtimeAssertions"])
PY

sha256sum "$OUTPUT_DIR/node.json" "$OUTPUT_DIR/python.json"
