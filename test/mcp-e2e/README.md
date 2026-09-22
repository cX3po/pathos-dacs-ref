# Two-client MCP proof

This bounded probe launches the local hardened `dacs-verifier-mcp` binary through two independent official MCP clients:

- Node `@modelcontextprotocol/sdk@1.30.0`
- Python `mcp==2.2.0`

The same deterministic signed fixtures are sent through both clients. The probes assert MCP initialize/list/info, valid `pass`, jobId-tampered `fail`, signed missing-evidence `indeterminate`, caller-policy downgrade refusal, unknown-argument refusal, per-operation timeouts, and fresh-process cleanup. The runner compares the complete normalized verdict objects from both output files.

The Node dependency directory and Python environment are generated outside the tracked source. Bootstrap them before the runtime jail with the one-command form:

```bash
REPRO_ROOT=$(git rev-parse --show-toplevel)
PYTHON_ENV=$(mktemp -d "${TMPDIR:-/tmp}/dacs-mcp-python.XXXXXX")
OUTPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dacs-mcp-output.XXXXXX")
"$REPRO_ROOT/test/mcp-e2e/run-e2e.sh" \
  --server "$REPRO_ROOT/packages/verifier/dist/packages/verifier/src/mcp.js" \
  --python-env "$PYTHON_ENV" \
  --output-dir "$OUTPUT_DIR" \
  --bootstrap
```

`--bootstrap` runs `npm ci --ignore-scripts` in `test/mcp-e2e/` and installs `requirements.lock` before `bwrap`; it may use the network. `npm ci` creates the ignored `test/mcp-e2e/node_modules/` directory. The Python environment and output directory above are outside the checkout; omit `--bootstrap` when those exact dependencies are already installed.

The runtime phase always uses `bwrap --unshare-net`, with the selected output directory as its only writable bind. The server receives `DACS_VERIFIER_MCP_POLICY=offline-enforcing` and `DACS_VERIFIER_RPC=http://127.0.0.1:9` through each client transport. The output’s `runtimeAssertions` are controls and scope metadata: wallet, payment, model, and RPC calls are not instrumented counters. The evidence is the offline policy, network namespace, absence of those client interfaces, and the compared verifier results.

The historical candidate run receipt is retained with the internal build record and is omitted from this public reproduction packet. A fresh runner invocation produces `node.json` and `python.json` under the requested output directory and prints their hashes for review.
