# DACS verifier MCP partner reproduction packet

This packet is a portable, read-only reproduction of the hardened verifier MCP policy and its two official client adapters. It does not make a live-chain, payment, wallet, model, published-package, independent-verifier, or partner-adoption claim.

The source pins are:

- clean base: `390c5fa01ed3ff24f4a0b2a52464922b4fef264f`
- hardened MCP policy source: `3473be9f2510f96e9259ef2a3c356cb16bab3c42`
- two-client probes: `1390cc4ece9d28a5dd630e1aa393334a6c111e10`

From a checkout containing this packet, the short reproduction path is:

```bash
REPRO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPRO_ROOT"

# Install the root build dependencies outside the runtime jail.
npm ci --ignore-scripts

# Rebuild the local verifier bytes from the pinned sources.
node --import tsx scripts/build-verifier-package.mts --check

# Install the official Node client dependencies outside the runtime jail.
npm ci --ignore-scripts --prefix test/mcp-e2e

# Create a disposable Python environment outside the checkout and install the exact lock.
PYTHON_ENV=$(mktemp -d "${TMPDIR:-/tmp}/dacs-mcp-python.XXXXXX")
python3 -m venv "$PYTHON_ENV"
"$PYTHON_ENV/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r test/mcp-e2e/requirements.lock
"$PYTHON_ENV/bin/python" -m pip check

# Run both official clients with the server in a network-isolated namespace.
OUTPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dacs-mcp-output.XXXXXX")
test/mcp-e2e/run-e2e.sh \
  --server "$REPRO_ROOT/packages/verifier/dist/packages/verifier/src/mcp.js" \
  --python-env "$PYTHON_ENV" \
  --output-dir "$OUTPUT_DIR"
```

The runner uses `bwrap --die-with-parent --unshare-net`, a read-only root view, and one writable output directory. Dependency installation occurs before that runtime jail. The server is started with `DACS_VERIFIER_MCP_POLICY=offline-enforcing` and `DACS_VERIFIER_RPC=http://127.0.0.1:9` by each official client transport.

The expected output contains two JSON files, `node.json` and `python.json`, with equal fixture hashes and complete equal verdict objects:

- valid signed bundle: `pass`, exit code `0`, two verified signers;
- the same bundle after a `jobId` mutation: `fail`, exit code `1`;
- a separately signed bundle carrying a missing evidence anchor: `indeterminate`, exit code `2`;
- `requireSignatures:false`, `offline:false`, and unknown arguments: refused;
- protocol: `2024-11-05`; tools: `verifier_info`, `verify_bundle`.

The fresh receipt should record this compact field set: `sourceCommit`, `server.binarySha256`, `clients.nodeLockSha256`, `clients.pythonLockSha256`, `fixtures.validFileSha256`, `fixtures.validCanonicalSha256`, `fixtures.indeterminateFileSha256`, `fixtures.indeterminateCanonicalSha256`, `outputs.nodeSha256`, `outputs.pythonSha256`, `verdicts.valid`, `verdicts.tampered`, `verdicts.indeterminate`, `errors`, `platform.node`, `platform.python`, `platform.kernel`, and `runtime.networkIsolation`. Runtime controls must be described as controls: wallet, payment, model, and RPC calls are not instrumented counters. Preserve the output directory for review; do not commit it.

The hardened server policy is available in `@pathos-labs/dacs-verifier@0.2.0`. These clients require server version `0.2.0`; use either the matching local build above or the absolute `dist/packages/verifier/src/mcp.js` path within a registry-installed `@pathos-labs/dacs-verifier@0.2.0`. Both clients have also been run locally against that registry version with networking disabled and matching normalized verdicts. Independent partner reproduction remains pending.
