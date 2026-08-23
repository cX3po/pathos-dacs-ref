# DACS Shared Conformance Suite (WG-adoption seed)

This is a non-normative, language-neutral runner seed for finding byte and verdict differences
between DACS implementations. It is interoperability tooling, not a specification change or a
certification program.

Adapters are executables speaking [`dacs-adapter/1`](./ADAPTER-PROTOCOL.md), a JSONL
request/response protocol over stdin/stdout with a mandatory provenance handshake. The default
run starts the PATH-OS reference adapter as a subprocess:

```sh
node cross-run.mjs
node cross-run.mjs --json
node cross-run.mjs --spec-questions
```

### Registering multiple adapters

The runner can launch multiple external adapter commands over the same subprocess protocol.
Provenance from each adapter's handshake is preserved in the report.

```sh
# repeatable --adapter; --adapter-provenance attaches a recorded provenance assertion to the
# preceding --adapter (used when independence cannot be inferred from the repository URL alone):
node cross-run.mjs \
  --adapter "node reference-adapter-process.mjs" \
  --adapter "path/to/other-impl-adapter" --adapter-provenance "https://example.org/other-impl"

# or a config file listing adapter commands + declared provenance:
node cross-run.mjs --config adapters.json
# adapters.json: { "adapters": [ { "command": ["node","reference-adapter-process.mjs"] },
#                                 { "command": ["./other"], "provenanceCodebase": "https://…",
#                                   "timeoutMs": 10000, "maxOutputBytes": 8388608 } ] }
```

**Runner-tracked identity (Blocker 1 fix).** Every adapter run is assigned a unique runner-side
`runId` (`run-0`, `run-1`, …) independent of the self-reported `metadata.name`. Results are keyed
by that `runId`, so two adapters that self-report the same name can never overwrite each other and
produce a false `INTEROP-AGREE`. Duplicate self-reported names are surfaced as a warning.

**Provenance canonicalization (Blocker 2 fix).** Independence is counted over a *canonicalized*
codebase identity, not the raw repository string: `.git` suffixes, trailing slashes, `git+`
transport prefixes, scheme/host case, default ports, and `scp`-style `git@host:owner/repo` are all
normalized, so `https://x/impl` and `https://x/impl.git` are ONE codebase (a self-check, not
interop), and two wrappers around one implementation are not independent. When independence cannot
be inferred structurally, an explicit `provenanceCodebase` assertion (recorded in the report) is
honored instead of inferring it.

**Subprocess safety (Blocker 3 fix).** Each adapter request has a per-adapter wall-clock timeout
and a bounded stdout+stderr budget (defaults 10s / 8 MiB, overridable per adapter). A hung,
crashing, or flooding adapter is SIGKILLed and recorded as an `UNAVAILABLE` adapter that abstains
on every vector — fail-closed, never a silent pass and never a hang or OOM of the whole cross-run.

> **Out of scope (Blocker 4, still open):** the multi-adapter path above provides the *invocation*
> mechanism and preserves provenance, but this seed still ships only ONE genuine implementation
> adapter (the PATH-OS reference) and no signed/pinned adapter manifest. Real `INTEROP-AGREE`
> evidence requires a *second genuinely independent* implementation adapter plus a reviewed
> manifest pin. Until then the default run is a self-check. Fixtures under `test-fixtures/` exist
> only to exercise the runner and are not cross-implementation evidence.

## Result categories

| Condition | Row status / category |
|---|---|
| one implementation matches the pinned expected value | `SELF-CHECK` |
| at least two independent real adapters agree with the expected value | `INTEROP-AGREE` |
| any result differs from the pinned expected value | `VECTOR-MISMATCH` / `vector-mismatch` |
| participating implementations produce different results | `IMPLEMENTATION-DIVERGENCE` / `implementation-divergence` |
| no adapter supports the operation | `ABSTAIN` |
| triage finds genuinely ambiguous or wrong normative text/vector | separately flagged `SPEC-QUESTION` |

A divergence can also contain a vector mismatch; both categories are retained. Neither is
automatically a spec question. The CLI creates `SPEC-QUESTION` only when an operator explicitly
supplies `--triage-spec-question <vector-id>` after triage. Reports never call an implementation
non-conformant.

## Exact seed coverage

The runner reads the existing sources through [`PINNED-SOURCES.json`](./PINNED-SOURCES.json)
and verifies their SHA-256 hashes before execution. It does not copy or rewrite their vectors.

| Measure | Exact count |
|---|---:|
| partner-kit source vectors declared | 49 |
| standalone SIG-6 source cases declared | 3 |
| partner-kit vectors mapped to this adapter interface | 40 |
| SIG-6 cases mapped to operations | 3 |
| executed assertions in the default run | 43 |
| declared partner-kit vectors not executed by this interface | 9 |
| per-vector adapter abstentions in the default run | 0 |
| F4 vectors declared / executed | 0 / 0 |

The 40 partner-kit assertions are canonicalization (27), domain separators (11), and signed
scope (2). Nine declared partner-kit cases are reported but not executed: one raw signed-bytes
layout case and eight full drift/manifest-pipeline cases. The three SIG-6 cases comprise two
strict conforming-path checks and one explicitly selected standard-Base64 legacy import. The
test suite additionally pins the required strict behavior directly: canonical unpadded
Base64URL is accepted and standard Base64 is rejected by the conforming F3 operation.

F4 bundle verification, including referenced-artifact authorization, is aspirational. There
are no shipped F4 vectors and no executed F4 rows, so the runner claims neither an F4 pass nor
a vector-level abstention. It becomes a candidate family only when authoritative vectors and
at least two genuine implementation adapters exist.

## Governance and repository shape

- `DACS-Standard` owns vector inputs, expected results, profile/rule references, vector tiers,
  and manifest hashes. Existing Standard review and tiering rules remain in force.
- A neutral runner may live in a dedicated `DACS-Agent-commerce` repository. It consumes a
  pinned Standard manifest or release and must fail on hash drift; it never silently forks the
  authoritative corpus. This proposal seed lock records its pre-adoption source provenance and
  must be replaced only by a reviewed Standard pin.
- Each implementation owns its adapter. Every report records the runner-assigned `runId` plus the
  adapter's self-reported name/version, repository, immutable revision, supported families, and
  operations from the handshake. The `runId` — not the self-reported name — is the identity the
  runner tracks results by.
- Candidate vectors become cross-implementation evidence only after at least two adapters with
  *distinct canonicalized codebase identities* execute them. Until then, a matching result is
  `SELF-CHECK`. Same-codebase duplicates and wrapper-over-one-impl pairs remain `SELF-CHECK`.
- The runner, adapter protocol, and report format remain non-normative. Passing is
  interoperability evidence, not certification.
