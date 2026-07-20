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
- Each implementation owns its adapter. Every report records adapter name/version, repository,
  immutable revision, supported families, and operations from the handshake.
- Candidate vectors become cross-implementation evidence only after at least two independent,
  real adapters execute them. Until then, a matching result is `SELF-CHECK`.
- The runner, adapter protocol, and report format remain non-normative. Passing is
  interoperability evidence, not certification.
