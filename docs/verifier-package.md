# The verifier as a package (`packages/verifier`)

`@pathos-labs/dacs-verifier` exposes the repository's attestation-bundle verifier through four
surfaces that share one implementation:

| Surface | Entry | Calls |
| --- | --- | --- |
| API | `packages/verifier/src/index.ts` | re-exports `src/lib/verify-document.ts`, `verify-bundle-v1.ts`, `verify-bundle.ts` |
| CLI | `packages/verifier/src/cli.ts` (`dacs-verifier`) | `loadBundleSource()` + `verifyDocument()` |
| HTTP | `packages/verifier/src/http.ts` (`dacs-verifier-http`) | `route()` -> `verifyDocument()` |
| MCP | `packages/verifier/src/mcp.ts` (`dacs-verifier-mcp`) | `handleRequest()` -> `verifyDocument()` |

`src/lib/verify-document.ts` is new in this change: the repository CLI (`src/cli/verify.ts`)
now imports its bundle classification, verdict normalisation, exit-code mapping and source
loading from there instead of carrying them locally, so the packaged surfaces and the in-tree
CLI cannot drift.

## Build

`node --import tsx scripts/build-verifier-package.mts` compiles the four entries with
`rootDir` at the repository root, so `dist/` keeps source paths (`dist/src/lib/...`,
`dist/packages/verifier/src/...`). `provenance.json` records the compiled source set and the
emitted file set with SHA-256s. `--check` rebuilds into a temporary directory under the
repository root and fails on any byte difference; CI runs it before the test suite.
`dist/` is committed for the same reason the JCS package's is: consumers and the container
build from the checked-in output, and the check proves it matches the sources.

## Tests

`test/vectors/verifier-package.test.ts` proves: the package entry re-exports the very
functions `src/lib` exports; the built `dist` is reproducible and imports only declared
dependencies; the built CLI, `route()` and the MCP tool return byte-equal results for the same
bundle and that result satisfies `schemas/verify-verdict.schema.json`; verdicts are never
coerced (unanchored, tampered, unrecognised, unloadable); HTTP caller errors are 4xx, `rpc` is
refused as a request field, oversized bodies are 413; MCP bad frames are structured errors and
the loop survives; the Dockerfile references files the build produces. No test touches the
network.

## Container

`packages/verifier/Dockerfile` builds a `node:20-alpine` image that runs the HTTP service on
0.0.0.0:8787 as the `node` user. The image installs the package's declared dependencies from the
registry; the repository's demosdk patch is not applied inside it (documented in the package
README). Building the image is a local or release step, not part of `npm test`.

## Scope

Registry publication, credentials, release approval and image publication remain separate
operator steps (plan item s5-pkg-publish). The package is a reference implementation and not a
DACS-Standard publication.
