# @pathos-labs/dacs-verifier

The pathos-dacs-ref attestation-bundle verifier as a package: a stable programmatic API, a
command line, a small HTTP service, and an MCP `verify_bundle` tool. Every surface calls the
same `verifyDocument()` from the repository's `src/lib/verify-document.ts`; the package is a
compile of the repository's verifier, not a second implementation (see `provenance.json`).

Verdicts are `pass`, `fail` or `indeterminate` and are never coerced: an unanchored bundle is
indeterminate unless the caller opted into `offline` (receipt-archive audit); a document that
cannot be classified or loaded is indeterminate; a chain failure during verification is
indeterminate. Exit codes: 0 pass, 1 fail, 2 indeterminate, 3 usage error.

## API

```ts
import { verifyDocument, loadBundleSource } from '@pathos-labs/dacs-verifier';
const result = await verifyDocument(bundle, { offline: true });
// { apiVersion: 'pathos-dacs-verifier:1', bundleKind: 'v1' | 'legacy' | 'unrecognised', verdict, exitCode }
```

`schemas/verify-verdict.schema.json` describes the result; `schemas/verify-request.schema.json`
describes the HTTP body and the MCP tool arguments. `bundleKind` is `v1` for
`bundleVersion:"1"` bundles and `legacy` for `v:"dacs-5-bundle:0.1"`.

## Command line

```
dacs-verifier --bundle-file bundle.json --offline --json
dacs-verifier --stdin --offline --json < bundle.json
dacs-verifier --bundle-anchor stor-... --rpc https://demosnode.discus.sh/
dacs-verifier --jobId <uuid>
```

## HTTP service

```
dacs-verifier-http --host 127.0.0.1 --port 8787 --rpc https://demosnode.discus.sh/
POST /verify            {"bundle": {...}, "offline": true}      -> 200 with the result
GET  /healthz           -> {ok, name, version, apiVersion}
GET  /schemas/verify-request.json, /schemas/verify-verdict.json
```

A well-formed request always answers 200 with a verdict. Caller-side problems answer 4xx;
bodies over 1 MiB answer 413. The Demos RPC is server configuration (`--rpc` or
`DACS_VERIFIER_RPC`), never a request field. The service has no authentication and binds
127.0.0.1 by default; put it behind something that authenticates before exposing it.

## MCP server

`dacs-verifier-mcp` speaks JSON-RPC over stdio (protocol 2024-11-05) with tools
`verify_bundle` (`bundle`, `offline?`, `requireSignatures?`) and `verifier_info`.

## Container

```
docker build -t dacs-verifier packages/verifier
docker run --rm -p 8787:8787 dacs-verifier
docker run --rm -i dacs-verifier dist/packages/verifier/src/mcp.js
docker run --rm -i dacs-verifier dist/packages/verifier/src/cli.js --stdin --offline --json < bundle.json
```

The image's entrypoint is `node`; the default command is the HTTP service. Dependencies are
installed with `npm ci` from the committed `package-lock.json`, so two builds run the same
dependency versions. The repository's
`patches/` are not applied inside the image, so anchored text that depends on the demosdk
UTF-8 patch is verified by the in-tree CLI, not by the container, until that patch is upstream.

## Provenance and reproducibility

`provenance.json` lists every compiled source with its SHA-256 and every emitted file with its
SHA-256; no git revision or timestamp is embedded. In the repository,
`node --import tsx scripts/build-verifier-package.mts --check` fails on any byte difference
between the committed `dist` and a fresh build, and CI runs that check.

This package is a reference implementation and not a DACS-Standard publication. Registry
publication is a separate operator step.
