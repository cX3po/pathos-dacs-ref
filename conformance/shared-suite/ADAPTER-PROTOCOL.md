# DACS adapter subprocess protocol v1

This document defines the language-neutral boundary for the non-normative shared runner.
An adapter is an executable owned by its implementation. It reads JSON Lines from stdin and
writes exactly one JSON response line to stdout for each request. Diagnostics go to stderr.
The protocol identifier is `dacs-adapter/1`.

The runner may keep a process alive or start a clean process per request. An adapter must not
depend on process state between requests.

## Envelope and metadata handshake

Every request contains `protocol`, a runner-chosen string `id`, and `type`. Every response
echoes `protocol` and `id`, then contains either `{ "ok": true, "result": ... }` or
`{ "ok": false, "error": { "code": "...", "message": "..." } }`.

The mandatory first request is:

```json
{"protocol":"dacs-adapter/1","id":"1","type":"metadata"}
```

A metadata result has this shape:

```json
{
  "name": "example-dacs",
  "version": "1.2.0",
  "repository": "https://example.test/example-dacs",
  "revision": "sha256:... or immutable commit id",
  "supportedFamilies": ["canonical-accept", "sig-value-encoding"],
  "operations": ["canonicalize", "signatureValueVerdict"]
}
```

`repository` identifies the implementation-owned adapter repository and `revision` pins the
exact adapter used. A branch name such as `main` or a mutable tag such as `latest` is not an
immutable revision. Reports retain the complete handshake. `INTEROP-AGREE` requires at least
two participating, non-demo adapters with distinct repository provenance; two wrappers around
one implementation remain a self-check.

## Execute request

```json
{"protocol":"dacs-adapter/1","id":"2","type":"execute","operation":"signatureValueVerdict","params":["YQ"]}
```

Operations and results are:

| Operation | Parameters | Result |
|---|---|---|
| `canonicalize` | `[value]` | `{ "hex": "..." }` |
| `signedScopeHash` | `[artifact]` | `{ "hex": "..." }` |
| `signatureValueVerdict` | `[value]` | `"ACCEPT"` or `"REJECT"` |
| `legacySignatureValueImport` | `[value, sourceEncoding]` | `{ "verdict": "ACCEPT", "canonicalValue": "..." }` or `{ "verdict": "REJECT" }` |
| `verifyBundle` | `[bundle]` | `{ "decision": "accept" | "reject" | "indeterminate" }` |
| `domainSepSign` | `[messageBytes, separator, privateKeyBytes, intermediateHashBytes?]` | `{ "hex": "..." }` |
| `domainSepVerify` | `[messageBytes, separator, signatureBytes, publicKeyBytes, intermediateHashBytes?]` | boolean |

F3 `signatureValueVerdict` is algorithm-independent and accepts only canonical unpadded
Base64URL. It does not enforce Ed25519's 64-byte decoded length. Algorithm-specific length
and cryptographic verification belong to the applicable algorithm contract. Standard Base64
is never accepted by this operation. Migration uses the distinct
`legacySignatureValueImport` operation and supplies `sourceEncoding` out of band; v1 defines
only `"base64"`.

JSON values that JSON cannot express directly use tagged objects:

```json
{"$dacsType":"bytes","hex":"00ff"}
{"$dacsType":"bigint","decimal":"9007199254740993"}
```

Unknown operations, malformed tagged values, and operation failures return `ok: false`.
Adapters must never write banners or logs to stdout.

## Versioning

Additive operations and families do not change the protocol identifier. A change to envelope
semantics, tagged-value interpretation, or an existing operation requires a new protocol
identifier. Language-specific module wrappers are conveniences only; this subprocess protocol
is the WG contract.
