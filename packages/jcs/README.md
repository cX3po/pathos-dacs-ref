# @pathos-labs/dacs-jcs

This package exposes the PATH-OS JSON canonicalization, SHA-256, and Ed25519 signing helpers for Node.js 20 or later.

This is **not a DACS-Standard publication**. This repository does not publish the package to an npm registry; registry publication is a separate operator action.

## API

- `jcsCanonical(value)` returns canonical UTF-8 bytes.
- `jcsHash(value)` returns the 32-byte SHA-256 digest of those bytes.
- `jcsHashHex(value)` returns that digest as lowercase hexadecimal.
- `sign(separator, body, privateKey, intermediateHash?)`, `verify(separator, signature, body, publicKey, intermediateHash?)`, and `generateKeypair()` provide Ed25519 operations.
- The exported separator maps, guards, and `buildSignedBytes` expose the repository's closed domain-separator registry.

The DACS CORE CF-1 pre-pass normalizes JSON string **values** to NFC. Object member names are not normalized: RFC 8785 preserves them and orders their raw UTF-16 code units. The implementation also rejects BigInt, non-finite numbers, numbers whose magnitude exceeds `Number.MAX_SAFE_INTEGER`, unpaired UTF-16 surrogates, and other inputs that cannot produce the repository's reproducible JSON form.

Signing is registry-bound. `sign` accepts only an emittable separator registered by `src/domain-sep.ts`; read-only legacy separators cannot produce signatures. `verify` returns `false` for an unknown separator. This prevents callers from using the signing primitive without an assigned purpose string.

## Vectors

`vectors/canonical-form-v0.1.json` is derived deterministically from `conformance/partner-kit/vectors.json`: it carries only the canonical-accept and canonical-reject sections (the repository's JCS corpus, including NFC/NFD value and member-name cases) and records the source file's SHA-256; the partner-kit signing and drift sections, which carry test keys, are not packaged. `vectors/index.json` records its package path, byte count, SHA-256 digest, and origin.

## Provenance and build

There is one authoritative implementation: the repository files `src/jcs.ts`, `src/domain-sep.ts`, and `src/lib/sign.ts`. The build refreshes their package source copies byte-for-byte and compiles those exact files with `packages/jcs/src/index.ts`. `provenance.json` lists each compiled source and records `sourceManifestSha256`, the SHA-256 of the JCS-encoded, path-sorted list of source paths and content hashes. It is content-derived and contains no Git HEAD or timestamp.

From the repository root:

```sh
node --import tsx scripts/build-jcs-package.mts
node --import tsx scripts/build-jcs-package.mts --check
```
