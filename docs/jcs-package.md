# JCS package

`@pathos-labs/dacs-jcs` packages the repository's JCS canonicalization, SHA-256 helpers, registered domain separators, and registry-bound Ed25519 helpers as ESM for Node.js 20 or later.

The API consists of `jcsCanonical`, `jcsHash`, `jcsHashHex`, `sign`, `verify`, `generateKeypair`, the separator maps, `assertKnownSeparator`, `assertEmittableSeparator`, `isLegacyReadSeparator`, and `buildSignedBytes`. Signing rejects unknown and read-only legacy separators; verification returns `false` for unknown separators. CF-1 NFC normalization applies to string values and not to object member names.

Build and reproducibility check commands are:

```sh
node --import tsx scripts/build-jcs-package.mts
node --import tsx scripts/build-jcs-package.mts --check
```

The build compiles byte copies of `src/jcs.ts`, `src/domain-sep.ts`, and `src/lib/sign.ts`. `provenance.json` fingerprints the compiled source manifest from paths and content hashes, without a Git revision or timestamp. The check rebuilds in a temporary directory and compares every package byte.

`vectors/canonical-form-v0.1.json` is derived from `conformance/partner-kit/vectors.json`: it keeps only the canonical-form sections (27 vectors, no key material) and records the source path, SHA-256, and kept sections under `derivedFrom`; the index records path, size, SHA-256, and origin. It includes the repository's JCS accept/reject corpus and NFC/NFD cases.

The package does not include higher-level DACS artifact construction, validation, transport, storage, CLI code, or the broader protocol fixture sets. It is not a DACS-Standard publication. The repository does not publish it to a registry; registry publication, credentials, release approval, and provenance attestation remain separate operator steps.
