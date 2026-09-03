# Fixtures data package

`@pathos-labs/dacs-fixtures` lets another implementation consume the reference repository's C1 manifests and selected settlement/HTLC fixtures without cloning this repository. It is a deterministic data package: it has no runtime entry point, executable package scripts, or code files.

The package contains the C1 implementation manifest, partner-kit manifest, vectors, README and license, plus the C1 bridge reference text. Its settlement group contains the `settlement-v1` and `sb2-settlement-uniqueness` security-vector sets and the pinned DACS-Standard settlement evidence, bijection vectors, and pin README. Its HTLC group contains the selected convergence-harness HTLC attestation bundle.

`packages/fixtures/index.json` is RFC 8785/JCS-canonical JSON. Its `v` field identifies the index schema, `generatedFrom` records the source repository commit, and each `files` item records the package path, SHA-256, byte count, group, and upstream origin. `expectations` contains only outcomes found in each vector case's own `expected`, `verdict`, or `decision` field; it does not infer outcomes for ordinary fixture files.

Rebuild the package from the byte-for-byte sources:

```sh
node --import tsx scripts/build-fixtures-package.mts
```

Check that the committed package is exactly reproducible:

```sh
node --import tsx scripts/build-fixtures-package.mts --check
```

Nothing from private material is included. This repository task only prepares the package; publication to a registry is a separate operator step.
