# Fixtures data package

`@pathos-labs/dacs-fixtures` lets another implementation consume the reference repository's C1 manifests and selected settlement/HTLC fixtures without cloning this repository. It is a deterministic data package: it has no runtime entry point, executable package scripts, or code files.

The package contains the C1 implementation manifest, partner-kit manifest, vectors, README and license, plus the C1 bridge reference text. Its settlement group contains the `settlement-v1` and `sb2-settlement-uniqueness` security-vector sets and the pinned DACS-Standard settlement evidence, bijection vectors, and pin README. Its HTLC group contains the selected convergence-harness HTLC attestation bundle.

`packages/fixtures/index.json` is RFC 8785/JCS-canonical JSON. Its `v` field identifies the index schema. `generatedFrom.sourceManifestSha256` is the SHA-256 of the JCS list of `{ sourcePath, sha256 }` records for every copied source file, and is therefore independent of the current PATH-OS commit. The top-level `pins` object contains only the upstream commits already recorded by the sources: DACS-Standard `63793a39` and dacs-sdk `12c5ad358800b4ddc6e732405366035b6a2ac955`. Each `files` item records the package path, SHA-256, byte count, group, and origin. PATH-OS origins contain repository and path only; copied DACS-Standard origins also carry their upstream pin. `expectations` contains only outcomes found in each vector case's own `expected`, `verdict`, or `decision` field; it does not infer outcomes for ordinary fixture files.

The packaged `data/settlement/dacs-standard/README.md` is the PATH-OS pin record for the copied DACS-Standard files, not the DACS-Standard README. The package `LICENSE` contains separately delimited PATH-OS and DACS-Standard MIT notices; the latter is reproduced from DACS-Standard commit `63793a39`. `NOTICE` maps each copied file to its applicable notice.

Rebuild the package from the byte-for-byte sources:

```sh
node --import tsx scripts/build-fixtures-package.mts
```

Check that the committed package is exactly reproducible:

```sh
node --import tsx scripts/build-fixtures-package.mts --check
```

Nothing from private material is included. This repository task only prepares the package; publication to a registry is a separate operator step.
