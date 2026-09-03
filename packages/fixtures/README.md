# @pathos-labs/dacs-fixtures

A deterministic, data-only package of PATH-OS C1 materials and settlement/HTLC fixtures for implementations that do not clone this repository.

This package is **not a DACS-Standard publication**. It includes non-normative PATH-OS material and byte-for-byte copies of the pinned inputs identified below.

## Contents and origins

| Packaged file | Group | Upstream path | Repository and pin |
| --- | --- | --- | --- |
| `data/c1/conformance/implementation-manifests/pathos-dacs-ref.json` | c1 | `conformance/implementation-manifests/pathos-dacs-ref.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/c1/conformance/partner-kit/LICENSE` | c1 | `conformance/partner-kit/LICENSE` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/c1/conformance/partner-kit/MANIFEST.json` | c1 | `conformance/partner-kit/MANIFEST.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/c1/conformance/partner-kit/README.md` | c1 | `conformance/partner-kit/README.md` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/c1/conformance/partner-kit/vectors.json` | c1 | `conformance/partner-kit/vectors.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/c1/docs/c1-conformance-bridge.md` | c1 | `docs/c1-conformance-bridge.md` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/htlc/conformance/security-vectors/convergence-harness/corpus/attestation-bundle-htlc9.json` | htlc | `conformance/security-vectors/convergence-harness/corpus/attestation-bundle-htlc9.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/settlement/conformance/security-vectors/sb2-settlement-uniqueness/vectors/sb2-settlement-uniqueness-v0.1.json` | settlement | `conformance/security-vectors/sb2-settlement-uniqueness/vectors/sb2-settlement-uniqueness-v0.1.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json` | settlement | `conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json` | [https://github.com/cX3po/pathos-dacs-ref](https://github.com/cX3po/pathos-dacs-ref) @ `671811f62942de48da5e59d1b3294ff4f43e6555` |
| `data/settlement/dacs-standard/README.md` | settlement | `README.md` | [https://github.com/DACS-Agent-commerce/DACS-Standard](https://github.com/DACS-Agent-commerce/DACS-Standard) @ `63793a39` |
| `data/settlement/dacs-standard/fixtures/settlement-evidence-delivery-success.json` | settlement | `fixtures/settlement-evidence-delivery-success.json` | [https://github.com/DACS-Agent-commerce/DACS-Standard](https://github.com/DACS-Agent-commerce/DACS-Standard) @ `63793a39` |
| `data/settlement/dacs-standard/fixtures/settlement-evidence-payment-success.json` | settlement | `fixtures/settlement-evidence-payment-success.json` | [https://github.com/DACS-Agent-commerce/DACS-Standard](https://github.com/DACS-Agent-commerce/DACS-Standard) @ `63793a39` |
| `data/settlement/dacs-standard/vectors/security/bundle-settlement-evidence-bijection-v0.4.json` | settlement | `vectors/security/bundle-settlement-evidence-bijection-v0.4.json` | [https://github.com/DACS-Agent-commerce/DACS-Standard](https://github.com/DACS-Agent-commerce/DACS-Standard) @ `63793a39` |

The two settlement-named security-vector sets included from `conformance/security-vectors` are `settlement-v1` and `sb2-settlement-uniqueness`; no other directory name there contains `settlement` or `htlc`. The HTLC convergence corpus file is included separately because it is an explicitly selected fixture.

The copied DACS-Standard README records the source fixture hashes and the short commit pin `63793a39`. The C1 implementation manifest and partner-kit manifest also retain their own embedded provenance pins.

## Index

`index.json` is JCS-canonical JSON with version `pathos-dacs-fixtures-index:0.1`. `generatedFrom` is the PATH-OS git commit used to build the package. Each `files` entry gives a package-relative path, SHA-256, byte count, group, and origin. Each `expectations` entry is copied only from a vector's own case-level `expected`, `verdict`, or `decision` field; `vectorName` is the case's `name` or `id` when present. Files without such a field have no expectation entry.

To verify the bytes, hash a data file directly and compare both values with its index entry, for example:

`sha256sum data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json`

`wc -c data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json`

From a checkout of the source repository, rebuild or check the complete package with:

`node --import tsx scripts/build-fixtures-package.mts`

`node --import tsx scripts/build-fixtures-package.mts --check`
