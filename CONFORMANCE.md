# DACS conformance checking with `dacs-drift`

`dacs-drift` checks whether your DACS artifact fixtures reproduce the expected **signed-scope hash** —
the layer where independent implementations can silently disagree. It covers two surfaces today:

- **DACS-5 §10.4 AttestationBundle** → `bundleHash` (v0.1 R5-1 `anchoredByRole`-excluded form), via
  `verifyBundleV1` + `bundleSignedScopeHashV1`.
- **DACS-4 §9 SettlementEvidence** → `evidenceHash` = sha256(JCS(evidence without `signature`)).

It reuses this implementation's own primitives, so "does my impl agree with the reference (and the
upstream §14 golden)" is answered by the same code the reference uses. dacs-drift independently
reproduces the DACS-Standard golden `bundleHash` **and** `evidenceHash` byte-for-byte (cross-impl
convergence, locked by test).

**Scope (honest):** this checks the **bundleHash / evidenceHash signed-scope surfaces** only — not all
of DACS, and not a full conformance certification. With **`--expect` (a hash manifest)** your fixtures
must reproduce the expected hashes (match the reference / golden); in **discovery mode** they are
computed + structurally checked but no hash is asserted. The job **fails on a structurally-invalid
artifact in either mode**, and **additionally on hash drift or an expected-but-missing fixture in
`--expect` mode**. Each artifact is auto-detected (AttestationBundle vs SettlementEvidence); other
JSON is skipped (discovery) or fails (if a manifest expected it).

## Use it in CI — a drop-in GitHub Action

```yaml
# .github/workflows/dacs-conformance.yml
name: DACS conformance
on: [push, pull_request]
jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cX3po/pathos-dacs-ref/.github/actions/dacs-drift@main
        with:
          fixtures-dir: test/fixtures/bundles        # your AttestationBundle fixtures
          expect-manifest: test/fixtures/expected.json  # optional; omit for discovery mode
```

- **`expect-manifest`** is `{ "<fixture>.json": "<expectedHashHex>", ... }`. With it, each fixture
  **named in the manifest** is compared MATCH/DRIFT and **the job fails on any drift, struct-fail, or
  expected-but-missing fixture** (fixtures not in the manifest are still computed + structurally checked).
- **Omit it** for *discovery mode*: dacs-drift computes the hash + structurally verifies each bundle and
  reports — it never fails on a hash, but **still fails on a structurally-invalid bundle**.

## Bootstrap your `expect-manifest`

Drift mode needs a manifest of expected hashes — generate it from your known-good fixtures instead of
hand-writing hashes:

```bash
npx tsx dacs-drift.mts test/fixtures/bundles --emit-manifest > test/fixtures/expected.json
```

It pins **only the valid bundles** (structurally-valid + verified) to their computed bundleHash; non-
bundles and struct-fails are excluded (diagnostics go to stderr, so stdout is a clean, redirectable
manifest). Commit `expected.json`, wire it as `expect-manifest`, and CI fails the moment a bundle drifts
from those pinned hashes. (`--emit-manifest` is mutually exclusive with `--expect`.)

## Run it locally

```bash
npx tsx dacs-drift.mts <fixtures-dir> [--expect <manifest.json>] [--json]
npx tsx dacs-drift.mts <fixtures-dir> --emit-manifest > expected.json   # bootstrap the manifest
# exit 0 = all conform · 1 = drift/struct-fail/missing · 2 = usage error
```

## What it catches
- A bundle whose signed-scope hash differs from the expected/golden value (impls disagree on canonical form or content).
- A fixture that is structurally non-conformant to the §10.4 schema.
- A manifest that names a fixture absent from the directory (silent-coverage-gap guard).
- The exact convergence check we ran in [DACS-Standard #99](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/99): our verifier reproduces the upstream `conformance/vectors/golden.json` bundle hashes.

Maintained by PATH-OS Labs · MIT · conformance stated per-surface, deliberately conservative.
