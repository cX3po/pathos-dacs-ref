# `dacs-drift` — DACS conformance / drift check (GitHub Action)

A drop-in CI check for **DACS-5 §10.4 AttestationBundle** fixtures: it computes each bundle's
**signed-scope `bundleHash`** (v0.1 R5-1 `anchoredByRole`-excluded form), structurally verifies it,
and — against an expected-hash manifest — **fails CI when a bundle drifts** from its golden value.

It runs your fixtures through the same verifier this reference implementation uses
(`verifyBundleV1` + `bundleSignedScopeHashV1`), so "does my implementation still agree with the
reference?" is answered by the reference's own code — the cross-impl divergence layer where
implementations silently disagree.

## Quick start

```yaml
# .github/workflows/dacs-conformance.yml
name: DACS conformance
on: [push, pull_request]
jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cX3po/pathos-dacs-ref/.github/actions/dacs-drift@v1
        with:
          fixtures-dir: test/fixtures/bundles          # your *.json AttestationBundle fixtures
          expect-manifest: test/fixtures/expected.json # optional — { "<fixture>.json": "<hashHex>" }
```

Pin to `@v1` for a stable contract; `@main` tracks the tip.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `fixtures-dir` | yes | — | Directory of `*.json` AttestationBundle fixtures to check. |
| `expect-manifest` | no | `''` | JSON `{ "<fixture>.json": "<expectedHashHex>" }`. Omit for **discovery mode** (compute + structurally verify, never fails on hash). |
| `node-version` | no | `20` | Node version to run under. |

> **Bootstrap the manifest** (instead of hand-writing hashes): run
> `npx tsx dacs-drift.mts <fixtures-dir> --emit-manifest > expected.json` against your known-good
> fixtures, commit the result, and point `expect-manifest` at it. See [`CONFORMANCE.md`](../../../CONFORMANCE.md).

## What a green run means (honest scope)

This checks the **§10.4 AttestationBundle signed-scope hash surface only** — not all of DACS, and it
is **not** a full DACS conformance certification.

- **With `expect-manifest`** — your fixtures reproduce the expected `bundleHash`es (match golden).
- **Discovery mode (no manifest)** — your fixtures are computed + structurally verified; no hash asserted.
- **Fails the job** on a structurally-invalid bundle in either mode, and additionally on hash **drift**
  or an **expected-but-missing** fixture in manifest mode.

The drift table is written to the **GitHub Step Summary**, so it renders in the Actions UI, not just the logs.

## Output table

Columns: `fixture | our bundleHash | expected | status | verify`.

- **`status`** — `match` (hash reproduces the expected value) · `drift` (hash diverged — **fails**) ·
  `computed` (discovery mode: hash computed, nothing asserted) · `skipped` (not an AttestationBundle —
  no `bundleVersion`; skipped in discovery mode, but **fails** if a manifest expected it).
- **`verify`** — `accept` / `reject` from the structural + signature verifier; a `reject` (structurally
  invalid bundle) **fails the job** in either mode.

The job also fails on an expected-but-missing fixture in manifest mode.

---

Part of **Wayfare** — PATH-OS Labs' tooling built on the Demos / DACS standard. Maintained at
[`cX3po/pathos-dacs-ref`](https://github.com/cX3po/pathos-dacs-ref); core logic in `src/lib/dacs-drift.ts`
(unit-tested), CLI in `dacs-drift.mts`. Full scope notes: [`CONFORMANCE.md`](../../../CONFORMANCE.md).
