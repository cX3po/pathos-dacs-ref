# `dacs-drift` — DACS conformance / drift check (GitHub Action)

A drop-in CI check for DACS artifact fixtures across two surfaces — it computes each artifact's
**signed-scope hash**, structurally checks it, and — against an expected-hash manifest — **fails CI
when an artifact drifts** from its golden value:

- **DACS-5 §10.4 AttestationBundle** → `bundleHash` (v0.1 R5-1 `anchoredByRole`-excluded form).
- **DACS-4 §9 SettlementEvidence** → `evidenceHash` (sha256 of JCS without `signature`).

It runs your fixtures through the same primitives this reference implementation uses, so "does my
implementation still agree with the reference (and the upstream §14 golden)?" is answered by the
reference's own code — the cross-impl divergence layer where implementations silently disagree.
dacs-drift reproduces the DACS-Standard golden `bundleHash` and `evidenceHash` byte-for-byte.

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

This checks the **signed-scope hash surfaces** — DACS-5 AttestationBundle `bundleHash` and DACS-4
SettlementEvidence `evidenceHash` — **only**. It is not all of DACS, and **not** a full conformance
certification.

- **With `expect-manifest`** — your fixtures reproduce the expected hashes (match golden).
- **Discovery mode (no manifest)** — your fixtures are computed + structurally checked; no hash asserted.
- **Fails the job** on a structurally-invalid artifact in either mode, and additionally on hash **drift**
  or an **expected-but-missing** fixture in manifest mode.

The drift table is written to the **GitHub Step Summary**, so it renders in the Actions UI, not just the logs.

## Output table

Columns: `fixture | kind | our hash (signed-scope) | expected | status | verify`.

- **`kind`** — `DACS-5 bundle` or `DACS-4 evidence`, auto-detected from the artifact.
- **`status`** — `match` (hash reproduces the expected value) · `drift` (hash diverged — **fails**) ·
  `computed` (discovery mode: hash computed, nothing asserted) · `skipped` (neither an AttestationBundle
  nor a SettlementEvidence; skipped in discovery mode, but **fails** if a manifest expected it).
- **`verify`** — `accept` / `reject`; a `reject` (structurally invalid artifact) **fails the job** in
  either mode.

The job also fails on an expected-but-missing fixture in manifest mode.

---

Part of **Wayfare** — PATH-OS Labs' tooling built on the Demos / DACS standard. Maintained at
[`cX3po/pathos-dacs-ref`](https://github.com/cX3po/pathos-dacs-ref); core logic in `src/lib/dacs-drift.ts`
(unit-tested), CLI in `dacs-drift.mts`. Full scope notes: [`CONFORMANCE.md`](../../../CONFORMANCE.md).
