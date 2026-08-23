# Vendored golden vectors (for hermetic CI convergence)

These are verbatim copies of DACS-Standard golden vectors, vendored so the convergence
suite (`conformance/convergence-suite.mts` + `.github/workflows/convergence.yml`) runs
deterministically in CI without a network fetch. Refresh when the upstream golden moves.

| file | upstream | as-of |
|------|----------|-------|
| control-gate-vectors.json | DACS-Agent-commerce/DACS-Standard `conformance/fixtures/identity/control-gate-vectors.json` @ branch `next` | 2026-07-08 (9/9 convergence, closes #170) |

To refresh: `gh api repos/DACS-Agent-commerce/DACS-Standard/contents/conformance/fixtures/identity/control-gate-vectors.json?ref=next --jq .content | base64 -d > control-gate-vectors.json` and re-run the suite.
