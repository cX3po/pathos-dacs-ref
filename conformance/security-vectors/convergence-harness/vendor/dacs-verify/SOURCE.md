# Vendored: dacs-verify (independent DACS reference verifier)

- **Upstream:** https://github.com/mj-deving/dacs-verify (MIT, by @mj-deving / Marius J)
- **Vendored commit:** `10aefa7f00679129941b110d8d486648ae297147`
- **Vendored:** 2026-07-01, verbatim (no logic edits) — for the convergence harness's
  `dacs-verify` adapter, so the Trust Wall reflects REAL cross-impl agreement between
  pathos-dacs-ref and this independent second implementation.
- **What we use:** `src/dacs5/bundle.ts` (`bundleHash`, `verifyBundle`) + its transitive
  imports (canonicalize, hash, signing, dacs1). Do NOT edit — this must stay the REAL impl.
- Re-vendor by re-cloning upstream at a newer commit and updating this SHA.
