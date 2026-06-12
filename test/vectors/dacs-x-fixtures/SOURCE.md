# DACS-X cross-impl fixtures (vendored)

Vendored from `mj-deving/dacs-verify` (`conformance/fixtures/`), the contributor fixtures
pinned in DACS-Standard #117 / #99. Used to test our §10.4 acceptance verifier reproduces
the same `bundleHash` and accept/reject verdicts (cross-impl convergence).

- `attestation-bundle-0004.json` — DACS-VERIFY-0004, outcome `completed` (consistent buyer bundle)
- `attestation-bundle-0004-seller.json` — same jobId, outcome `failed-counterparty` (§10.4.3(d) divergence)
- `attestation-bundle-htlc9.json` — HTLC-9 `dest-revealed-source-unclaimed`, outcome `failed-counterparty` (v0.1 R4-A: the asymmetric-settlement resolution is no longer the unreachable `failed-substrate`)

Non-normative illustrative fixtures; signers use placeholder DIDs (not resolvable keys).

## Re-vendor 2026-06-11 — DACS v0.1 R5-1 (anchoredByRole EXCLUDE convergence)

Re-vendored from `DACS-Agent-commerce/DACS-Standard` `main` @ `27aa692` (`conformance/fixtures/`)
after upstream published DACS v0.1, which resolves `anchoredByRole` to **EXCLUDED from the hashed
canonical form** (CHANGELOG R5-1; DACS-5 §10.4.1/§227/§231/§248). The three fixtures were
regenerated upstream under the exclude rule (new signatures + one changed contentHash). Our
verifier now computes the exclude-rule `bundleHash`, matching upstream `conformance/vectors/golden.json`:

- `attestation-bundle-0004.json` → `9e5ea58d198b459a2929d38019807c465ce9988dcb89c847cce8e80210df39ba`
- `attestation-bundle-0004-seller.json` → `83b180d7a2a00109e96fe099df6c1ef14271b5c0d43c24da78051238cee580bd`
- `attestation-bundle-htlc9.json` → `ba1889b7d86e37b98cd2f7b4a053f328ab33e7137b0edff8efb4645f24fd4096`

Supersedes the prior pin `98d7b565…` (in-hash rule, R4-B). This re-pin makes pathos-dacs-ref the
converged party again; the joint convergence note in DACS-Standard #99 is HELD for Phil (outbound).
