# DACS-X cross-impl fixtures (vendored)

Vendored from `mj-deving/dacs-verify` (`conformance/fixtures/`), the contributor fixtures
pinned in DACS-Standard #117 / #99. Used to test our §10.4 acceptance verifier reproduces
the same `bundleHash` and accept/reject verdicts (cross-impl convergence).

- `attestation-bundle-0004.json` — DACS-VERIFY-0004, outcome `completed` (consistent buyer bundle)
- `attestation-bundle-0004-seller.json` — same jobId, outcome `failed-counterparty` (§10.4.3(d) divergence)
- `attestation-bundle-htlc9.json` — HTLC-9 `dest-revealed-source-unclaimed`, outcome `failed-substrate`

Non-normative illustrative fixtures; signers use placeholder DIDs (not resolvable keys).
