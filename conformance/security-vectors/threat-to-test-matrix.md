# DACS §12.4 threat-to-test matrix (security conformance coverage)

_Maps every DACS v0.1 §12.4 threat to whether a conformance test actually verifies the claimed defense.
Built by PATH-OS as the independent conformance contributor; offered non-normatively. Conservative by
design: COVERED is asserted ONLY with a citable test in pathos-dacs-ref (overclaiming coverage is the
dangerous error in a security artifact). Source: DACS-Standard spec/THREAT-MODEL.md §12.4 (46 rows)._

## Buckets
- ✅ **COVERED** — a conformance test verifies the defense (test cited).
- 🟡 **PARTIAL** — an aspect is tested; the full defense is not.
- 🕳️ **GAP** — the spec claims a defense; no test yet → candidate next conformance vector.
- ⚖️ **RESIDUAL** — the spec *explicitly accepts* the risk (§12.1 non-goal / "accepted by design" / "protocol cannot prevent"). Correctly untested.
- 🏛️ **FUTURE-SPEC** — spec defers the strengthening to v0.2 ("v0.2 planned").
- 🔗 **INHERITED** — defense inherited from a composed external standard (AP2, x402).
- ⚙️ **NON-CONFORMANCE** — not testable by conformance (parameter- / consumer- / implementation- / economics-driven).

## The matrix

| # | Threat (§12.4) | Spec status | Bucket | Test / vector or reason |
|---|---|---|---|---|
| 1 | Forged listing | mitigated | ✅ COVERED | signature-roundtrip + domain-sep-rejection (sig over §B.7 separator) |
| 2 | Identity-bundle replay | mitigated | 🟡 PARTIAL | identity-presentation §6.3.2 (presentation binds the bundle_hash); cross-session nonce replay not directly exercised |
| 3 | Attestation-bundle replay across sessions | mitigated | ✅ COVERED | verify-bundle-v1 "third bundle riding along jobId → fail"; jobId bound into bundle hash |
| 4 | Catalog poisoning | mitigated | ✅ COVERED | verify-bundle-v1-chain (consumer dereferences anchor + recomputes content-hash; mismatch / missing → fail, §7.5.2) |
| 5 | Identity-claim substitution | mitigated | ✅ COVERED | identity-presentation "tampered bundle fails"; verify-bundle "mutated payload → fail" |
| 6 | Method substitution | mitigated | 🕳️ GAP | §7.12 method-field comparison not exercised by a test → candidate vector |
| 7 | Recipe poisoning | mitigated | 🕳️ GAP | signed-recipe + pinned-recipeVersion check not tested (recipe-availability tests cover availability states, not signature/version pinning) |
| 8 | Substrate validator capture (SR-3) | partial — v0.2 planned | 🏛️ FUTURE-SPEC | multi-method strengthening is v0.2; not conformance-testable in v0.1 |
| 9 | Authority-endpoint TLS MITM | partial — v0.2, residual v0.1 | 🏛️ FUTURE-SPEC | validator-body-signed is §7.3.5 v0.2; residual in v0.1 |
| 10 | Negative-match fail-open (truncated sanctions clears a party) | mitigated | 🟡 PARTIAL | vet-gleif-classify "non-binary/absent → indeterminate, never coerced to pass" + 404→fail; PSP-5 completeness-floor on a *truncated list* not directly tested |
| 11 | Verifiable-presentation replay (VC re-presented by non-holder) | mitigated | 🕳️ GAP | §7.3.2 VP holder-binding to session nonce not exercised (we test bundle-presentation binding, not VC/VP) |
| 12 | HTLC preimage-reveal front-running | mitigated (theft)/residual (ordering) | 🟡 PARTIAL | htlc-evidence lock/reveal/refund tested; theft-prevention via beneficiary-binding not isolated; ordering/MEV is ⚖️ residual (chain-level) |
| 13 | Rail availability-field poisoning (read before pin) | mitigated | 🕳️ GAP | §9.4.4 rail-availability pinning not tested (recipe-availability tests are recipe, not rail) |
| 14 | Cross-session offer replay (channelId reuse) | mitigated | 🟡 PARTIAL | secure-channel/sealed-bid exercise channel semantics; CH-6 channelId-per-session uniqueness not isolated as a test |
| 15 | Counterparty-graph reconstruction | accepted by design | ⚖️ RESIDUAL | §12.1 non-goal (public audit trail; no crypto to break; encrypted-anchoring is roadmap) |
| 16 | Vet-attestation disclosure | partial — accepted by design | ⚖️ RESIDUAL | §12.1 relationship/decision accepted by design; §7.5 minimises raw PII (predicate-only) |
| 17 | VerifyResult replay | mitigated | 🕳️ GAP | §7.12 identifier + bundle-hash binding not exercised → candidate vector |
| 18 | TOCTOU authority change | parameter-driven | ⚙️ NON-CONFORMANCE | §7.12 maxAge is a deployment parameter, not a fixed conformance check |
| 19 | Indeterminate exploitation | mitigated | ✅ COVERED | verify-decision-semantics + verify-bundle "tampered → fail, never pass (§7.5.1)" + vet-gleif-classify "non-binary/absent → indeterminate, never coerced to pass" |
| 20 | Channel-operator censorship | mitigated (substrate-dependent) | 🕳️ GAP | §8.12 CH-4 liveness detection not exercised by a test |
| 21 | Channel-operator forking | mitigated | 🕳️ GAP | secure-channel enforces monotonic sequence + replay/reorder rejection RECIPIENT-side, but the §8.12 operator-fork cross-check (detecting a forked view) is not exercised → candidate vector |
| 22 | Offer replay across sessions | mitigated | 🟡 PARTIAL | channelId-in-envelope; see #14 — not isolated |
| 23 | Cross-artifact signature replay | mitigated | ✅ COVERED | signature-roundtrip "cross-context replay: sign with LISTING, verify with AGREEMENT must fail" + domain-sep-rejection (§B.7) |
| 24 | HTLC asymmetric-loss blame ambiguity | partial — DACS-X dispute | 🏛️ FUTURE-SPEC | out-of-band review; DACS-X dispute concern (dispute.ts is prototype/non-normative) |
| 25 | HTLC free-option abandonment | partial — not standardised v0.1 | ⚖️ RESIDUAL | known HTLC property; v0.1 records the pattern, does not standardise a fix |
| 26 | Sealed-envelope front-running | mitigated | ✅ COVERED | sealed-bid "wrong salt FAILs reveal", "mutated bid FAILs", commitment-bound |
| 27 | Sealed-envelope post-deadline submission | mitigated | 🕳️ GAP | §8.4.3 chain-timestamp anchoring not exercised by a test |
| 28 | Agreement-listing mismatch | mitigated | 🕳️ GAP | §8.5.2 commit-agreement validation not exercised → candidate vector |
| 29 | Re-entrancy on EVM rails | implementation-dependent | ⚙️ NON-CONFORMANCE | §9.13 phase-handler ordering is impl-level, not a protocol vector |
| 30 | MEV front-running on payments | parameter-driven | ⚙️ NON-CONFORMANCE | private-mempool is a deployment option |
| 31 | Cross-chain atomicity failure | mitigated for HTLC; SR-5 impl-dependent for tanks | 🟡 PARTIAL | htlc-evidence "timelock-asymmetry rejected at build" + build/verify symmetry cover the HTLC branch; the Liquidity-Tank SR-5 path remains implementation/substrate-dependent (untested) |
| 32 | Liquidity-tank operator compromise | partial — substrate floor | ⚖️ RESIDUAL | substrate-trust floor (2/3 BFT + 15-day recovery); tank-lock/refund evidence tested but operator trust is substrate-level |
| 33 | AP2 mandate replay | inherited from AP2 | 🔗 INHERITED | AP2 nonce/expiry — external standard's mechanism |
| 34 | x402 receipt forgery | inherited from x402 | 🔗 INHERITED | x402 signature verification — the mechanism belongs to the x402 standard, exercised via its settle path |
| 35 | Refund laundering | mitigated | ✅ COVERED | htlc-evidence "mutual exclusion: settled + refund txRef → FAIL" + tank-refund-evidence "refund path → PASS" (anchored amendments) |
| 36 | Decimal-overflow on cross-decimal pay | mitigated | ✅ COVERED | canonicalization "§7.2 JSON number above 2^53-1 is rejected" + htlc-evidence "canonical price" + settlement-evidence-verifier (negative/zero amount → FAIL) |
| 37 | Bundle forgery | mitigated | ✅ COVERED | verify-bundle-v1 "missing required signer → fail", "non-abort needs buyer+seller signed" |
| 38 | Bundle suppression | mitigated | ✅ COVERED | verify-two-sided + chain "unilateral (only buyer anchor) → fail, aborted-by-self for seller" |
| 39 | Sybil reputation farming | mitigated cross-tier; not same-tier | 🕳️ GAP | per-primary-claim keying / reputation derivation not exercised by a test |
| 40 | Reputation collusion | partial — protocol cannot prevent | ⚖️ RESIDUAL | protocol-unpreventable (volume disclosure + external signals only) |
| 41 | Orchestrator error-class misclassification | mitigated | 🟡 PARTIAL | verify-two-sided divergence (party-disagreement → contradiction → fail); error-class re-derivation not isolated |
| 42 | Bundle anchor unavailability | mitigated (substrate-dependent) | 🟡 PARTIAL | verify-bundle-v1 "anchor missing → fail / RPC error → indeterminate"; on-substrate availability is substrate-level |
| 43 | Stale reputation windows | consumer-driven | ⚙️ NON-CONFORMANCE | explicit window bounds are a consumer choice |
| 44 | ERC-8004 write spamming | mitigated | ⚙️ NON-CONFORMANCE | the defense is gas cost (economic) + a per-session rate limit that is a deployment policy, not a fixed protocol rule with a verifiable assertion |
| 45 | RFQ session-initiation flooding | partial | ⚙️ NON-CONFORMANCE | v0.1 has NO mandatory rule (bounds a session via maxTurns/timeoutSec, not the initiation rate) → nothing normative to test, not an accepted-by-design risk |
| 46 | Sealed-envelope commit-spam | partial | ⚙️ NON-CONFORMANCE | v0.1 does not standardise bidder stake / eligibility — mitigations are optional, so there is no normative rule to conformance-test (candidate for future standardisation) |

## Coverage summary
- ✅ COVERED: 11 · 🟡 PARTIAL: 8 · 🕳️ GAP: 10 · ⚖️ RESIDUAL: 5 · 🏛️ FUTURE-SPEC: 3 · 🔗 INHERITED: 2 · ⚙️ NON-CONFORMANCE: 7 (= 46)
- **Conformance-addressable today** (COVERED + PARTIAL + GAP) = 29 rows; of those, **11 fully covered, 18 with work to do.**
- The other 17 are honestly *not* a v0.1 conformance question (5 accepted-by-design, 3 v0.2/future-spec, 2 inherited from composed standards, 7 environment / economics / deployment-policy).
- _(Counts independently verified against the table by an adversarial reviewer, 2026-06-19.)_

## GAP rows = the candidate next conformance vectors (prioritised)
High-value, buildable now, ordered by security weight (identity/auth-replay first):
1. **#28 Agreement-listing mismatch** (§8.5.2) — a forged agreement against a different listing; core integrity.
2. **#11 Verifiable-presentation replay** (§7.3.2) — a non-holder re-presenting a VP; direct identity/auth replay.
3. **#17 VerifyResult replay** (§7.12) — identifier + bundle-hash binding.
4. **#6 Method substitution** (§7.12) — verifier asserts a different method than run.
5. **#7 Recipe poisoning** (§7.12) — pinned recipeVersion + signed-recipe check.
6. **#13 Rail availability-field poisoning** (§9.4.4) — extends our existing dacs-drift.
7. **#27 Sealed-envelope post-deadline** (§8.4.3) — chain-timestamp anchoring.
8. **#20/#21 Channel-operator censorship/forking** (§8.12 CH-4 / monotonic) — SR-4 trust-property tests.
9. **#39 Sybil reputation farming** — per-primary-claim keying.

## Honest scope
- Buckets reflect the spec's OWN status language; this is a coverage map of *pathos-dacs-ref* tests, not a claim about other impls. A 🕳️ GAP means "we have no test," not "the defense is broken."
- "Mitigated" in the spec ≠ "tested here." 8 spec-"mitigated" rows are PARTIAL/GAP for us — exactly what a conformance contributor should surface.
- RESIDUAL rows are the spec's *deliberate* non-goals; marking them prevents anyone reading "DACS = secure against everything."
