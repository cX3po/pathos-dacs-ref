# DACS spec coverage — `pathos-dacs-ref` v0.2

This document maps each in-scope DACS section to the file(s) that implement it.

## Conventions

- **✅** = implemented + tested (77 tests / 72 pass / 5 skipped as of M3)
- **🚧** = partial / stub with documented upgrade path
- **❌** = out of scope for this version
- **§N.M** = section number in DACS v0.7 + DACS-1..5 v0.1

## DACS-1 Identify

| Spec section | Coverage | File | State |
|---|---|---|---|
| §6.3.1 Identity-claim reference grammar | TS type | `src/types/identity.ts` | ✅ |
| §6.3.2 IdentityBundle schema + 3 presentation kinds | TS type | `src/types/identity.ts` | ✅ types; SIWD presentation kind exercised |
| §6.3.3 BundleRequirement matching algorithm | function | `src/lib/bundle-match.ts` | ❌ v0.3 (deferred — first consumer is buyer-agent in DACS-3 negotiate, which is out of scope) |
| §6.3.4 Listing logical/native split | CF-4 addressing + publisher CLI | `src/dacs1/addressing.ts`, `src/types/listing.ts`, `src/cli/listing-pub.ts` | ✅ go-forward `logical_address` metadata; opaque colon-free Demos write input; native locator is discovery-only |
| §6.3.5 `.well-known/agent.json` `dacs` block + listing index | generator + LR resolver | `src/dacs1/discovery.ts`, `src/cli/discovery-gen.ts` | ✅ exact-byte `indexHash`; logical→native binding; immutable legacy-record disclosure |
| §6.3.6 Off-chain catalog API artifacts | generator | `src/dacs1/discovery.ts`, `discovery/api/dacs/` | ✅ logical/native binding via host-ready collection/detail + ListingSummary; seller/reputation endpoint deferred outside this addressing-only slice; HTTP hosting remains deployment work |

## DACS-2 Vet

| Spec section | Coverage | File | State |
|---|---|---|---|
| §7.3.5 `consensus-backed-proxy` method (GLEIF only) | recipe runner | `src/cli/vet-gleif.ts`, `src/demos/dahr.ts` | ✅ as v0.2 honest stub (single-fetch + SR-2 anchor; `dahr-stub:` prefix marker; validator-quorum signing is v0.3 once KyneSys exposes the validator-side DAHR endpoint) |
| §7.3.7 `evm-rpc` method | type only | `src/types/verify-result.ts` (AttestationRef) | 🚧 stub; AttestationRef shape compatible |
| §7.5.1 VerifyResult outcomes (pass/fail/indeterminate) — **NEVER coerce** | TS enum + verifier invariant | `src/types/verify-result.ts`, `src/lib/verify-bundle.ts` | ✅ enforced at type + runtime; 4 regression tests; distinct exit codes 0/1/2 |
| §7.5.2 AttestationRef contentHash recomputation | function | `src/lib/verify-bundle.ts` (walkAttestationRefs) | ✅ fetch + sha256 + compare; mismatch → fail; stub locators verify prefix |
| §7.7 CompositeVerificationRecord aggregation | function | `src/lib/verify-bundle.ts` (StepLog.rollupDecision) | ✅ §7.7.1 precedence — fail > indeterminate > pass; never collapses |
| §B.7 Universal signature scheme — domain separators (23-entry closed registry) | constants + sign/verify | `src/domain-sep.ts`, `src/lib/sign.ts` | ✅ closed registry asserted; cross-context replay protection tested |
| §7.3.1–7.3.4, 7.3.6, 7.3.8 (5 other methods) | — | — | ❌ v0.3 (compose same way as evm-rpc + cbp-gleif) |
| §7.4.4 Recipe-track governance | — | — | ❌ v0.3 |

## DACS-3 Negotiate

**Entire stage out of scope v0.2.** Rationale: §5 of the spec is honest that SR-4 (channel-protocol) is *"trust-property specified only in v1"* and that wire-protocol harmonisation is v2 work. The KyneSys Labs team pre-flagged L2PS gaps and institutional CCI credentials as moving (2026-05-28). Building a ref-impl against a moving target costs both sides.

## DACS-4 Settle

**Entire stage out of scope v0.2.** Same rationale as DACS-3. Cross-chain HTLC (§9.5.4) is the closest to settled, but introducing the HTLC harness pulls in a Solana Anchor program + Base EVM contract that doubles the surface for a v0.2 ref-impl.

## DACS-5 Verify

| Spec section | Coverage | File | State |
|---|---|---|---|
| §10.3.1 SessionRecord state machine | TS type + 14 states | `src/types/bundle.ts` | ✅ types |
| §10.4.1 Bundle consumer MUST recompute + verify | **verifier CLI** | `src/cli/verify.ts`, `src/lib/verify-bundle.ts` | ✅ **load-bearing — closes §11.3 gap** |
| §10.4.2 AttestationBundle two-sided anchoring at `stor-{sha256(jobId+"-bundle-"+role)}` | TS type + anchor calc + verifier | `src/types/bundle.ts`, `src/lib/verify-bundle.ts` (computeAnchorPair + verifyTwoSidedAnchoring) | ✅ deterministic + full canonical-bytes binding + signature re-verify on both anchors |
| §10.4.3 Consumer queries both party-specific addresses; unilateral ⇒ `aborted-by-self` | verifier logic | `src/lib/verify-bundle.ts` (verifyTwoSidedAnchoring) | ✅ distinguishes RPC error from absence |
| §10.5.1 Reputation derivation (per-primary-claim, failed-substrate excluded) | — | — | ❌ v0.3 |
| §10.7 ERC-8004 publication surface | — | — | ❌ v0.3 (optional in spec) |
| Domain separator `"dacs5-bundle:v1:"` | constant | `src/domain-sep.ts` | ✅ |

## Universal infrastructure

| Spec section | Coverage | File | State |
|---|---|---|---|
| RFC 8785 JCS (JSON Canonicalization Scheme) | function | `src/jcs.ts` | ✅ via `canonicalize` npm pkg; 5 round-trip tests |
| All §B.7 domain separators (23-entry closed-registry inventory) | constants | `src/domain-sep.ts` | ✅ closed registry + assertion + 5 closure tests |
| ed25519 signing with domain-separated prefix | function | `src/lib/sign.ts` | ✅ via `@noble/ed25519`; 4 sign/verify round-trip tests |
| Test vectors per §14.6 | implemented | `test/vectors/*.test.ts` (7 files, 72 passing tests) | ✅ |

## Proposed spec contribution (pre-v1 freeze)

Per the audit memo PATH-OS delivered 2026-05-28 to the KyneSys Labs team (FIND-003 finding):

> §6.1 production-mapping legend (🟢 in production / 🟡 v1-pending / 🔵 third-party) is **informative front-matter today**. We'd propose promoting it to a **normative `recipe.availability` field** on every `Recipe` and `RailDefinition`, with the values `live | operator_gated | closed_data | bilateral | mocked | disabled | failed`. This closes the FIND-003 framing exposure ("Wired" flattens 4 operational states into 1) at the protocol layer rather than at every implementer's UI.

If KyneSys accepts the proposal, this repo will be updated to match the normative shape in the same release.
