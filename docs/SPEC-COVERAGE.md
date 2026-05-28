# DACS spec coverage — `pathos-dacs-ref` v0.1

This document maps each in-scope DACS section to the file(s) that implement it.

## Conventions

- **✅** = implemented + tested against spec test vectors
- **🚧** = stubbed (interface present, body not yet conformant)
- **❌** = out of scope for this version
- **§N.M** = section number in DACS v0.7 + DACS-1..5 v0.1

## DACS-1 Identify

| Spec section | Coverage | File | State |
|---|---|---|---|
| §6.3.1 Identity-claim reference grammar | TS type + parser | `src/types/identity.ts` | 🚧 |
| §6.3.2 IdentityBundle schema + 3 presentation kinds | TS type | `src/types/identity.ts` | 🚧 |
| §6.3.3 BundleRequirement matching algorithm | function | `src/lib/bundle-match.ts` | 🚧 |
| §6.3.4 Listing document (16 KB cap, JCS, monotonically versioned, SR-2 anchored) | TS type + publisher | `src/types/listing.ts`, `src/cli/listing-pub.ts` | 🚧 |
| §6.3.5 `.well-known/agent.json` `dacs` block | TS type only | `src/types/wellknown.ts` | 🚧 |
| §6.3.6 Off-chain catalog API | ❌ | — | out of scope v0.1 |

## DACS-2 Vet

| Spec section | Coverage | File | State |
|---|---|---|---|
| §7.3.5 `consensus-backed-proxy` method (GLEIF only) | recipe runner | `src/recipes/consensus-backed-proxy-gleif.ts` | 🚧 |
| §7.3.7 `evm-rpc` method | recipe runner | `src/recipes/evm-rpc.ts` | 🚧 |
| §7.5.1 VerifyResult outcomes (pass/fail/indeterminate) — **NEVER coerce** | TS enum + invariant | `src/types/verify-result.ts` | 🚧 |
| §7.7 CompositeVerificationRecord aggregation | function | `src/lib/composite-verify.ts` | 🚧 |
| §7.3.1–7.3.4, 7.3.6, 7.3.8 (5 other methods) | ❌ | — | out of scope v0.1 |
| §7.4.4 Recipe-track governance | ❌ | — | out of scope v0.1 |

## DACS-3 Negotiate

**Entire stage out of scope v0.1.** Rationale: §5 of the spec is honest that SR-4 (channel-protocol) is *"trust-property specified only in v1"* and that wire-protocol harmonisation is v2 work. KyneSys (RandomBlock) pre-flagged L2PS gaps and institutional CCI credentials as moving. Building a ref-impl against a moving target costs both sides.

## DACS-4 Settle

**Entire stage out of scope v0.1.** Same rationale as DACS-3. Cross-chain HTLC (§9.5.4) is the closest to settled, but introducing the HTLC harness pulls in a Solana Anchor program + Base EVM contract that doubles the surface for a v0.1 ref-impl.

## DACS-5 Verify

| Spec section | Coverage | File | State |
|---|---|---|---|
| §10.3.1 SessionRecord state machine | TS type + states | `src/types/session.ts` | 🚧 |
| §10.4.1 Bundle consumer MUST recompute + verify | **verifier CLI** | `src/cli/verify.ts` | 🚧 **load-bearing** |
| §10.4.2 AttestationBundle two-sided anchoring at `stor-{sha256(jobId+"-bundle-"+role)}` | TS type + anchor calc | `src/types/bundle.ts` | 🚧 |
| §10.4.3 Consumer queries both party-specific addresses; unilateral ⇒ `aborted-by-self` | verifier logic | `src/cli/verify.ts` | 🚧 |
| §10.5.1 Reputation derivation (per-primary-claim, failed-substrate excluded) | function | `src/lib/reputation.ts` | 🚧 |
| §10.7 ERC-8004 publication surface | ❌ | — | out of scope v0.1 (optional in spec too) |
| Domain separator `"dacs5-bundle:v1:"` | constant | `src/domain-sep.ts` | 🚧 |

## Universal infrastructure

| Spec section | Coverage | File | State |
|---|---|---|---|
| RFC 8785 JCS (JSON Canonicalization Scheme) | function | `src/jcs.ts` | 🚧 (uses `canonicalize` npm pkg) |
| All 17 domain separators (§7.7 inventory) | constants | `src/domain-sep.ts` | 🚧 |
| ed25519 signing with domain-separated prefix | function | `src/lib/sign.ts` | 🚧 (uses `@noble/ed25519`) |
| Test vectors per §14.6 | skeletons | `test/vectors/*.test.ts` | 🚧 |
