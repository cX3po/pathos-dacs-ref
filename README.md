# pathos-dacs-ref

PATH-OS reference implementation of **DACS** — Demos Agent Commerce Standards (paper v0.7, per-stage standards DACS-1..5 v0.1).

## What this is

An independent, third-party reference implementation built against the DACS specification published by KyneSys Labs. Its primary purpose is to **demonstrate that an outside implementer can compose DACS primitives end-to-end against a public substrate, and to provide a public envelope-receipt verifier CLI that DACS v0.7 §11.3 explicitly acknowledges as remaining work**.

## What this is NOT

- Not a full coverage of all five DACS stages — see [docs/SPEC-COVERAGE.md](docs/SPEC-COVERAGE.md) for what's in scope.
- Not a production-graded library — v0.x; APIs will change.
- Not a re-implementation of the Demos SDK — composes on top of `@kynesyslabs/demosdk@^4.0.0`.

## Scope (v0.1)

| DACS stage | Coverage | Status |
|---|---|---|
| DACS-1 Identify | Listing publisher conformant to §6.3.4 | scaffolded |
| DACS-2 Vet | `evm-rpc` (§7.3.7) + `consensus-backed-proxy` GLEIF (§7.3.5) | scaffolded |
| DACS-3 Negotiate | — | **out of scope v0.x** (SR-4 wire protocol is v2 spec work) |
| DACS-4 Settle | — | **out of scope v0.x** (SR-3 wire protocol is v2 spec work) |
| DACS-5 Verify | Envelope-receipt verifier CLI per §10.4.1 | scaffolded |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the three CLIs compose.

## CLIs

```bash
# DACS-1 — publish a marketplace listing
npm run listing-pub -- --listing-file ./my-listing.json --mnemonic-env DEMOS_MNEMONIC

# DACS-2 — vet a counterparty's GLEIF LEI claim
npm run vet-gleif -- --lei 984500ABCDEF1234567890 --jobId <uuid>

# DACS-5 — verify a bundle (the load-bearing artifact)
npm run verify -- --bundle-anchor stor-<hash> --or-file ./bundle.json
```

All three CLIs return structured JSON to stdout + non-zero exit on failure.
Per DACS §7.5.1: outcomes are `pass | fail | indeterminate` — never coerced.

## Status

| Component | State |
|---|---|
| Repo scaffold | ✅ done |
| TypeScript types from DACS spec | ✅ stub |
| JCS canonicalization | 🚧 stub |
| 17 domain separators (§7.7) | 🚧 stub |
| ed25519 signing with domain separation | 🚧 stub |
| Verifier CLI logic | 🚧 stub |
| Listing publisher logic | 🚧 stub |
| GLEIF recipe runner | 🚧 stub |
| Test vectors (§14.6) | 🚧 skeleton |
| End-to-end demo (CSV-class) | ⏳ planned |

## Spec source of truth

DACS v0.7 + DACS-1..5 v0.1. We pin spec section references in code comments throughout. If a code comment cites `§N.M`, that is the section number in the DACS spec we are conforming to.

## Origin

This implementation was scaffolded 2026-05-28 by PATH-OS at the explicit invitation of KyneSys Labs (RandomBlock), who asked us to review the DACS spec and build a reference implementation as an independent test of its third-party implementability. The audit that preceded this build identified the lack of a public verifier as a v1 conformance gap; this implementation closes that gap from outside the KyneSys org.

See `memory/reports/demos-recognition-contribution-spec-2026-05-22.md` (PATH-OS internal) and the audit memo + agent JSON delivered 2026-05-28 for context.
