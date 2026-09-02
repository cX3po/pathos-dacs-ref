# pathos-dacs-ref

> Independent, third-party reference implementation of **DACS** — Demos Agent Commerce Standards (paper v0.7, per-stage standards DACS-1..5 v0.1).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What this is

A working implementation of a defined subset of DACS, built so the protocol's
third-party implementability claim has something concrete behind it.

- **DACS-1** listing publisher (§6.3.4) — JCS canonical, 16 KB size cap, SR-2 anchored, ed25519 signed
- **DACS-2** vet — `consensus-backed-proxy` recipe against GLEIF (§7.3.5)
- **DACS-5** envelope-receipt verifier CLI — the **load-bearing artifact** of v0.x; closes the v0.7 §11.3 acknowledged gap
- Universal signature scheme (§7.7) — closed registry of 17 domain separators with cross-context replay protection

Status: **77 tests / 72 pass / 5 skipped** (integration tests gated by env vars). Default `npm test` is fully offline-safe. TypeScript strict-mode clean.

## Status at a glance

| Component | State |
|---|---|
| Repo scaffold | ✅ shipped (Codex APPROVED-WITH-NOTES) |
| M1 Demos SDK wiring (SR-2 + DAHR honest stub) | ✅ shipped (6 review rounds) |
| M2 DACS-5 verifier full implementation | ✅ shipped (8 review rounds) |
| M3 GitHub + CI + external-ready docs | ✅ shipped (this commit) |
| v0.3 — true validator-quorum DAHR + DACS-3 channel | ⏳ roadmap (gated on DACS v2 wire protocol) |

## Try it in two minutes

```bash
git clone <this-repo>
cd pathos-dacs-ref
npm ci
npm test                            # 72 pass + 5 skipped; ~3s
SKIP_GLEIF=1 npx tsx examples/csv-class/run.mts   # full DACS-1+2+5 loop offline
```

Verify a real DACS-5 bundle (offline, file-based):

```bash
npx tsx src/cli/verify.ts --bundle-file path/to/bundle.json --offline --json
# Exit codes: 0 pass, 1 fail, 2 indeterminate, 3 usage error
```

Vet a live LEI against GLEIF (DAHR-stub mode — no DEM consumed):

```bash
npx tsx src/cli/vet-gleif.ts --lei HWUPKR0MPOU8FGXBT394 --jobId my-job-001 --dry-run
# Returns a §7.5.1 VerifyResult with decision=pass for Apple Inc's LEI
```

## Scope

Per [`docs/SPEC-COVERAGE.md`](docs/SPEC-COVERAGE.md):

| DACS stage | Coverage | Rationale |
|---|---|---|
| DACS-1 Identify | ✅ Listing publisher + IdentityBundle types | core to receipt loop |
| DACS-2 Vet | ✅ `evm-rpc` (§7.3.7) + `consensus-backed-proxy` GLEIF only (§7.3.5) | scope-disciplined: extend per recipe |
| DACS-3 Negotiate | ❌ out of scope v0.x | DACS v1 §5: SR-4 wire protocol is v2 work |
| DACS-4 Settle | ❌ out of scope v0.x | DACS v1 §5: SR-3 wire protocol is v2 work |
| DACS-5 Verify | ✅ Full §10.4 walk + CLI | the moat artifact |

### What this proves about DACS

The closed registries (17 domain separators in §7.7, 8 verification methods in §7.4, 6 negotiation patterns), the `pass / fail / indeterminate` invariant in §7.5.1, the two-sided anchoring in §10.4.2, the `failed-substrate` exclusion from party-fault denominators in §10.5.1 — all compose cleanly into a working implementation by a third party that did not author the spec. That's the empirical proof DACS v0.7 §11.3 line 1179 asks for: a second independent reference implementation against a non-Demos substrate is the next step beyond this; we're the first independent-from-KyneSys one.

### What we lean on the spec being honest about

The DACS v0.7 spec is unusual in how clearly it names its own gaps:

- §5 — SR-3 + SR-4 are trust-property specified only in v1; wire harmonisation is v2
- §11.3 — public envelope-receipt verifier CLI is acknowledged remaining work
- §6.1 — production-mapping legend (🟢🟡🔵) is informative, not normative

We close §11.3's gap (the verifier CLI is this repo's `src/cli/verify.ts`). We propose closing §6.1's gap via a PR that promotes the legend to a normative `recipe.availability` field — see [`docs/SPEC-COVERAGE.md`](docs/SPEC-COVERAGE.md) and the audit memo in our prior outside-tester pass for the rationale.

## Architecture

### Agent identities (CCI)

[`src/adapters/demos/identity.ts`](src/adapters/demos/identity.ts) is the only module allowed to import `@kynesyslabs/demosdk/identity`; all other code uses its typed adapter surface. Start from [`config/dacs-agents.example.json`](config/dacs-agents.example.json) and keep the local `config/dacs-agents.json` gitignored. Agent credentials are read only from the named environment variables. The adapter accepts testnet configuration only; use faucet DEM only. Identities conform to the SDK's own CCI claim representation (`demos:<address>` claim references, signed and verified through the SDK's primary-claim functions); this repo defines no identity format of its own. The only addition is the `dacs-x-agent-identity:v1:` SIG-4 *extension* separator for adapter payloads. The config file is an example local-agent layout, not a schema anyone else needs to adopt.

Inspect configured identities without revealing credentials with `npm run dacs-agents -- check` (or add `--config path`). If the local config is absent, the command prints a notice and checks the example config. Derive a claim reference with `npm run dacs-agents -- claim <address>`.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Short version:

```
DACS-1 listing (signed, JCS, SR-2 anchored)
        ↓
DACS-2 vet via DAHR (consensus-backed-proxy GLEIF)
        ↓
DACS-5 AttestationBundle (cosigned, two-sided anchored at stor-{sha256(jobId+role)})
        ↓
verify CLI walks §10.4.1 → recompute hash → verify both signatures → walk every
AttestationRef.contentHash → cross-check counterparty bundle → emit verdict
```

The verifier CLI is what makes DACS receipts non-vacuous from outside the KyneSys org: anyone can run `pathos-dacs-verify --bundle-anchor stor-...` against any Demos chain and reach the same pass/fail/indeterminate verdict the original parties' agents reach.

## §7.5.1 invariant

The single most important rule in this codebase:

> `decision ∈ {pass, fail, indeterminate}` — `indeterminate` MUST NOT be coerced to `pass`. Implementations MUST NOT silently coerce ambiguous outcomes to pass.

Distinct exit codes are how this invariant survives at the OS layer:

| Exit | Meaning | When |
|---:|---|---|
| 0 | pass | All signatures verified + all attestations content-matched + no `dahr-stub:` prefix in any walked attestation |
| 1 | fail | At least one signature failed verification, OR a content-hash mismatch, OR a forged stub locator, OR a cross-party identifier mismatch |
| 2 | indeterminate | Verifier could not reach a definitive verdict (RPC unreachable, key unresolvable, non-cci scheme, dahr-stub attestation present, etc.) |
| 3 | usage error | Bad CLI args / missing required flags |

The honest-scope marker on DAHR attestations (`dahr-stub:` prefix in `attestation.type`) is how the verifier knows to refuse `pass` on a bundle whose attestations don't yet carry a validator-quorum signature. Until v0.3 ships true `consensus-backed-proxy` DAHR, the cleanest end-state for v0.2 bundles is `indeterminate` — which is the right answer, not a polish gap.

## Roadmap

| Version | Adds | Gated on |
|---|---|---|
| v0.2 *(current)* | M1 + M2 + M3 — SDK wiring, full DACS-5 verifier, external-ready docs | shipped |
| v0.3 | Real validator-quorum DAHR (validator signs + anchors response hash); additional DACS-2 recipes (ECB, FedRAMP, SAM, FINRA, OFAC); ERC-8004 primary-claim resolution; HTLC test-vectors | KyneSys docs / API surfacing the validator-side DAHR endpoint |
| v0.4+ | DACS-3 channel layer (negotiate-fixed-price, sealed-envelope); DACS-4 settle (x402, HTLC); TLSN closed-data recipes | DACS v2 spec ships SR-3 + SR-4 wire protocols |

## Posture

This is a third-party reference impl. Where DACS is ambiguous, we surface the ambiguity in code comments next to the spec §, pick the interpretation we believe is intended, and file the gap for KyneSys review. We do **not** extend the spec.

If a reviewer wants to push on a design decision, the section reference is the cite-back point — open an issue with the spec §, the file path, and the alternate interpretation. We'll close on whichever reading is more conformant.

## Origin

Scaffolded 2026-05-28 at the explicit invitation of the KyneSys Labs team, who asked PATH-OS to review the DACS spec and build a reference implementation as an independent test of its third-party implementability. The audit that preceded this build identified the lack of a public verifier as a v1 conformance gap (FIND-008); this implementation closes that gap from outside the KyneSys org.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for review style + how to file issues.

## License

MIT — see [`LICENSE`](LICENSE).
