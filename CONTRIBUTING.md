# Contributing to pathos-dacs-ref

Thank you for considering a contribution. This is an independent reference
implementation of DACS — Demos Agent Commerce Standards — and is built in the
open so that the protocol's third-party implementability claim has something
concrete behind it.

## What this repo IS

A working v0.x reference implementation of a defined subset of DACS:

- **DACS-1** listing publisher (§6.3.4 schema, JCS canonicalization, SR-2 anchor)
- **DACS-2** `evm-rpc` + `consensus-backed-proxy` (GLEIF only) recipes
- **DACS-5** envelope-receipt verifier CLI (§10.4 walk)
- Universal signature scheme (§7.7) — closed registry of 17 domain separators

See [`docs/SPEC-COVERAGE.md`](docs/SPEC-COVERAGE.md) for the complete in-scope
section list.

## What this repo is NOT

- The Demos Network itself (that's [kynesyslabs/node](https://github.com/kynesyslabs/node))
- The DACS specification (that's published by KyneSys; we *implement* it)
- A production-grade library (v0.x; APIs will change)
- A full coverage of all five DACS stages — DACS-3 and DACS-4 are deliberately
  out of scope until SR-3/SR-4 wire protocols land in DACS v2

## Filing issues

Issue templates live in `.github/ISSUE_TEMPLATE/`. Two main shapes:

- **Bug** — something fails to conform to a spec section, or a CLI exits with
  the wrong code, or a test vector breaks. Please cite the spec § + the file
  path + a minimal reproduction.
- **Spec-coverage gap** — a §N.M case you'd like to see covered. Please cite
  the spec text and propose what "passing" would look like.

## Pull requests

Before opening a PR:

1. **Read the spec section you're touching.** Code comments should cite §N.M
   anchors so reviewers can match implementation to spec on sight.
2. **`npm test` must pass offline.** No live-network / chain-write dependencies
   in the default test run. Network tests gate on `DACS_LIVE_NETWORK=1`; chain
   writes additionally gate on `DEMOS_MNEMONIC`.
3. **TypeScript strict mode.** `npx tsc --noEmit` must produce zero errors.
4. **Test what you change.** New code paths get unit tests in `test/vectors/`.
   Network-dependent tests live in `test/integration/`.
5. **No new dependencies without a one-line justification.** If a dep is added,
   note in the PR why it's worth the bundle weight.

## The §7.5.1 invariant

The single most important invariant in this codebase:

> `decision ∈ {pass, fail, indeterminate}` — `indeterminate` MUST NOT be
> coerced to `pass`. Implementations MUST NOT silently coerce ambiguous
> outcomes to pass.

Any code that compares a `VerifyDecision` to a boolean, or that defaults an
unhandled error to `pass`, will be rejected. Use the `isPass`/`isFail`/
`isIndeterminate` helpers from `src/types/verify-result.ts` to make the
invariant explicit at the call site.

## Review style

PRs against this repo are reviewed against the same Codex peer-review discipline
used to ship M1 and M2 (~14 review rounds across the two modules combined). The
reviewer will name spec sections, propose concrete fixes, and refuse merges that
collapse the §7.5.1 invariant or silently degrade an attestation's honest-scope
marker (`dahr-stub:` prefix).

If a finding feels load-bearing, file it as a code comment with `// Codex
review #N` or `// finding:` so future readers can match decisions to their
origin.

## Spec contributions

If you spot a normative gap in DACS v0.x itself (not in our implementation),
file it at [kynesyslabs/documentation-mintlify](https://github.com/kynesyslabs)
or contact the KyneSys Labs team via the channels listed at
[docs.kynesys.xyz](https://docs.kynesys.xyz). We try to surface gaps *here* (in
code comments + the SPEC-COVERAGE doc) but the spec edits live with KyneSys.
