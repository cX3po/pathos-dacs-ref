# BundleBinding differential property fuzzer

`bb-differential-fuzzer.mts` — a property-based / metamorphic fuzzer for DACS-5 §10.4.2
BundleBinding resolution (BB-1..BB-8), targeting the round-9/10/11 defect classes on PR #248.

## Why this exists

PR #248 has churned for 11 review rounds. Every defect since round 7 lives in the BB-6
candidate-multiplicity ladder or in malformed-input handling. The recurring failure mode is
that tests assert **fixture metadata** (a pinned expected verdict) rather than **executing the
predicate** against a reference implementation, so semantic bugs pass CI silently. xm33's point:

> "a suite is authority over the paths it exercises and silent about the rest."

Fixed vectors only lock the corners someone thought of. This fuzzer generates randomised,
structurally-rich BB scenarios and asserts **invariants that must hold for any input** — no
pinned metadata, no hand-picked corners.

## Run

```bash
npm run fuzz:bb-binding                                        # 1000 cases, fixed seed 20260701
tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts --cases 20000 --seed 42
tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts --case-seed 575977194   # replay one case
```

Exit code is non-zero iff an invariant violation was found (CI-gateable). On failure it prints,
per invariant, a `--case-seed` replay command and the minimal reproducing input.

The tool starts with a **self-test**: it hand-builds a valid, fully-signed scenario and asserts
the resolver returns `present`. If signing/oracle wiring is broken the whole fuzz would be
vacuous (every "valid" case silently collapsing to non-present), so the self-test aborts loudly
rather than reporting a meaningless green.

## Invariants asserted

Universal (every case):
- **no-throw** — the resolver never throws on any input; it always returns a deterministic
  disposition (`present` / `fail` / `indeterminate`). *(round-11 "21 exception escapes" class)*
- **determinism** — same input → identical resolution across runs.
- **permutation-invariance** — reordering the `bindings` array never changes the disposition, and
  never changes the winner when `present`. *(catches order-dependent tie-breaks / non-determinism)*
- **fail-closed** — an input with no genuinely valid, authorized, byte-exact copy is never
  `present`.

Constructive / ground-truth (scenario-specific, built with real Ed25519 signatures so the
`present`-yielding paths are actually exercised):
- **full-signature precedence** — a co-signed (fully-signed) copy is never overridden by a
  single-signed divergent copy; the fully-signed copy wins.
- **equal-standing divergence** — two fully-signed, authorized, byte-divergent copies at equal
  standing → `indeterminate` (void), never an arbitrary pick.
- **budget exhaustion** — exceeding the per-signer fetch budget N → `indeterminate`, never silent
  truncation to some winner.
- **BB-5 reject-on-any** — an authenticated binding whose tuple does not match the requested side
  → the whole resolution is `fail`.

Scenario generators (weighted): `valid-present`, `full-sig-precedence`,
`equal-standing-divergence`, `budget-exhaustion`, `outsider-sybil-flood`, `bb5-reject-on-any`,
`malformed-ingress` (weighted up), `corrupt-valid`, `pure-garbage`.

## Findings (2026-07)

Run against `src/lib/bundle-binding-v1.ts`, the fuzzer found **two exception-escape defects** of
the round-11 class — both were **fixed** (fail-closed hardening) and the fixes verified clean
across 25k+ cases over 5 seeds. It found **zero** semantic violations (determinism,
permutation-invariance, fail-closed, precedence, divergence, budget, BB-5 all held).

1. **Non-array `bindings` throws** (`bindings.filter is not a function`).
   The resolver defensively validated the `request` shape (BB-1) but not the `bindings` argument.
   Malformed wire input (`"bindings": false`) threw instead of fail-closing.
   **Fix:** symmetric BB-1 guard — `if (!Array.isArray(bindings)) return invalid('BB-1: malformed binding set')`.
   Strict-JSON-reachable; the higher-severity of the two.

2. **Non-finite number in a signed tuple / fetched bundle throws** (`JCS: JSON number NaN is
   outside the IEEE-754 safe-integer range (§7.2)`). The resolver canonicalises untrusted input
   (`hashCanonical` in `bindingSignatureValid`; `bundleScope` on fetched bundles). A `NaN`/`Infinity`
   in a numeric field made JCS throw and the exception escaped.
   **Fix:** wrap both canonicalisation call sites; a tuple/bundle that cannot be canonicalised is
   treated as **invalid / present-but-invalid** (fail-closed), never a thrown exception.
   Note on severity: `NaN`/`Infinity` are **not** RFC-8259-reachable via `JSON.parse`, so this is
   lower-severity than (1) — but lenient parsers and upstream numeric computation can produce them,
   and a resolver hashing untrusted input should fail-closed regardless of provenance.

Both fixes are consistent with the resolver's existing fail-closed vocabulary and did not change
any `present`/`indeterminate`/`fail` verdict on the published round-8 vectors (existing cross-run
still 36/36 AGREE; `npm test` 428 pass / 0 fail).

> These are core-resolver changes to an implementation under active standardization review.
> They should go through the operator's Codex + Claude peer-review gate before shipping to the
> #248 PR.

## Scope: what is and isn't a true second-oracle differential

The task's ideal is a **true second-oracle differential**: run every generated input through our
resolver AND the DACS-Standard reference implementation, and assert *agree-or-both-fail-closed*.

As of this build, the DACS-Standard repo ships **no executable BB-1..BB-8 resolver** — only
schema/structural vector **validators** (`scripts/validate_conformance_vectors.py`), i.e. the very
"assert fixture metadata" anti-pattern this exercise exists to escape. There is nothing to run
differentially. So this deliverable is the **invariant / metamorphic** property fuzzer, and the
second-oracle mode is **deferred, not faked**.

The invariants here are still differential in spirit: several are **metamorphic** — they compare
the resolver against *itself* under transformations that must not change the verdict (determinism,
permutation-invariance, monotonicity), which is exactly where non-deterministic tie-breaks and
order dependence hide.

### Follow-up to wire the true second-oracle mode
1. Obtain a runnable reference resolver (the #270 promotion-batch adapter, or a reference impl that
   speaks the `dacs-adapter/1` JSONL subprocess protocol — see
   `conformance/shared-suite/ADAPTER-PROTOCOL.md`).
2. Serialise each generated scenario to the adapter's request shape, run it through the reference
   subprocess, and add a `differential-agreement` invariant: `ours.disposition === theirs.disposition`
   (or both fail-closed). Reuse `conformance/shared-suite/adapter-process-client.mjs`.
3. Keep the invariant checks — they catch classes a single-oracle differential cannot (a bug present
   in *both* implementations still violates determinism / fail-closed / precedence).

## Out of scope (documented, not silently skipped)
- **Symbols, BigInt, circular references** as input values — not reachable via any JSON or
  lenient-JSON parser; a resolver is not expected to defend against them.
- **Cryptographic soundness of Ed25519 / SHA-256 / JCS** — those are `@noble/*` and `canonicalize`
  concerns, not BB resolution logic.
