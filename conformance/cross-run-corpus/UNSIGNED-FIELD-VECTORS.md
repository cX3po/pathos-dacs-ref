# Unsigned-field / loosely-typed member laundering — conformance vectors

Published conformance evidence for a single, recurring DACS-5 §10.4 defect **class** that the
ecosystem has been finding one instance at a time.

## The class (one sentence)

> A receipt/bundle member that a resolution decision depends on is either **outside the signed hash
> scope**, or **too loosely typed**, so a mutation that keeps the signature valid (or confuses the
> type) changes the verdict — laundering a `fail`/`indeterminate` into a `present`, or hiding a
> genuine divergence.

Known hand-mined instances, all one class:

| Instance | Field | Sub-class | Mechanism |
|---|---|---|---|
| #248 (ours) | `anchoredByRole` | unsigned field | stripped from `bundleScope`; flipping it re-attributes fault authority without breaking the signature (`fail` → `present`). |
| xm33 | `bundleCount` | boolean-for-int | a `bool` where an `int` is expected slips a naive `x == 0` check (`0 == false` in JS). |
| RB | `windowingBasis` | container-for-scalar | an array/object where a scalar is expected takes the wrong branch (TypeError, or silently evades a cross-copy check). |

## What ships here

- **Generator:** `gen-unsigned-field-vectors.mts` — deterministic; `--check` is a byte-for-byte
  reproducibility proof. `npm run gen:unsigned-vectors` regenerates + checks.
- **Vector set:** `dacs248/unsigned-field-laundering-v0.1.json` — 14 vectors, real Ed25519 over the
  JCS-canonical signed scope with the published corpus seeds (asserted to reproduce the published
  pubkeys). Set-level `hash = sha256(jcsCanonical(vectors))`.
- **Runner:** `unsigned-field-cross-run.mts` (standalone AGREE/DIVERGE report;
  `npm run cross-run:unsigned-vectors`). Also wired into the parent `dacs248-cross-run.mts`.
- **Test:** `test/vectors/unsigned-field-laundering-vectors.test.ts` — runs the set, asserts the
  no-launder invariant, and mutation-pins the container-index guard (revert → RED).

## The vector triple

Every reachable field ships a **triple** so the set is not tautological:

- **PRISTINE** — correct field, its correct expected disposition.
- **MUTATED** — the field altered so the **signature still verifies** (or the type is confused): the
  laundering attempt. Expected disposition = the **safe** one — it must **never** become `present`
  when the pristine was `fail`/`indeterminate` (fail-closed).
- **CONTROL** — the field flipped in a way that **should legitimately change** the disposition. Proves
  the resolver distinguishes a real change from a laundered one.

## Coverage (honest)

| Field | Sub-class | Reachable in our resolver? | Triple | Our resolver |
|---|---|---|---|---|
| `anchoredByRole` (mixed) | unsigned field | **yes** | pristine `fail` / mutated `fail` / control `present` | AGREE — re-anchored to the copies-map key (`anchorRoleMismatch`). |
| `anchoredByRole` (extended-pointer) | unsigned field | **yes** | pristine `present` / mutated `fail` / control `fail` | AGREE — re-anchored to the signed/derived `binding.role`. |
| `budget` | boolean-for-int | **yes** | pristine `indeterminate` / mutated `indeterminate` / control `present` | AGREE — `Number.isInteger(budget)` rejects the bool → normative default N=8 (never coerced to 0/1). |
| `phaseSummary[].index` | container-for-scalar | **yes** | pristine `fail` / mutated `fail` / control `present` | AGREE **after resolver hardening** (see below). |
| `bundleCount` | boolean-for-int | **reference-only** | — | Our resolver derives copy counts structurally (array length), not from a caller-supplied `bundleCount`; no decision to swing here. Named for implementations that carry it. |
| `windowingBasis` | container-for-scalar | **reference-only** | — | Not present in our §10.4 surface; the same class is exercised via `phaseSummary[].index`. Named for implementations that carry it. |

`reachable:true` vectors are **scored** (AGREE/DIVERGE) against our resolver; `reachable:false`
(aspirational) vectors are **reported REF-ONLY**, not scored — they are coverage sign-posts for other
implementations (e.g. Marius's `dacs-verify`, the DACS-Standard reference), not fabricated passing
cases.

## Resolver gap found + closed (container-for-scalar)

Building this set surfaced a **real gap**: `phaseSummaryDiverges` keyed a `Map` by the raw
`phaseSummary[].index`. With a **container** index (`[0]`), Map keys compare by reference, so two
copies' `[0]` indices never collide and the #254 shared-index cross-copy check was **silently
skipped** — laundering a genuine phase divergence (`fail`) into agreement (`present`). Before the fix,
`unsigned-field-cross-run.mts` reported this vector as **DIVERGE** (ours `present`, safe `fail`),
reported honestly rather than hidden.

The fix (`src/lib/bundle-binding-v1.ts`, `phaseSummaryDiverges`) normalises the index to a **canonical
string key** (`jcsCanonical`), so container indices compare by value and cannot evade the check; a
non-canonicalisable index falls back to a stable string tag rather than throwing. The
mutation-pin test reverts this guard and proves the vector goes RED without it.

## How to run

```bash
npm run gen:unsigned-vectors          # regenerate + byte-for-byte --check
npm run cross-run:unsigned-vectors    # AGREE/DIVERGE report for this set alone
npx tsx conformance/cross-run-corpus/dacs248-cross-run.mts   # parent runner (all families; this set included)
npx tsx --test test/vectors/unsigned-field-laundering-vectors.test.ts
```

Any second implementation can load `unsigned-field-laundering-v0.1.json`, resolve each vector by its
`family` (`mixed` / `pointer` / `direct`), and compare its disposition to the vector's `expected` (for
`reachable:true` vectors). The signatures are genuine Ed25519 over JCS scope, so the vectors are real
adversarial inputs, not hand-waved fixtures.

## Provenance

Each vector records, in its `provenance`, **why** its expected disposition holds and **which**
signed-scope/type rule it exercises (mirroring the v0.3 sets). The set metadata records the class
definition, the three sub-class instances, the triple structure, the canonicalisation + seed rules,
and the reachability note.
