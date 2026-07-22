# BB Stateful / History Fuzzer

`bb-stateful-fuzzer.mts` — a **stateful, history-based** model fuzzer for the DACS-5 §10.4.2
BundleBinding resolver (`src/lib/bundle-binding-v1.ts`).

## Why a second fuzzer (input-shaped vs history-shaped)

`bb-differential-fuzzer.mts` is **input-shaped**: it generates a single malformed/rich input and
asserts invariants on ONE resolution. That catches per-input defects (exception escapes,
fail-open, budget truncation, precedence inversion on a single call).

But the deepest DACS defects are **histories** — *sequences* of operations, not single inputs:

- the `anchoredByRole` laundering we fixed (#248) is a history: **sign** a bundle → **alter the
  UNSIGNED `anchoredByRole` field** → **resolve**. The signature still verifies (`anchoredByRole`
  is excluded from `bundleScope`), yet a `fail` becomes `present` unless the resolver re-anchors
  the unsigned field to a trusted signal;
- the **perspective-flip** fault swap is a history: re-anchor a copy under another party's storage
  address and see whether the absolute `faultedParty` attribution moves;
- **mixed-version reconciliation** is a history: migrate a legacy `AttestationBundle` ↔
  `FaultAttestationBundle` and reconcile the pair.

@mj-deving (Marius) made this point about autoreview tooling; it is just as true of resolver
testing. A fuzzer that generates randomized **operation sequences** and asserts invariants **across
the whole history** catches the *class*, not one instance.

## State model

Each copy runs a small lifecycle state machine:

```
constructed → signed → anchored/persisted → (adversarial transitions) → resolved
```

A `World` holds a roster of three parties (buyer / seller / orchestrator) whose Ed25519 keys are
derived from the **published dacs248 corpus seeds**, so every history shares the same key material
as the pinned vectors (a history is a superset of the fixture corners). Each `Copy` tracks:

| field | meaning |
|---|---|
| `signedScopeHex` | hex of the JCS `bundleScope` hash **frozen at sign time** |
| `bundle` | the live JSON at the anchor (may drift from `signedScope` after `ALTER_UNSIGNED`) |
| `anchorRole` | the role whose native storage address the copy is anchored at (the **trusted signal**) |
| `trueAnchoredByRole` | the `anchoredByRole` value at sign time, before any tamper |
| `nativeAddress` | the native storage address |
| `boundJobId` / `boundRole` | the `(jobId, role)` the binding was **signed for** (replay probe) |
| `binding` | the `BundleBinding` anchoring this copy (real Ed25519 signature) |

## Transition alphabet (legitimate + adversarial)

| op | kind | effect |
|---|---|---|
| `SIGN+ANCHOR` | legit | sign a copy with real Ed25519 over the JCS canonical signed scope; anchor it at a role's native address |
| `ALTER_UNSIGNED` | **adversarial** | flip `anchoredByRole` (an unsigned field) AFTER signing — signature stays valid. THE laundering step |
| `PERSPECTIVE_FLIP` | **adversarial** | re-anchor a copy under another party's role key (perspective swap), content unchanged |
| `REPLAY` | **adversarial** | resolve a binding signed for `(jobId, role=X)` against a *different* session/job/role |
| `VERSION_MIGRATE` | legit | migrate legacy `AttestationBundle` ↔ `FaultAttestationBundle`, forming a mixed pair |
| `BUILD_POINTER` | legit | build an extended `FaultBundleExtendedPointer` over a dereferenced FAB (triple-identity) |
| `RESTART` / reorder | probe | re-resolve the same state, and re-resolve with copies / map-keys reordered (order-independence) |
| `CORRUPT` | **adversarial** | corrupt an unsigned/structural field into garbage (fail-closed probe) |

## Invariants asserted ACROSS the sequence

| invariant | statement |
|---|---|
| **no-launder** | no `ALTER_UNSIGNED` of an unsigned field may turn a `fail`/`indeterminate` into `present` (the `anchoredByRole` class — reproduces the known defect if the `anchorRoleMismatch` guard is reverted) |
| **perspective-invariance** | a `PERSPECTIVE_FLIP` under another perspective must not change the absolute `faultedParty` attribution / must be rejected |
| **replay-rejection** | a copy replayed into a `(jobId, role)` it was not signed for is never `present` for the wrong session |
| **determinism-under-restart** | the same state re-resolved yields the same disposition + `resolvedNativeAddress`, order-independently (copy order AND map-key order) |
| **fail-closed** | any malformed/incomplete transition yields a deterministic disposition, never a throw/hang |
| **monotonic-standing** | a full-standing (fully-signed) copy is never overridden by a lesser-signed one regardless of operation order |

## Run + replay

```bash
# default: 500 histories, length <= 8, fixed seed 20260701 (reproducible, CI-gateable)
npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts
npm run fuzz:bb-stateful

# more histories / different seed / longer sequences
npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts --cases 3000 --seed 42 --history-len 12

# replay ONE history (prints the ordered operation sequence + resolution)
npx tsx conformance/cross-run-corpus/bb-stateful-fuzzer.mts --case-seed 2390727658
```

The process exits non-zero iff an invariant violation is found. On a violation it prints the
**minimal reproducing SEQUENCE** (the ordered operations) and a `--case-seed` replay command.

The signing path is **self-tested first** (`selfTest()`): it proves (a) a valid full-signed history
resolves `present` and (b) a pristine contradiction base resolves `fail` — so a broken oracle
cannot report a vacuous green (every "valid" history collapsing to non-present, or every "fail"
base never actually being `fail`).

## Teeth check (does it actually catch the defect?)

A one-line documented toggle temporarily reverts the `anchorRoleMismatch` guard in the resolver:

```ts
// in src/lib/bundle-binding-v1.ts::anchorRoleMismatch, first line:
if (process.env.DACS_FUZZ_REVERT_ANCHOR_GUARD === '1') return false; // TEETH-CHECK TOGGLE
```

With the guard reverted, the fuzzer goes **RED**: ~211/500 histories violate `no-launder` (158) and
`perspective-invariance` (53) — the `ALTER_UNSIGNED` / `PERSPECTIVE_FLIP` steps launder `fail→present`
across the mixed, perspective-pair, AND extended-pointer families. With the guard in place the same
seeds resolve `fail` (`anchor-address ↔ anchoredByRole mismatch … rejected`). This proves the fuzzer
has teeth. **The toggle is not committed** — it exists only to demonstrate the teeth check.

## Honest scope

**Covered histories:** `anchoredByRole` laundering (mixed / perspective-pair / extended-pointer
families), perspective-flip fault swap, cross-session/role replay of a bound binding, legacy↔FAB
version migration of a coherent non-divergent pair, monotonic full-signature standing under
randomized anchor order, and malformed-transition fail-closed corruption.

**Not yet modeled (candidate follow-ups):**
- multi-copy (>2) mixed pairs and 3-way divergence beyond the pair/mixed constructions here;
- `phaseSummary` histories with multiple shared indices (only index 0 is modeled);
- budget-exhaustion as a *history* (many `SIGN+ANCHOR` ops for one signer over N=8) — the input
  fuzzer covers the single-input form;
- true second-oracle differential across a runnable DACS-Standard reference (none ships an
  executable BB resolver yet — same limitation the input fuzzer documents);
- pointer-family histories where the pointer/binding hashes drift independently (only the
  triple-identity-holds base with an unsigned-field flip is modeled).
