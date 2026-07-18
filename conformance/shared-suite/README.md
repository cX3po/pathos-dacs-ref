# DACS Shared Conformance Suite (v0, draft — proposed for working-group adoption)

A **neutral, cross-implementation** conformance suite for DACS (Demos Agent Commerce
Standards). Its job is to answer one question, mechanically and reproducibly:

> **Do independent DACS implementations agree, byte-for-byte and verdict-for-verdict, on
> what the specification says — and where they don't, exactly which spec corner is ambiguous?**

## Why this exists

The specification is the source of truth, but two conformant-looking implementations can
still diverge on undefined corners (the ComponentSignature value encoding — CORE SIG-6,
DACS-Standard#263/#265 — is a worked example). A single implementation's test harness can
only prove "you match *me*." What the ecosystem needs is an **independent oracle**: a shared
corpus of vectors, run through *every* implementation via a thin adapter, where **agreement
is interop evidence and disagreement is a spec question** — never a verdict on anyone's code.

## How it works

1. Each implementation provides a small **adapter** (see [`ADAPTER.md`](./ADAPTER.md)) —
   a few pure functions (canonicalize, signed-scope-hash, signature-value verdict, bundle
   verdict). No implementation adopts another's code.
2. The suite runs every vector through every registered adapter.
3. It emits an **agreement matrix** + a list of **spec-questions** (disagreements), ready to
   file upstream. It never labels an implementation "non-conformant."

```
node cross-run.mjs                 # agreement matrix across all registered adapters
node cross-run.mjs --spec-questions   # only the disagreements, formatted for upstream
```

Self-contained on the run path (Node ≥ 18, zero dependencies, no network) — inherited from
the [`../partner-kit`](../partner-kit) design, and tamper-evident by the same per-file
manifest hashing.

## Governance & neutrality (the load-bearing part)

- **This is seeded by an independent implementer, not owned by one.** The intended home is a
  neutral `DACS-Agent-commerce` repository; the vectors are governed by the working group.
- **Non-normative.** Passing is interop evidence, not certification — no DACS certification
  exists; the normative source is the specification.
- **Every impl is one adapter among several.** The `pathos-dacs-ref` adapter is the first
  reference adapter because it's the seed, not because it defines conformance.
- Disagreements are published as spec-questions with the reproducing vector attached, so the
  fix lands in the spec once and every implementation inherits it.

## v0 coverage (honest scope)

Running today, self-contained (`node cross-run.mjs`): **43 seed vectors PASS** across five
families — `canonical-accept` (21), `canonical-reject` (6), `domain-sep-sign` (11),
`drift-signed-scope` (2), `sig-value-encoding` / SIG-6 (3) — through the wired
`pathos-dacs-ref` reference adapter, with a divergent-stub demo proving the spec-question path.

Explicitly **not yet covered** by the v0 adapter interface (documented in the run output, not
dropped):
- **`verifyBundle` / DACS-5 §10.4 (F4)** — the full ~700-line acceptance verifier (incl. the
  referenced-artifact-authorization class, dacs-sdk#38) isn't zero-dependency-reproducible on
  this run path; it's a **repo-side adapter variant**, and the suite records ABSTAIN, not a pass.
- **8 fuller `drift-signed-scope` vectors** — they exercise the whole drift-classification /
  manifest / fail-closed pipeline, beyond F2's narrow "sha256 over the signed scope"; a future
  family adds them without breaking existing adapters.
- **1 raw signed-bytes-layout vector** — needs a byte-layout function F5 doesn't declare.

The adapter interface is versioned and additive, so these land as new optional families. The
point of v0 is a *working, honest, extensible* cross-run — not full spec coverage on day one.

## Status

Runner built + independently verified (43/43 PASS, demo spec-question fires). See
[`PROPOSAL-DRAFT.md`](./PROPOSAL-DRAFT.md) for the working-group proposal.
