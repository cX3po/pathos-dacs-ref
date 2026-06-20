# DACS security conformance vectors

Independent, runnable conformance vectors for DACS v0.1 **security** rules, derived directly from the
DACS-Standard spec sections and contributed by PATH-OS as the independent reference implementation.
**Non-normative** — offered to the ecosystem (steward + other implementations) as shared test material;
the spec remains the source of truth.

## What's here

| Artifact | Spec | What it checks |
|---|---|---|
| [`threat-to-test-matrix.md`](./threat-to-test-matrix.md) | §12.4 | Coverage map: every §12.4 threat → is the claimed defense actually verified by a conformance test (COVERED / PARTIAL / GAP / RESIDUAL / FUTURE-SPEC / INHERITED / NON-CONFORMANCE)? |
| [`agreement-listing/`](./agreement-listing/) | §8.5.2 | Agreement-listing conformance: a forged/out-of-band agreement against its listing is rejected (7 checks: currency, price-band, rail, deliverable, deadline, expiry, pattern). 30 vectors. |
| [`vp-replay/`](./vp-replay/) | §7.3.2 | Verifiable-presentation holder-binding (anti-replay): a genuine VC re-presented by a non-holder, or replayed across sessions, is rejected. 13 vectors. |

The matrix's GAP rows are the roadmap for the next vector sets in this directory.

## Design principles
- **Conservative.** A vector asserts a defense holds only when it genuinely does; the matrix marks
  untested defenses honestly as GAPs rather than implying coverage.
- **§7.5.1 decision discipline.** Validators return the full `pass | fail | indeterminate | error`
  lattice and never collapse "undecidable" into "fail/reject".
- **Exact + portable.** Decimal comparisons are exact (BigInt, no floats); signatures are raw ed25519.
  The validators are dependency-light so any implementation can run them.
- **Adversarially reviewed.** Each validator was reviewed by independent models for overclaim, crypto
  correctness, and edge coverage before inclusion.

## Run

```bash
npx tsx conformance/security-vectors/agreement-listing/run.mts   # §8.5.2 — 30 vectors
npx tsx conformance/security-vectors/vp-replay/run.mts            # §7.3.2 — 13 vectors
```

Each run regenerates its `vectors/*.json` deterministically (stable set hash) and asserts every case's
expected decision. Exit non-zero on any mismatch.

## Scope notes
- `vp-replay` implements §7.3.2 steps 1 (issuer genuineness) + 6 (holder-binding); steps 3 (issuer
  allow-list), 4 (expiry/revocation), 5 (subject↔identifier match) are separate surfaces, out of scope
  here. See the file header.
- These vectors test the offline/deterministic security predicates. Chain-side checks (§7.5.2 anchoring,
  §10.4.2 two-sided) are exercised by the reference impl's own test suite.
