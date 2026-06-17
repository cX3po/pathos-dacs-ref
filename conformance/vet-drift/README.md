# DACS-2 Vet drift-testing — GLEIF / public-authority convergence

A #99-style convergence check for the **DACS-2 Vet** surface: two independent implementations verify
the **same claim** via their own public-authority path and must agree on the **deterministic verdict**.
Proposed as a collaboration between **PATH-OS Labs (GLEIF `consensus-backed-proxy` path)** and
**DNO (public-authority probes)** — XM33's suggestion in the DACS group.

## The comparable surface (what must converge)
A DACS-2 `VerifyResult` (§7.5.1) carries both deterministic and run-specific fields. Drift-testing
compares ONLY the deterministic verdict — NOT the per-run attestation/timestamps:

| Field | Compared? | Why |
|---|---|---|
| `claim` (scheme + identifier) | ✅ | the input both sides verify |
| `recipe` family | ✅ (family, not version pin) | both target the same method class |
| `decision` (`pass`/`fail`/`indeterminate`) | ✅ | the verdict — must agree (NB: DACS-2 §7.5.1 lists a 4th `error` value; our impl uses 3 + rejects malformed pre-VerifyResult. A draft §7.5.1 clarity note is in flight — co-authored XM33·DNO + C3PO·PATH-OS Labs — pinning the three-way frame: input-rejected → no VerifyResult / `error` → execution failure / `indeterminate` → completed-but-inconclusive) |
| entity resolution (`reason` / `supplementarySignals.entityName`) | ✅ | the resolved entity must match |
| `runAt`, `attestation.anchor`, `contentHash`, `producedAt` | ❌ | per-run (timestamps, anchor) — never expected equal |

Convergence = same `claim` → same `decision` + same resolved entity, across both impls.

## Our side (live, reproducible)
`src/cli/vet-gleif.ts` runs the GLEIF `consensus-backed-proxy` recipe against the open GLEIF public
API (no key). Reproduce our exemplar:
```bash
npx tsx src/cli/vet-gleif.ts --lei 506700GE1G29325QX363 --jobId <uuid> --dry-run
```
See `exemplar-506700GE1G29325QX363.json` for our normalized verdict.

## Proposed shared set (expand together)
Start with a mix that exercises every `decision`: an active LEI (→ `pass`), a lapsed/retired LEI
(→ `fail`/`indeterminate`), and a malformed LEI (in our impl: rejected pre-VerifyResult as a usage error; spec lists a 4th `error` decision — to reconcile). We seed one active exemplar; DNO/XM33
to co-author the rest so the set isn't biased to our path.
