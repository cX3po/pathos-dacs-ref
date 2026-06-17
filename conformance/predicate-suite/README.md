# dacs_conformance — predicate conformance suite

A **defensive conformance test harness** for the DACS verifier. It proves the verifier correctly
**ACCEPTS** inputs that satisfy every verification predicate and **REJECTS** inputs that violate
exactly one. Pure, deterministic code — **no LLM, no API, no network at run time**. Every fixture is
built from fixed seeds, salts and timestamps, so the corpus is reproducible byte-for-byte and drift is
a single sha256 comparison.

Sibling to the other conformance tools in this repo, covering the surface they don't:

| tool | surface it checks |
|---|---|
| `dacs-drift.mts` | §10.4 AttestationBundle **signed-scope bundleHash** (cross-impl hash agreement) |
| `pathos-conformance-harness.mts` | JCS / ed25519 **crypto oracle** (byte-identical canonicalisation + signatures) |
| **`predicate-suite/` (this)** | the verifier's **accept/reject predicate** contract (ACCEPT valid · REJECT one-violation) |

## Two cores

1. **`vectorgen.mts`** — deterministic test-corpus generator. From each predicate the verifier
   enforces it emits one valid case (→ `ACCEPT`) and N negative cases, each violating exactly one
   predicate (→ `REJECT`, with the predicate as the reason). Writes `vectors/<set>.json` and a
   content-hashed golden manifest `golden/<set>.json`. **Drift** (the corpus changed unexpectedly) is
   caught by comparing the regenerated hash to the golden.
2. **`verifycore.mts`** — runner + assertions. Runs every generated case through the **real** verifier
   predicate and asserts `actual == expected`. Any mismatch is a **conformance bug** — it names the
   case, expected vs actual verdict, and the verifier's own reason text so a human can tell whether the
   verifier is wrong or the case is wrong.

`run.mts` is the whole loop in one command: `vectorgen → verifycore → diff golden`.

## Predicate families (grounded in the real offline verifier code)

The chain-side checks (§10.4.2 two-sided anchoring, §7.5.2 AttestationRef walk) require RPC and are
**out of scope** — this harness covers the offline acceptance contract only.

- **`bundle-v1`** (`src/lib/verify-bundle-v1.ts::verifyBundleV1`, enforcing) — structural (§10.4),
  signer-rule (§10.4.1), and signature predicates.
- **`consent`** (`src/lib/consent.ts::consentCovers` → `resolveEffectiveConsent` → `verifyConsentRecord`)
  — record authenticity, effective-state (revoke / expiry / authority), and coverage.
- **`disclose`** (`src/lib/disclose.ts::verifyDisclosedClaim`) — audience / nonce / consent-scope /
  freshness / salt-floor / Merkle-membership / reveal-signature.

## Usage

```bash
# the deterministic DACS check (generate → verify → drift-check):
npx tsx conformance/predicate-suite/run.mts            # exit 0 = all conform & no drift; 1 = bug or drift

# regenerate the golden after an INTENTIONAL predicate change:
npx tsx conformance/predicate-suite/run.mts --update

# individual cores:
npx tsx conformance/predicate-suite/vectorgen.mts          # generate corpus, fail on drift
npx tsx conformance/predicate-suite/verifycore.mts          # verify all sets
npx tsx conformance/predicate-suite/verifycore.mts disclose # verify one set
```

## Extending the suite (where the model plugs in — developer surface only)

When a **new** predicate or negative-case category is wanted beyond the enumerated set, draft it with a
one-off `claude -p` on the developer surface, then **encode it as a predicate** in the relevant
`families/<set>.ts` (`buildCases` for a structural/state predicate, or the `NEGATIVES`/`CASES` table
for a one-violation case) and re-run with `--update`. The model *extends* the generator; it never runs
in the loop. The loop stays deterministic and $0.

Conformance stated per-surface, deliberately conservative.
