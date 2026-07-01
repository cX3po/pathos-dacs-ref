# The Stranger Gauntlet — a DACS trust showcase

A2A's unsolved problem is **trusting a stranger's agent**: a shopper meets a vendor
agent it has never seen and has no basis to believe the "deal done" it is handed. The
Gauntlet demonstrates that **DACS solves this at the artifact layer**.

One **Shopper** meets **three stranger Vendor agents** in the same session, and the same
§10.4.1 referee (`verifyBundleV1`) judges all three:

| Vendor | Bundle | Verdict |
|--------|--------|---------|
| **A (honest)** | valid, real-ed25519-signed two-sided `AttestationBundleV1` | `accept` → 🟢 TRUSTED |
| **B (honest)** | a *different* valid, real-signed bundle | `accept` → 🟢 TRUSTED |
| **C (counterfeit)** | validly signed, then **tampered after signing** | `reject` → 🔴 CAUGHT |

The showcase prints a **Trust Report** naming, for the counterfeit, the **decisive check
that killed it**, and emits a machine-readable JSON result a later HTTP / signed-receipt
layer can consume. It exits `0` **only if** both honest vendors are trusted **and** the
counterfeit is caught. A `1` would mean the counterfeit slipped through — a real §7.5.1
*do-not-collapse* verifier bug.

## Run

```bash
npx tsx showcase/stranger-gauntlet/gauntlet.mts
```

Console only. Deterministic (fixed-seed ed25519 keys). Zero network, zero funds, no
deployed identities — it runs anywhere with no setup, mirroring `src/showcase`.

## Test

```bash
npx tsx --test test/stranger-gauntlet.test.ts
```

Asserts honest → `accept`, counterfeit → `!== accept`, and that the counterfeit's
`killedBy` is populated with the decisive check.

## How Vendor C is counterfeited (and what catches it)

Vendor C's bundle is built **honestly first** — a real two-sided bundle, signed by both
the Shopper (buyer) and Vendor C (seller) over `"dacs-bundle:v1:" || bundleHash`. Then a
single field inside the **signed canonical scope** is mutated *after* signing:

```
listingRef.contentHash  →  rewritten to a different listing (a bait-and-switch:
                           the signed attestation now claims to cover a listing —
                           at a swapped price — that nobody actually agreed to)
```

`listingRef.contentHash` is part of the hashed canonical form, so the referee's
recomputed `bundleHash` no longer matches the hash the ed25519 signatures were made over.
Every resolvable signature therefore **fails to verify**, and §10.4.1 resolves the bundle
to **`reject`**, with `killedBy = signature-invalid` ("does not verify over
`dacs-bundle:v1: || bundleHash`"). The tamper is deliberately a no-op on structure and on
the signer set, so the *decisive* check is unambiguously the signature — not a side effect.

> Note: `anchoredByRole` is **excluded** from the signed hash (spec R5-1), so tampering
> *that* field would **not** break the signature. The counterfeit tampers a field that is
> in-scope on purpose — that is what makes the signature the decisive kill.

## Decision vocabulary

The §10.4 bundle referee returns the three acceptance values `accept | reject |
indeterminate`. **Only `accept` is success** ("trusted"); **both** `reject` (invalid)
**and** `indeterminate` (undecidable) mean NOT-trusted (§7.5.1 do-not-collapse). That maps
onto the broader §7.5.1 four-value `VerifyResult` vocabulary (`pass | fail | indeterminate
| error`): `accept ≈ pass`, `reject ≈ fail`.

## Scope (no overclaiming)

Defensive **conformance** verification — it proves the verifier *catches* a bad bundle
built from our own fixtures. It is **not** attack tooling, is not live on-chain, and uses
local fixed-seed keypairs, not deployed identities. This is the core engine; no HTTP or
public surface yet (a later phase).

## Files

- `gauntlet.mts` — the engine: builds A/B/C, runs `verifyBundleV1`, prints the Trust Report + JSON
- `README.md` — this file
- `../../test/stranger-gauntlet.test.ts` — the guarantee tests
