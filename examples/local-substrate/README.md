# §11.3b — DACS on a non-Demos substrate

DACS §11.3 asks for a **second, independent reference implementation on a non-Demos
substrate**, to prove the spec is genuinely substrate-agnostic. SR-2 ("anchored,
immutable storage") is an *abstract* requirement — it is not "the Demos StorageProgram."

This example proves it by running the **same, unmodified DACS-5 verifier**
(`verifyBundle`) against a **local filesystem store** — zero Demos dependency — through
the seam the verifier already exposes: `fetchAnchoredImpl`.

## What it shows

```
npx tsx examples/local-substrate/run.mts
```

| Step | What runs | Result |
|------|-----------|--------|
| [1] | bundle structural verify (`skipTwoSidedLookup`) | `pass` |
| [2] | the SR-2 contract on local — anchor → verifyAnchor | `pass` / tamper→`fail` / missing→`indeterminate` |
| [3] | **full §10.4.2 two-sided-anchoring verify on local storage** | **`pass`** |
| [4] | unilateral anchor (seller absent) | `fail` — spec-correct §10.4.3 *aborted-by-self* |

Step [3] is the headline: the production verifier fetches **both** party anchors from the
local store, byte-checks the local bundle against its anchored side, validates both
signatures, and reaches a `pass` — exactly as it would against Demos. Step [4] removes
the seller anchor and the *same* verifier returns the correct unilateral `fail`. The
substrate changed; the verifier did not.

## The substrate (`src/substrate/local.ts`)

Implements the same three SR-2 operations as `src/demos/storage.ts`, on the filesystem:

- `localAnchor(storeDir, storageAddress, data, owner)` → `AnchorResult`
- `localFetchAnchored(storeDir, storageAddress)` → `FetchResult | null` — signature matches
  `typeof fetchAnchored`, so it drops straight into `verifyBundle({ fetchAnchoredImpl, rpc: storeDir })`
- `localVerifyAnchor(storeDir, storageAddress, expectedHashHex)` → `pass | fail | indeterminate`

Addresses are the content-derived `stor-<hex>` locators from `computeAnchorPair(jobId)`,
encoded to safe filenames (no path traversal). The verifier recomputes the same address,
so it finds what was anchored.

## Why this matters for the spec

If a third party can stand up SR-2 on *any* immutable store and the reference verifier
runs unchanged, then DACS-5 attestations are portable across substrates — the property
§11.3 is asking implementers to demonstrate. This is the non-Demos half of that proof;
the Demos half is `examples/` against the StorageProgram.
