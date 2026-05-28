# csv-class — end-to-end example

A self-contained demonstration of the DACS-1 + DACS-2 + DACS-5 loop using the
"CSV row analyzer" scenario from the KyneSys Agent Commerce demo:

```
buyer agent (Tidybooks) ──── DACS-1 listing ──── seller agent (RowSense Analytics)
       │                          ↓                          │
       └── DACS-2 vet GLEIF ──────┴────────── DACS-5 bundle ─┘
              (DAHR-stub)                         (anchored both sides)
```

## What this script does

`run.mts` walks the full DACS loop in one process:

1. **Generate fresh buyer + seller keypairs** (ed25519). The public keys ARE the
   CCI primary-claim identifiers (`scheme: cci`).
2. **Build a DACS-1 listing** advertising "analyze-csv" capability, sign it with
   the seller's primary-claim key (separator `dacs-listing:v1:`), and verify the
   JCS canonical bytes fit in the 16 KB §6.3.4 size cap.
3. **Run a DACS-2 vet** against a public GLEIF LEI (skip-anchor mode, so the run
   doesn't require a Demos node or DEM balance). Produces a §7.5.1 VerifyResult
   with the `dahr-stub:gleif-cbp:1` honest-scope marker.
4. **Build a DACS-5 AttestationBundle** for the buyer side, embedding the
   listing reference + the DACS-2 vet result. Sign with `dacs5-bundle:v1:`.
5. **Build the matching seller-side bundle** with the same `jobId` and
   cross-party identifiers.
6. **Verify both bundles** via the same `pathos-dacs-verify` library used by
   the CLI. The expected v0.2 verdict is `indeterminate` (NOT pass) — see the
   "Why indeterminate" note below for the §7.5.1 reason.

No chain writes, no DEM consumed. By default the script makes one live HTTP call
to GLEIF for the DACS-2 vet step; pass `SKIP_GLEIF=1` to skip that call and use
a canned attestation (fully offline).

## Run it

```bash
cd ~/pathos-dacs-ref

# Fully offline (canned GLEIF response — fastest, deterministic)
SKIP_GLEIF=1 npx tsx examples/csv-class/run.mts

# Default (one live HTTPS call to api.gleif.org; still no chain writes)
npx tsx examples/csv-class/run.mts
```

Expected output ends with:

```
buyer-side verdict:  indeterminate
seller-side verdict: indeterminate
scope honesty marker:  dahr-stub:gleif-cbp:1

csv-class: OK — full loop ran cleanly; verdict=indeterminate is expected for v0.2 stub scope
  (§7.5.1 invariant survives end-to-end; pass requires v0.3 validator-quorum DAHR)
```

**Why `indeterminate` and not `pass`?** That's the §7.5.1 invariant in action.
The DACS-2 attestation today is a `dahr-stub:` (single-fetch, no validator
quorum yet); the verifier correctly refuses to mark a bundle that contains
stub attestations as `pass`. Until v0.3 wraps the DAHR fetch with a real
consensus-backed-proxy signature, the cleanest end-state is `indeterminate` —
which is *exactly* what an honest receipt should produce in this scope. A `pass`
here would be a bug, not a feature.

The example exits 0 when no step `fail`s and exits 1 if any step does.

## What this proves about DACS

- **Composability** — DACS-1 + DACS-2 + DACS-5 compose without DACS-3/4 in scope
- **Reference reproducibility** — anyone running this script gets byte-identical
  canonical forms + identical signatures (modulo the fresh keys generated at top)
- **§7.5.1 invariant survives the full loop** — the vet result feeds into the
  bundle which feeds into the verifier; pass/fail/indeterminate never collapses
- **Honest-scope marker travels** — the `dahr-stub:` prefix added by DACS-2
  appears verbatim in the AttestationRef inside the DACS-5 bundle

## What's NOT in this example

- DACS-3 channel messages / negotiation envelope (out of v0.x scope)
- DACS-4 settlement (no x402 / HTLC / payment auth)
- Real chain writes (would require `DEMOS_MNEMONIC` + DEM balance)
- TLSN closed-data attestations
- Multi-recipe aggregation (§7.7 CompositeVerificationRecord with N>1 results)

To exercise chain writes, set `DEMOS_MNEMONIC` and run the integration tests:

```bash
DACS_LIVE_NETWORK=1 DEMOS_MNEMONIC="..." npm test
```
