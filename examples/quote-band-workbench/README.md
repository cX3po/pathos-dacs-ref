# Quote Band Workbench

A walletless, local CLI calling the real dacs-sdk `negotiablePriceBand` and
`isNegotiablePriceWithinBand` APIs. No copied arithmetic, network reads,
negotiation messages, signing, payment rails or state files. This is price-band
inspection, not an authenticated Listing or complete RFQ validator.

## Run

Requires Node ^20.19.0 or >=22.12.0 and an already built, trusted dacs-sdk checkout.
No npm installation is required for this workbench. SDK dependencies must already
be installed by the SDK owner. The local reproduction used Node v20.20.2.

From this directory:

```sh
export DACS_SDK_ROOT=/path/to/dacs-sdk
node --test test.mjs
node cli.mjs example.json
```

The example deliberately exits **1**, since two of its four counteroffers are
rejected. Its band is `{ "lower": "1.4", "upper": "1.7" }` in DEM.
Set the SDK root to a trusted build of source commit
`557f417a77d6e0834a01a95524110e9aa2c483d9`.
The entry module SHA-256 must equal
`4d2928e40665754d00be379c2c5d67cd134dd909276bf2cb82bd5702e0781c35`.
Missing or different entry bytes cause an error; the program never substitutes
an offline approximation. The entry hash is a drift check, not a signature or
verification of the entire SDK dependency graph. Trust the checkout and its
installed dependencies before running it.

## Input and decisions

The complete schema is demonstrated in `example.json`. Exactly the shown keys
are accepted. Amounts must be JSON **strings** in positive CD-1 canonical form:
`"1.5"` works; `"1.50"`, `"01.5"`, `"1e0"`, numeric `1.5`, and zero do not.
Percentages are JSON numbers because the SDK API requires numbers. The SDK uses
their canonical JSON decimal representation as an integer ratio. Prefer small
explicit decimal values; pre-JSON JavaScript precision loss cannot be recovered.
Amounts never pass through JavaScript Number.

The centre's canonical fractional digits determine rounding, independent of
currency precision. Both endpoints are inclusive. Centre `1.5` ±10% produces
raw `1.35`/`1.65`, rounded half-up to `1.4`/`1.7`. Offers themselves are not
rounded: `1.70001` is rejected. Centre `15` ±10% yields `14`/`17`.

Each offer receives `ACCEPTABLE` or `REJECTED`, with `WITHIN_INCLUSIVE_BAND`,
`OUTSIDE_BAND`, `INVALID_AMOUNT`, or `CURRENCY_MISMATCH`. Currency comparisons
are exact and case sensitive; no conversion or currency registry is implied.
`ACCEPTABLE` means only this amount/currency passes the band inspection.
Units are unsupported and refused, as are other unknown keys. The SDK RFQ
runtime additionally binds units, authenticated Listings, turns and deadlines.

Exit codes: **0** all supplied offers acceptable (or band-only empty offers);
**1** at least one offer rejected; **2** invalid request, read/import error or
timeout. Errors emit JSON on stderr; successful inspection JSON goes to stdout.
No partial inspection is printed for malformed request structure or invalid
centre/percentages. Invalid offer amounts are retained as individual rejections.

Bounds: regular input files only, <=65,536 bytes; <=64 offers; amount strings
<=4,096 characters; nonempty currency <=128 characters without whitespace;
0<=minPct<100 and 0<=maxPct<=1,000,000. A rounded zero lower bound is invalid.
The CLI has a five-second asynchronous import timeout. Synchronous computation
is bounded by these input caps; the timer cannot preempt synchronous JS or a
blocking filesystem. An untrusted SDK is executable code and outside this model.

## Fixtures and scope

`test.mjs` has explicit expected decimals derived from half-up examples, with
no independent reimplementation of SDK arithmetic. It covers inclusive ties,
non-ties, sub-precision offers, 1,000-digit canonical amounts, malformed and
noncanonical values, wrong currencies, input limits, entry hash failure, and
fresh-process recovery after errors. Tests import the actual SDK entry.
All evidence is local execution, not a live testnet result.

Sources read on 2026-10-22: local SDK README, RFQ guide, fixedPrice.ts and rfq.ts;
upstream HEAD `9d820e0f0fea0d9d34c6c0a2b521c18badfb4fee` fixedPrice.ts had the
same SHA-256 as the local source:
`ed755584f4f46541da8388f8ee58e5ecd381c0a4310ba1b2d3c108b2d45fec5f`.
See https://github.com/DACS-Agent-commerce/dacs-sdk/blob/9d820e0f0fea0d9d34c6c0a2b521c18badfb4fee/src/negotiate/fixedPrice.ts
and the sibling README.md and docs/rfq-negotiation-core.md.



See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
