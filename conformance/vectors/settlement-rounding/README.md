# settlement-rounding vectors

Spec-derived conformance vectors for the DACS-3 §8.5.2 negotiable price band:
exact half-up rounding of each bound to the fractional digits of the CD-1
canonical band centre, inclusive boundaries, CD-1 canonicalisation of the
rounded bounds, refusal of noncanonical amounts (CORE §B.2), and rejection of
a computed lower bound ≤ 0. Clause text is quoted in `vectors.json`, pinned to
DACS-Standard revision `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`.

Expected values were derived independently from the quoted clause with
arbitrary-precision decimal arithmetic (half-up, quantized to the centre's
fractional digits, then CD-1-canonicalised) — never copied from SDK output.
One vector (`zero-amount-comparison-refused-sdk-contract`) pins an additional
SDK guard and is explicitly labeled as SDK contract, not clause-derived.

## Run

```sh
DACS_SDK_ROOT=/path/to/dacs-sdk npx tsx conformance/vectors/settlement-rounding/runner.mts
```

Needs a trusted local dacs-sdk source checkout with installed dependencies
(default `~/dacs-sdk`; validated against SDK source commit
`557f417a77d6e0834a01a95524110e9aa2c483d9`). The runner executes the real SDK
`negotiablePriceBand` / `isNegotiablePriceWithinBand` functions — pure
negotiation-price arithmetic. No network, no testnet, no wallet, no signing.
Exit 0 all vectors match; exit 1 any mismatch; exit 2 setup error.

**Honest scope:** this pins negotiation-time band arithmetic only. It is not
settlement-fee or rail-asset precision (`rail.asset.decimals`, DACS-4 §9),
not an authenticated Listing, and not a full §8.5.2 terms validator.
