# Mainnet Readiness Kit — conformance vector families

Spec-derived DACS conformance vectors with runners that execute the real
dacs-sdk, in three families:

| Family | Pins | Spec basis |
|---|---|---|
| [`settlement-rounding/`](settlement-rounding/) | exact half-up negotiable band bounds, inclusive boundaries, CD-1 refusals | DACS-3 §8.5.2, CORE §B.2 |
| [`spend-cap-restart/`](spend-cap-restart/) | spend caps/reservations enforced across process restarts | DACS-4 §9.5.1 discipline; SDK surface, labeled pre-normative |
| [`rfq-restart-no-dup/`](rfq-restart-no-dup/) | crash-resume reuses the exact signed packet; replay is a duplicate with no state change | DACS-3 §8.3.3, §8.12, CH-6 |

Each family is a `vectors.json` (expected outcomes with quoted spec clauses,
pinned to DACS-Standard revision `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`)
plus a `runner.mts` and a `README.md` with its honest scope. Vectors claim
nothing beyond what they test: no mainnet readiness, no full-DACS conformance,
no payment execution, no authenticated identity.

## Setup

From the repository root of `cX3po/pathos-dacs-ref` (Node 20+):

```sh
npm ci --no-audit --no-fund
```

## Verify offline (no dacs-sdk checkout needed)

```sh
npx tsc --noEmit
npx tsx --test test/vectors/mainnet-kit-vectors.test.ts
```

The structural test validates every family's `vectors.json` (unique names,
quoted-clause pins, CD-1 well-formedness of expected amounts, declared denial
reasons) and runs in CI without an SDK checkout or network access.

## Execute the vectors against the SDK

Executing the runners additionally requires a trusted local dacs-sdk **source**
checkout with its own dependencies installed. `DACS_SDK_ROOT` selects it; when
unset, the runners default to `~/dacs-sdk`. Validated against SDK source commit
`557f417a77d6e0834a01a95524110e9aa2c483d9`.

```sh
DACS_SDK_ROOT=/path/to/dacs-sdk npx tsx conformance/vectors/run-all.mts
```

or a single family, e.g.:

```sh
DACS_SDK_ROOT=/path/to/dacs-sdk npx tsx conformance/vectors/settlement-rounding/runner.mts
```

Exit codes, all runners: **0** every vector matched; **1** at least one
mismatch; **2** setup error (missing SDK modules, temp-dir failure). Without a
valid `DACS_SDK_ROOT` the runners exit 2 with a message — that is the designed
behaviour, not a vector failure. No runner touches the network, a testnet, a
wallet, or a payment rail; fixtures are synthetic and labeled in each family's
README.
