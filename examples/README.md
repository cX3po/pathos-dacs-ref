# Six small Demos SDK examples

Six standalone experiments built with the real [DACS SDK](https://github.com/DACS-Agent-commerce/dacs-sdk). They use wallet-free testnet reads or local synthetic fixtures. They do not send transactions, fund wallets, or authorize purchases.

| Example | Shows | Mode |
|---|---|---|
| [Passport Diff](passport-diff/) | Snapshot and compare projected identity claims | Wallet-free testnet reads; synthetic diff tests |
| [Recipe Studio](recipe-studio/) | JSONPath, CSS, XPath and RE2 ParserSpec decisions | Detached local inputs; optional wallet-free testnet read |
| [Spend Simulator](spend-simulator/) | A durable spend cap survives a process restart | Synthetic balances and policy; optional wallet-free testnet read |
| [Quote Band Workbench](quote-band-workbench/) | Exact decimal negotiable price bands | Local synthetic prices |
| [Fault Theater](fault-theater/) | Signed bundle copies, tampering, and independent party roles | Local synthetic identities and evidence |
| [RFQ Restart Storyboard](rfq-restart-storyboard/) | Offer/counter/accept, crash recovery and dual signatures | Local synthetic authority and filesystem transport |

## Prerequisites

Linux, Git, Python 3.12+, Bun (tested 1.2.22), and Node ^20.19.0 or >=22.12.0. The SDK is a separate, trusted source checkout with its dependencies installed and `dist/` built. All six examples were tested against SDK source revision `557f417a77d6e0834a01a95524110e9aa2c483d9`. Follow the SDK's own README for its build requirements. Do not run these examples against an untrusted checkout: importing an SDK executes its code.

Set the SDK directory explicitly, then run from the root of this repository:

```sh
export DACS_SDK_ROOT=/path/to/trusted/dacs-sdk
bash examples/test-all.sh
```

`/path/to/trusted/dacs-sdk` is a placeholder for your existing built checkout. The test runner requires that directory and fails if it is missing. Quote Band Workbench additionally checks the pinned `fixedPrice.js` module hash documented in its README; rebuild from the declared SDK revision if it refuses a different build. The other examples report provenance without authenticating all dependencies.

Each example README gives its own commands, output meaning and limits. The test runner runs 73 offline tests across the six tools. It needs no wallet, credentials, network, or repository-wide dependency installation. It uses the declared SDK dependency checkout.

## Optional testnet observations

The test suite is offline. After it passes, these wallet-free commands read public testnet identity data:

```sh
bun examples/passport-diff/main.mjs snapshot 0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2 > before.json
bun examples/passport-diff/main.mjs snapshot 0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2 > after.json
bun examples/passport-diff/main.mjs diff before.json after.json
bun examples/recipe-studio/main.mjs demo
bun examples/spend-simulator/main.mjs --live
```

Only the tools' allowlisted testnet endpoints are accepted. RPC errors fail explicitly. A reset may remove the example identity or its claims; an empty result is not evidence of identity ownership or verified absence. RPC observations are unverified, and historical counts in example READMEs describe earlier measurements. Synthetic balances, identities, signatures and evidence are labelled; none establishes live settlement, finality, trusted roles or purchase authority. Never fund or reuse deterministic fixture keys.
