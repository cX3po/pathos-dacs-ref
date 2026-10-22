# Spend Simulator

A local safety demonstration using the real DACS wallet spend authority and authenticated filesystem store. A first Bun process reserves 60 synthetic base units under a cumulative cap of 100. A fresh second process opens the durable store and refuses a reservation of 50 with `cumulative-limit`, preserving reserved debit 60 and headroom 40. Nothing begins or executes a payment.

From this directory, with Bun 1.3.4 and the existing `~/dacs-sdk` source checkout and its installed dependencies:

```sh
bun test ./test.mjs
bun main.mjs --offline
bun main.mjs --live
```

`DACS_SDK_ROOT=/absolute/path/to/dacs-sdk` overrides the checkout location. Snap Bun's `SNAP_REAL_HOME` is respected. Source revision tested: `557f417a77d6e0834a01a95524110e9aa2c483d9` (`@kynesyslabs/dacs` 0.1.0-alpha.0); native Demos peer installed there is 4.0.16. This intentionally uses source modules via Bun, because the local Node ESM native peer packaging does not run reliably. No npm registry publication is assumed.

Live mode reads the public example DID with the SDK's `createAgent().resolveIdentity()`. Exact HTTPS testnet origins `https://node2.demos.sh` (default) and `https://demosnode.discus.sh` are accepted; choose the second with `DEMOS_RPC=https://demosnode.discus.sh bun main.mjs --live`. Subject equality and a bounded claim count are checked. The RPC result supplies contextual provenance in the report. It is an unverified RPC observation, and does not establish chain authenticity, balance authenticity, funded authorization, or identity ownership. On the measured live run the canonical subject matched and claims were empty.

Balances (1000 synthetic units, or 150 in the minimum-reserve probe), wallet, chain binding, counterparty, policy, agreement and settlement hashes, and finality model are explicitly synthetic. No payment rail is imported by the simulation; no wallet is created, connected, or funded. Recovery authentication always returns false; no settlement or absence claim can release budget. The CLI never reads `.env`, key material, or real balances and never signs, sends transactions, calls faucets, or changes services.

Every run creates its own private temporary directory. Its random 32-byte HMAC integrity key is stored in a separate 0600 file outside the SDK state directory; the key is never printed or passed in argv. This key authenticates simulated storage only, and is not a wallet key. The independently launched workers read the same private key file; all temporary files are removed after that run. The example is deliberately not an installed persistent wallet policy service. Erasing the whole temporary run erases its policy history; production callers must preserve the store, markers, and independently protected integrity key.

Tests execute the real SDK in separate processes: restart cap retention, minimum reserve denial, missing state after initialization, valid-JSON state tampering, changed integrity key, and hostile endpoint/subject inputs. Workers have a 12-second kill deadline, bounded input/output, and the full CLI has a 25-second hard deadline. Network responses remain governed by SDK parsing before the bounded projection; the CLI deadline bounds total runtime. Live mode exits nonzero on an unreachable RPC or subject mismatch; offline mode makes no network calls.


See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
