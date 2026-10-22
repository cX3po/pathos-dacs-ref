# Fault Theater

Local, signed two-sided fault-bundle gallery using the actual DACS SDK. All identities, evidence pointers, timestamps, transactions and authority inputs are synthetic. There are no RPC reads, chain writes, wallets, funds or network calls. This is not a live testnet result.

From the repository root, with Python 3.12+, Bun 1.2.22 and a trusted local `~/dacs-sdk` checkout with its dependencies already installed:

```bash
timeout 30s bun examples/fault-theater/main.mjs
cd examples/fault-theater
timeout 30s bun test ./test.mjs
```

Set `DACS_SDK_ROOT` to another trusted SDK checkout if needed. The implementation imports SDK TypeScript directly, not an imitation or stale built distribution. The JSON report records the SDK git HEAD; it does not attest the cleanliness of that checkout or dependency provenance. Validated against SDK commit `557f417a77d6e0834a01a95524110e9aa2c483d9`.

Open `gallery.html` as a local file; it is a standalone, script-free report with all signed fixtures embedded. `fixtures.json` retains the exact six signed bundle copies. `bun main.mjs --generate` exclusively creates those two files if absent and refuses to overwrite existing ones. If interrupted between those writes, the first file may remain; inspect and retain it, then generate again in a fresh repository checkout. No persistent lock, lane reservation, payment state or service exists.

The gallery includes completed buyer/seller copies, two role-relative copies of a buyer self-abort, and newly signed copies whose local party labels have been swapped. The latter are valid signatures over producer assertions, not a trusted assignment of real-world roles. This differs from editing signed bytes without re-signing, which fails signature validation.

For the scored synthetic buyer, the SDK reports counterparty fault rate 0 with the independent per-job role map and 1 with the deliberately unsafe SDK `trustBundlePartyRoles` compatibility path. An unresolved role map excludes the job and yields null, not a clean score. A one-sided copy needs explicit authoritative absence; the helper defaults to indeterminate and transport uncertainty excludes it. The local absence callback models that authority only and proves nothing about a substrate.

The gallery rows pass the buyer/seller slot as independent synthetic address-role context to SDK `verifyBundleCopy`, which verifies shape, role-address consistency and Ed25519 signatures. The scoring helper uses the copy’s asserted anchor role for signature eligibility; it does not independently authenticate an address. The actual `deriveReputationWithValidation` applies the independent role resolver. Keys are public deterministic fixture material derived from a clearly marked test namespace; never fund or reuse them. Synthetic identity bundle hashes are placeholders, not verified IdentityBundles. Referenced listing/agreement/evidence bytes, anchors, execution, lifecycle and finality are not resolved or authenticated. A production consumer must establish those independently and must not derive its role map from these bundles.

The bundled bounded Python helper supplies five synthetic mutation cases: finality removal, chain identity replacement, content change, forged vet reference and damaged role signature. Every original passes and every mutation is refused. Rejection is a copy-validation result; it does not resolve evidence or disprove a payment on-chain.

Failure probes also cover wrong/unresolved keys, thrown verification, role confusion, unresolved/thrown/Promise role authorities, indeterminate absence, process failure and recovery, unknown CLI flags, deterministic fixture reproduction and HTML escaping. The mutation bridge has a 10-second subprocess deadline and 1 MiB output bound. Run the CLI under the documented external 30-second deadline to bound SDK startup as well.


See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
