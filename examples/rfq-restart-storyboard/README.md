# RFQ Restart Storyboard — LOCAL TRANSPORT ONLY

A transport-neutral RFQ example using the actual DACS SDK. No RPC,
wallet, chain write, payment or live Demos encrypted/signature wire is installed.
Identity, Vet, Listing verification and time are explicitly **synthetic**.
`disposition: verified` is fixture authority, not a verification result. The quoted
USDC denomination is a string in the Listing; no USDC is held or transferred.

Requires Linux, Bun (tested 1.2.22), and a trusted local `~/dacs-sdk` checkout with
its dependencies already installed. Tested SDK commit:
`557f417a77d6e0834a01a95524110e9aa2c483d9`.
`DACS_SDK_ROOT=/absolute/trusted/checkout` selects another SDK source tree.
No dependency download is performed. The example imports SDK TypeScript directly;
it does not copy SDK logic or use a mocked RFQ state machine.

From this directory:

```sh
~/.bun/bin/bun main.mjs
~/.bun/bin/bun test ./test.mjs
```

From this repository root:

```sh
bun test ./examples/rfq-restart-storyboard/test.mjs
```

The first command emits a public transcript, exact finalized agreement, agreement
hash and process evidence. It exits nonzero on any failed assertion. Private
runtime files are created in a fresh 0700 temporary root and removed in `finally`.
No secrets appear in arguments or reports. A hard kill of the top-level runner
can leave that temporary directory behind; preserve it for investigation and
remove only that inspected `demosspeed6-*` directory when finished.

## Three turns and two signatures

1. Buyer proposes 9 USDC and exits **86 after durable local publish, before ack**.
2. A fresh buyer process resumes the outbox, reconciles the exact packet and
   does not sign another turn. Seller receives the offer. Another fresh seller
   process replays it: `duplicate`, with unchanged revision and transcript.
3. Seller counters at 9.5; buyer receives and accepts sequence 2. Seller receives
   the acceptance. Both transcripts contain exactly offer, counter, accept.

Buyer then derives a signing plan; seller independently rederives/verifies it
and contributes its own Ed25519 signature. Buyer receives that contribution.
Both role stores must contain the **identical dual-signed agreement**. The runner
also calls `deriveRfqAgreement` directly and compares every unsigned field to the
final artifact, including the exact accepted 9.5 USDC price.

`createDurableRfqLifecycleClient` calls real `openRfqSession` on open,
`advanceRfqSession` on local and incoming turns, and `deriveRfqAgreement` during
agreement exchange. Persistence uses `createFsDurableRfqLifecycleStore`.
Every operation runs in a newly spawned OS process. A fixed synthetic clock
keeps this tutorial repeatable; timeout tests deliberately move it past 10s.
It is not production timekeeping or a live testnet result.

## Local transport and persistence boundary

Buyer and seller have separate 0700 store directories, separate random 32-byte
integrity keys and separate Ed25519 signing keys. Restart reloads **its existing
role key**; keys are never regenerated to make unreadable state look fresh.
Buyer and seller never share an integrity key. Public key pins are local bootstrap
trust, not Demos identity proofs. The same Unix account controls the whole demo;
role separation is directory/key separation, not OS-level hostile-process isolation.

Transport is an explicitly local durable filesystem spool with packets relayed
by the test runner over JSON stdin/stdout. It is not encrypted; use only synthetic
content. An immutable packet is synced into a temporary inode and linked without
overwrite; the containing directory is synced before acknowledgement. Reconcile
acknowledges only exact bytes, permits retry only on ENOENT, and otherwise returns
indeterminate. Interrupted temporary files are ignored. Packet reads permit extra hard links
within this trusted local spool so a crash immediately after link is recoverable;
key reads continue to require a single link. Both sides of link are crash-tested. The SDK persists session,
transcript and packet before publish and uses its authenticated CAS store/locks.
A role-local immutable reservation binds the one synthetic channel to the exact
session. This tutorial supports only its single fixed job and channel per run.

Each child has a 12s hard deadline and 256KiB input/output bounds; the hung-publish
probe uses 1.5s. Wrong keys, altered signed packets, corrupted state, failed
transport, invalid proposals and protocol timeout are tested. Unknown/corrupt
state is refused, never reset. No passphrase is used.

For a production adapter, supply actual independently verified Listing/Vet/party
authority, real trusted clocks, separate custody and a specified confidential
member transport. The live Demos signature and encrypted transcript wire remain
undefined here; this example does not propose a substitute upstream protocol.



See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
