# rfq-restart-no-dup vectors

Restart and replay vectors for RFQ negotiation: a sender that crashed after a
durable publish resumes the exact signed packet (never signs a second turn for
the same sequence), a replayed packet is recognised as a duplicate with
revision and transcript unchanged, and a full offer → counter → accept flow
ends with identical three-turn transcripts and one identical dual-signed
agreement in both roles — with every lifecycle action in a fresh OS process.

Clause basis (quoted in `vectors.json`, pinned to DACS-Standard
`4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`): DACS-3 §8.3.3 (envelope
`sequence` monotonic per channel), §8.12 (same-channel replay duplicates a
sequence number and is rejected), CH-6 (per-session channelId uniqueness).

**Honest scope:** the durable RFQ lifecycle is an SDK surface
(`dacs-sdk src/negotiate/durableRfqLifecycle{,StoreFs}.ts`). Identity, Vet and
Listing authority here are synthetic fixtures (`disposition: verified` is
asserted, not verified); transport is a local file spool, not the Demos
encrypted wire; signatures are local Ed25519 over the SDK envelope hash, not a
Demos wire format; the clock is fixed. No network, no testnet, no payment.

## Run

```sh
DACS_SDK_ROOT=/path/to/dacs-sdk npx tsx conformance/vectors/rfq-restart-no-dup/runner.mts
```

Needs a trusted local dacs-sdk source checkout with installed dependencies
(default `~/dacs-sdk`; validated against SDK source commit
`557f417a77d6e0834a01a95524110e9aa2c483d9`).
Exit 0 all vectors match; exit 1 any mismatch; exit 2 setup error.
