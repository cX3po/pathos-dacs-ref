# spend-cap-restart vectors

Restart-survival vectors for wallet spend caps and reservations: a fresh
process over the durable spend-authority state may never see more headroom
than that state allows. Scenarios cover cumulative-cap denial across restart,
the inclusive cap boundary, headroom preservation after a denial, the
minimum-reserve floor and its boundary, and the per-order limit.

**Honest scope:** wallet spend caps and their denial reasons are an SDK-side,
pre-normative surface (`dacs-sdk src/rails/walletSpendAuthority{,Fs}.ts`) — no
DACS-Standard clause normatively defines them today. The vectors pin the SDK's
own declared policy contract; the quoted DACS-4 §9.5.1 retry/recovery clause
(pinned to DACS-Standard `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`) is the
Standard-side discipline this surface upholds: durable state, not process
memory, is the authority on what is already reserved. Balances are fixture
callbacks; no payment rail is imported; recovery authentication always
refuses; nothing signs, sends, or spends.

## Run

```sh
DACS_SDK_ROOT=/path/to/dacs-sdk npx tsx conformance/vectors/spend-cap-restart/runner.mts
```

Needs a trusted local dacs-sdk source checkout with installed dependencies
(default `~/dacs-sdk`; validated against SDK source commit
`557f417a77d6e0834a01a95524110e9aa2c483d9`). Every step runs in a fresh OS
process sharing only the durable state directory and its integrity key.
Exit 0 all vectors match; exit 1 any mismatch; exit 2 setup error.
