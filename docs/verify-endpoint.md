# d402-gated verification endpoint (`src/live/verify-endpoint.mts`)

The attestation-bundle verifier behind a Demos d402 payment gate: the parked N5. A caller
POSTs a bundle, gets a `402 Payment Required` naming the recipient, the amount in OS and a
`resourceId` bound to the SHA-256 of the exact request bytes, pays on Demos, and repeats the
same request with `X-Payment-Proof: <txHash>` to receive the verdict plus a receipt.

## Routes

| Route | Gate | Answer |
| --- | --- | --- |
| `POST /verify` | d402 | 402 `{amount, recipient, resourceId, description, reason}` until paid; then 200 `VerifyDocumentResult` + `receipt {txHash, from, amountOs, resourceId}` |
| `GET /healthz` | free | `{ok, name, version, apiVersion, priceDem, amountOs, recipient, offline}` |
| `GET /schemas/verify-request.json`, `/schemas/verify-verdict.json` | free | the packaged verifier's schemas |

Bodies over 1 MiB answer 413 before any gate, and a body that can never yield a verdict
answers 400 before any challenge, so nobody is asked to pay for it. A refused payment is 402
with the reason (`missing-proof`, `malformed-proof`, `unverifiable`, `mismatch`, `replayed`).
Three rules protect the payer:

- **Redelivery.** The same proof with the same request bytes after a delivered verdict is
  answered again (`receipt.redelivered: true`): from a bounded in-process cache while the
  verdict is there, by verifying again once it has been evicted (`receipt.reverified: true`).
  Never refused, never billed twice. The proof store and the cache live in this process only;
  after a restart the chain proof is accepted afresh, which is safe for the payer and means,
  for the operator, that one payment can buy one verification per process lifetime: durable
  single-use across restarts needs a persisted proof store, which this endpoint does not ship.
  A payment above the price is accepted as paid; nothing is refunded.
- **Not billed for the server's outage.** If a chain read fails on this server during
  verification, the answer is 503 with `proofRetained: true` and the proof reservation is
  released, so the same proof pays for the retry. The signal is the verifier handler's own
  `incomplete` flag, not the name of a verdict step, so a genuine verdict is always delivered.
  An indeterminate verdict about the bundle itself (an absent anchor, an unresolvable key) is
  an answer and is billed.
- **No downgrade.** The request's own `offline` and `requireSignatures` are ignored; the
  deployment decides what a paid verification is (`--offline` for archive-audit deployments).

Verdicts are never coerced: pass, fail or indeterminate come from the verifier's rollup.

## One implementation

Verification is `handleVerifyRequest()` from `src/lib/verify-http.ts`, the same handler the
packaged HTTP service (`packages/verifier/src/http.ts`) uses. The gate is
`createD402Service()` from `src/adapters/demos/d402-service.ts` with the seller-side
reserve-then-commit proof store (`src/live/d402-organ.mts`): a proof is committed only once
the verdict has been written to the socket, so a failed delivery does not consume a payment.

## Run

```
VERIFY_RECIPIENT=<merchant address> VERIFY_PRICE_DEM=0.1 VERIFY_PORT=8403 \
  node --import tsx src/live/verify-endpoint.mts            # add --offline for archive-audit deployments
node --import tsx src/live/verify-endpoint.mts --dry-run    # prints a sample challenge, no chain
```

`VERIFY_RECIPIENT` must be a Demos address (`0x` + 64 hex) and `VERIFY_PRICE_DEM` must be
greater than zero. `D402_RPC` (default `https://demosnode.discus.sh/`) is the Demos node used
both to verify payment proofs and for the verifier's anchor lookups; it is never taken from a
request.
`VERIFY_HOST` defaults to 127.0.0.1. There is no authentication beyond payment; expose the
port only where that is the intended door. An unpaid request still costs the server one
body read (at most `MAX_VERIFY_BODY_BYTES`) and one SHA-256 before the gate answers 402, and
sockets are cut at 10 s for headers and 30 s per request.

## Paying from a client

The first request answers 402. Pay the requirement with the Demos SDK d402 client (see
`examples/d402/client.mts`; in PATH-OS, `tools/demos_d402_pay.mjs` routes the amount through
the spend preflight and the pay-policy caps) and repeat the identical request with
`X-Payment-Proof: <txHash>`. The proof is bound to the recipient, the amount and the
`resourceId`, so it pays for exactly those request bytes once.

## Tests

`test/vectors/verify-endpoint.test.ts` runs the handler on a real local socket with a fake
payment verifier: challenge shape and body binding, the paid path with receipt and proof
commit, redelivery of the same paid request, cross-body reuse refused, underpayment and
payment-verifier outage as 402 reasons, malformed bodies refused before any challenge, a
server-side chain failure answering 503 with the proof retained and the retry billed once,
three concurrent requests with one proof billed once, request-level downgrade ignored, free
healthz/schemas, 413, forced offline, and the config and `--dry-run` CLI paths. No network.

## Confirming payments on the testnet node

`D402Server.verify` in `@kynesyslabs/demosdk` 4.0.16 calls `POST <rpc>/getTransaction` and
`POST <rpc>/d402/verify`, routes the testnet node `demosnode.discus.sh` does not serve (404;
its RPC reports `getTransaction` as not implemented), so it answers `valid:false` for every
real payment. The endpoint therefore confirms payments with
`src/adapters/demos/d402-node-verifier.ts`, which reads the transaction through the node's
`getTxByHash` and checks type `d402_payment`, inclusion in a block (a positive `blockNumber`),
the hash echo, no negative status word from the node, and then recipient, amount floor and the
`resourceId:` memo prefix. A node error is `valid:false`, so the gate answers 402 `unverifiable`
rather than failing. Trust model: the configured node is trusted for inclusion; the verifier
does not check the transaction signature itself and does not wait for confirmation depth, which
is the testnet posture. A payer equal to the recipient is accepted (the gate prices the work, not
the counterparty); an absent payer is refused.

## Observed on 2026-09-03 (testnet, demosdk 4.0.16)

- After `D402Client.createPayment(requirement)` the transaction's outer `content.to` is empty
  (`""`) while `content.data[1].to` carries the recipient, and `Demos.sign` rejects it with
  `Invalid To address: 0x`. Setting `content.to` to the recipient before signing makes `sign`
  succeed. `src/demos/storage.ts` works around the same sign-side check for storage programs
  by using the dedicated program flow; the PATH-OS pay tool sets `content.to` at the call
  site. Whether the SDK or its callers should set the field is not confirmed upstream and has
  not been reported there.
- With that, a 0.1 DEM payment for a real challenge settled (hash `887cdf41…`, block 222221),
  the same request with `X-Payment-Proof` answered 200 with a receipt, the request repeated
  was redelivered, and the same proof for a different body was refused. The verdict was
  indeterminate because the fixture bundle is not anchored on chain and the deployment ignores
  a payer's `offline` flag, which is the intended answer.
