# D402 organ engine seller

`src/live/d402-organ.mts` exposes organ answers behind a framework-free HTTP 402
payment gate. It uses Node's built-in HTTP server and the Demos SDK verifier.

## Run the seller

Set a recipient and start the endpoint:

```bash
D402_RECIPIENT=<merchant-address> \
  node --import tsx src/live/d402-organ.mts
```

Configuration:

- `D402_RECIPIENT` is required. Startup exits with status 2 when it is absent.
- `D402_RPC` defaults to `https://demosnode.discus.sh/`.
- `D402_PORT` defaults to `8402`.
- `D402_PRICE_DEM` defaults to the canonical DEM string `1`.
- `AXIOM_PY` defaults to `python3`, and `ORGAN_CLI` defaults to
  `organ_answer.py`.
- `D402_ORGANS` is a comma-separated allowlist and defaults to `nws_alerts`.

The configured DEM price is converted without floating point and put in the 402
requirement as a decimal-string **OS** amount. One DEM is 1,000,000,000 OS.

Request an allowed organ with a query:

```bash
curl 'http://localhost:8402/engines/organ/nws_alerts?q=39.7684,-86.1581'
```

The first response is `402 Payment Required` with an object containing `amount`,
`recipient`, `resourceId`, and `description`. The resource ID includes the first
16 hexadecimal characters of SHA-256 over the exact `q` value, binding payment
to that query.

## Payment header and verification

After settling the requirement on Demos, retry the same URL with the transaction
hash:

```http
X-Payment-Proof: <hex-transaction-hash>
```

Header names are case-insensitive. A valid proof must verify on-chain and match
the recipient exactly, pay at least the required amount after DEM/OS
normalization, and have a memo beginning with `resourceId:<required-id>`. Missing,
malformed, unverifiable, mismatched, and replayed proofs all fail closed with a
402 response; verifier and RPC failures never disclose the organ content or turn
into a 5xx response. Verification is bounded by a 15-second deadline.

A transaction hash can unlock a given resource ID only once. The seller reserves
a verified proof while its organ process runs and releases the reservation if
the CLI times out or fails before a response is written. Once the seller writes
the 200 headers, it commits the replay record permanently before handing body
bytes to the HTTP stream, even if the client disconnects. Concurrent requests
cannot reuse a reserved or committed proof. Replay stores are capped and fail
closed when full.

Successful responses contain the organ fields plus a receipt with `txHash`,
`from`, and `amountOs`. `commitment_nonce` is deliberately excluded from every
buyer response.

## Dry run and buyer

Check configuration and print a sample 402 requirement without an RPC call:

```bash
D402_RECIPIENT=<merchant-address> \
  node --import tsx src/live/d402-organ.mts --dry-run
```

`D402_DRY_RUN=1` is equivalent. For the complete buyer flow—receive the 402,
create and settle the payment, then retry with `X-Payment-Proof`—see
[`examples/d402/client.mts`](../examples/d402/client.mts).
