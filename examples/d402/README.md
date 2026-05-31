# D402 — agent pays for a gated resource (end-to-end)

> A runnable reference for the **D402** HTTP-402 agent-payment loop in
> `@kynesyslabs/demosdk` (verified against **v4.0.5** source). An agent requests a
> paid resource, gets `402 Payment Required`, **pays on-chain**, retries with the
> payment proof, and receives the content — with a **verifiable on-chain receipt**.
>
> *Contributed by [pathos-dacs-ref](../../README.md). The D402 client/server/middleware
> are fully implemented in the SDK; this fills the missing end-to-end "zero → paid"
> walkthrough.*

## The flow

```
  agent (D402Client)                         merchant (d402Required middleware)
  ─────────────────                          ─────────────────────────────────
  GET /premium  ───────────────────────────►  no X-Payment-Proof header
                ◄───────────────────────────  402  { amount, recipient, resourceId }
  createPayment(requirement)  →  d402_payment tx
  settle(tx)  →  sign + broadcastNativeTransaction  →  on-chain  →  { hash }
  GET /premium  (X-Payment-Proof: <hash>) ──►  D402Server.verify(hash)
                                                getTransaction → d402/verify → validate
                ◄───────────────────────────  200  { the content }   (+ req.d402Payment)
```

The `<hash>` is the **receipt**: anyone can re-verify the payment on-chain later — no
trust in the merchant, no payment processor in the middle.

## Prerequisites

```bash
npm install @kynesyslabs/demosdk express
npm install -D tsx @types/express
```
- A reachable Demos node RPC — e.g. `https://node2.demos.sh` (live testnet at time of writing).
- **A funded wallet for the agent** (see Step 0 — this is the easy thing to miss).

## Step 0 — fund the agent wallet (the gotcha)

A brand-new wallet has **nonce 0 and no on-chain history**. On a fresh wallet, a
transaction (and some auth endpoints) can fail in ways that *look* like a signature
error but are really "this address has never transacted." **Fund first, then transact.**

```bash
# generate + fund (use your faucet flow); confirm balance/nonce before paying:
#   demos.getAddressNonce(pubkeyHex)  should be >= 0 and the address must be funded
```
If a payment fails immediately on a new wallet, check funding before anything else.

## Step 1 — run the merchant (gates `/premium` behind a 5-DEM payment)

```bash
RECIPIENT=<merchant-address> RPC=https://node2.demos.sh npx tsx server.mts
# → listening on :8402 ; GET /premium is now payment-gated
```
See [`server.mts`](./server.mts). The whole gate is one middleware:

```ts
import express from 'express'
import { d402Required } from '@kynesyslabs/demosdk/d402/server'

app.get('/premium',
  d402Required({
    amount: 5,                       // 5 DEM — number (DEM) | decimal-string (OS), see note
    resourceId: 'premium-report-001',
    rpcUrl: process.env.RPC!,
    recipient: process.env.RECIPIENT!,
    description: 'Premium market report',
  }),
  (req, res) => {
    // reached ONLY after a verified, matching on-chain payment.
    // req.d402Payment = { from, to, amount, txHash }
    res.json({ report: 'Premium content…', paidBy: (req as any).d402Payment.from })
  },
)
```

## Step 2 — run the paying agent

```bash
MNEMONIC="<funded wallet mnemonic>" RPC=https://node2.demos.sh \
  RESOURCE=http://localhost:8402/premium npx tsx client.mts
```
See [`client.mts`](./client.mts). The agent does the full loop with `D402Client`:

```ts
import { Demos } from '@kynesyslabs/demosdk/websdk'
import { D402Client } from '@kynesyslabs/demosdk/d402'

const demos = new Demos()
await demos.connect(process.env.RPC!)
await demos.connectWallet(process.env.MNEMONIC!)   // funded wallet (Step 0)

const res = await fetch(process.env.RESOURCE!)
if (res.status === 402) {
  const requirement = await res.json()             // { amount, recipient, resourceId, description? }
  const d402 = new D402Client(demos)
  // one call: createPayment → settle (sign + broadcast) → retry with X-Payment-Proof
  const paid = await d402.handlePaymentRequired(requirement, process.env.RESOURCE!, { method: 'GET' })
  console.log(await paid.json())                   // the unlocked content
}
```

`handlePaymentRequired` wraps the three primitives if you want them separately:
`createPayment(requirement) → settle(tx) → { hash } → re-fetch with header
X-Payment-Proof: <hash>`.

## What you get
- **The content**, gated behind a real on-chain payment.
- **`txHash`** = a verifiable receipt. Re-verify any time:
  `new D402Server({ rpcUrl }).verify(txHash)` → `{ valid, verified_from, verified_to, verified_amount, … }`.
- **No intermediary**: the merchant verifies the payment directly against the chain.

## Notes (verified against SDK v4.0.5 source)
- **Amount is dual-shape** (P4 osDenomination migration): pass a **`number`** for whole/
  fractional **DEM**, or a **decimal `string`** for **OS** (smallest unit). The server
  normalizes via `demToOs` / `parseOsString`; normalize with `BigInt(...)` before arithmetic.
- **Header is `X-Payment-Proof`** (client sets it; the Express middleware reads `x-payment-proof`).
- **Settlement** is `demos.nodeCall('broadcastNativeTransaction', { transaction })`; the
  `d402_payment` tx carries `data = ['d402_payment', { to, amount, memo }]` with
  `memo = "resourceId:<id> - <description>"` (the server validates the resourceId match).
- **Verification** hits `${rpcUrl}/getTransaction` then `${rpcUrl}/d402/verify`; results are
  cached `cacheTTL` seconds (default 300).
- **Middleware verdicts:** missing proof → `402` + requirement; bad proof → `403`; proof that
  doesn't match the requirement → `403` with `details`; valid → `next()` + `req.d402Payment`.

## Found while writing this
`src/d402/client/D402Client.ts:17` — the constructor line `constructor(demos: Demos) {`` `
carries a stray empty template-literal (``` `` ```) after the brace. It's valid (a no-op
expression statement) but is clearly an editor artifact; worth removing for cleanliness.
