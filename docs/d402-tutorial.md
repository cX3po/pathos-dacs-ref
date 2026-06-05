# D402 — Agent Commerce over HTTP 402 (tutorial + runnable example)

D402 gates any HTTP resource behind an **on-chain DEM payment**: a client (human or agent) requests
a resource, gets back `402 Payment Required` with the price, pays on Demos, and retries with the
payment proof to receive the resource. It's the agent-commerce settlement rung — the same shape PATH-OS
exercises as the DACS exchange step — exposed as drop-in Express middleware + a client SDK.

> Built against `@kynesyslabs/demosdk` (`d402/` module). All method names/signatures below are from
> the shipped `.d.ts`. Amounts use the P4 **dual-shape**: a JS `number` = pre-fork DEM, a decimal
> `string` = post-fork OS (1 DEM = 1e9 OS).

## The loop

```
client                                   server (d402Required)
  │  GET /resource                              │
  │ ───────────────────────────────────────────▶│  no x-payment-proof header
  │  402 Payment Required                        │
  │ ◀───────────────────────────────────────────│  body: D402PaymentRequirement
  │                                              │     { amount, recipient, resourceId, description? }
  │  createPayment(requirement) → settle()  ── on-chain ─┼──▶  DEM transfer to recipient
  │     → { success, hash, blockNumber }         │
  │  GET /resource   x-payment-proof: <hash>     │
  │ ───────────────────────────────────────────▶│  verifies the proof on-chain
  │  200 + the resource                          │  sets req.d402Payment, calls next()
  │ ◀───────────────────────────────────────────│
```

`D402Client.handlePaymentRequired()` does the middle three steps (pay → settle → retry) for you.

## Server — gate a route in 3 lines

```ts
import express from 'express';
import { d402Required } from '@kynesyslabs/demosdk/d402';

const app = express();

app.get(
  '/premium/report',
  d402Required({
    amount: 5,                       // 5 DEM (number = pre-fork DEM; use a decimal string for OS)
    resourceId: 'premium-report-001',
    rpcUrl: 'https://demosnode.discus.sh/',
    recipient: '0x…your-merchant-address',
  }),
  (req, res) => {
    // Only reached after an on-chain payment is verified.
    // req.d402Payment carries the verified payment details.
    res.json({ report: 'the paid-for content', paidBy: (req as any).d402Payment });
  }
);

app.listen(8080);
```

The middleware: with **no** `x-payment-proof` header → `402` + a `D402PaymentRequirement` body. With a
**valid** proof header → it verifies the payment on-chain, attaches `req.d402Payment`, and calls `next()`.
Invalid/insufficient → `403`. The server **never spends DEM** — it only verifies.

## Client — pay and retrieve

### Automatic (recommended)

```ts
import { Demos } from '@kynesyslabs/demosdk/websdk';
import { D402Client } from '@kynesyslabs/demosdk/d402';

const demos = new Demos();
await demos.connect('https://demosnode.discus.sh/');
await demos.connectWallet(process.env.BUYER_MNEMONIC!);

const d402 = new D402Client(demos);

// First call returns 402; read the requirement, then let the client pay + retry:
const first = await fetch('http://localhost:8080/premium/report');
const requirement = await first.json();                 // D402PaymentRequirement

const finalResponse = await d402.handlePaymentRequired(  // ⬅ on-chain DEM spent here
  requirement,
  'http://localhost:8080/premium/report'
);
console.log(await finalResponse.json());                 // the paid-for resource
```

### Manual (if you want the settlement receipt)

```ts
const payment = await d402.createPayment(requirement);   // unsigned d402_payment tx
const settlement = await d402.settle(payment);           // ⬅ broadcasts; spends DEM
// settlement: { success, hash, blockNumber?, message? }
if (!settlement.success) throw new Error(settlement.message);

const res = await fetch('http://localhost:8080/premium/report', {
  headers: { 'x-payment-proof': settlement.hash },       // the tx hash IS the proof
});
console.log(await res.json());
```

## Types (from the SDK)

```ts
interface D402PaymentRequirement { amount: number | string; recipient: string; resourceId: string; description?: string }
interface D402SettlementResult   { success: boolean; hash: string; blockNumber?: number; message?: string }
```

## Notes & gotchas

- **Proof = the tx hash**, sent in the `x-payment-proof` request header.
- **Amount dual-shape (P4):** `number` is pre-fork DEM; a decimal `string` is post-fork OS (1 DEM = 1e9 OS).
  Keep server and client on the same convention.
- **`settle()` / `handlePaymentRequired()` spend real DEM** — fund the buyer wallet first. `createPayment()`
  alone is unsigned and free.
- **Recipient** can be fixed in the middleware options, or per-request via `req.d402Recipient`.
- The server verifies on-chain via `rpcUrl`; during the network's audit-spring slowdown, point both sides
  at a healthy node.

---
*Contributed by PATH-OS — reference verifier + builder on Demos/DACS. Fills the D402 documentation
gap so any builder can stand up agent-commerce gating in minutes.*
