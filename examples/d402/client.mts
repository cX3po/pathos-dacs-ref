/**
 * D402 paying agent — fetch a gated resource, pay on 402, get the content.
 *
 * Run (wallet MUST be funded — see README Step 0):
 *   MNEMONIC="<funded wallet mnemonic>" RPC=https://node2.demos.sh \
 *     RESOURCE=http://localhost:8402/premium npx tsx client.mts
 *
 * Shows both the one-call path (handlePaymentRequired) and, commented, the three
 * primitives it wraps (createPayment → settle → retry). Verified against
 * @kynesyslabs/demosdk v4.0.5.
 */
import { Demos } from '@kynesyslabs/demosdk/websdk'
import { D402Client } from '@kynesyslabs/demosdk/d402'

const RPC = process.env.RPC ?? 'https://node2.demos.sh'
const RESOURCE = process.env.RESOURCE ?? 'http://localhost:8402/premium'
const MNEMONIC = process.env.MNEMONIC
if (!MNEMONIC) {
  console.error('Set MNEMONIC="<funded wallet mnemonic>" (see README Step 0 — fund first).')
  process.exit(2)
}

async function main() {
  const demos = new Demos()
  await demos.connect(RPC)
  await demos.connectWallet(MNEMONIC!) // funded wallet — nonce-0/unfunded fails (README Step 0)

  // 1. Try the resource. Expect 402 the first time.
  const first = await fetch(RESOURCE)
  if (first.status !== 402) {
    console.log(`Resource returned ${first.status} (no payment needed?):`, await first.text())
    return
  }

  const requirement = await first.json() // { amount, recipient, resourceId, description? }
  console.log('402 Payment Required:', requirement)

  const d402 = new D402Client(demos)

  // 2. One call: createPayment → settle (sign + broadcastNativeTransaction) → retry
  //    the original request with header  X-Payment-Proof: <txHash>.
  const paidResponse = await d402.handlePaymentRequired(requirement, RESOURCE, { method: 'GET' })

  console.log(`Unlocked (${paidResponse.status}):`, await paidResponse.json())

  // --- The same flow, broken into the three primitives (if you need the receipt
  //     hash before retrying, or want custom retry logic):
  //
  //   const tx     = await d402.createPayment(requirement)        // unsigned d402_payment
  //   const result = await d402.settle(tx)                         // { success, hash, blockNumber? }
  //   if (!result.success) throw new Error(result.message)
  //   console.log('receipt (txHash):', result.hash)                // <-- verifiable on-chain
  //   const res = await fetch(RESOURCE, { headers: { 'X-Payment-Proof': result.hash } })
}

main().catch((e) => {
  console.error('D402 client error:', e?.message ?? e)
  process.exit(1)
})
