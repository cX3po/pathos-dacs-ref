/**
 * D402 merchant — gates GET /premium behind an on-chain payment.
 *
 * Run:
 *   RECIPIENT=<merchant-address> RPC=https://node2.demos.sh npx tsx server.mts
 *
 * The `d402Required` middleware does everything: returns 402 + a payment requirement
 * when there's no X-Payment-Proof header, verifies the proof on-chain when there is,
 * checks it matches (recipient + amount + resourceId), and only then calls the handler.
 * Verified against @kynesyslabs/demosdk v4.0.5.
 */
import express from 'express'
import { d402Required } from '@kynesyslabs/demosdk/d402/server'

const RPC = process.env.RPC ?? 'https://node2.demos.sh'
const RECIPIENT = process.env.RECIPIENT
if (!RECIPIENT) {
  console.error('Set RECIPIENT=<merchant-address> (where payments are sent).')
  process.exit(2)
}

const app = express()

app.get(
  '/premium',
  d402Required({
    amount: 5, // 5 DEM. number => DEM, decimal-string => OS (smallest unit). See README.
    resourceId: 'premium-report-001',
    rpcUrl: RPC,
    recipient: RECIPIENT,
    description: 'Premium market report',
    // cacheTTL: 300, // seconds a verified proof is cached (default 300)
  }),
  (req: any, res) => {
    // Reached ONLY after a verified, matching on-chain payment.
    // The middleware attaches the verified payment details:
    const paid = req.d402Payment // { from, to, amount, txHash }
    res.json({
      report: 'Premium content unlocked. (Replace with the real resource.)',
      paidBy: paid?.from,
      receipt: paid?.txHash,
    })
  },
)

app.listen(8402, () => {
  console.log(`D402 merchant on :8402 — GET /premium is payment-gated`)
  console.log(`  recipient=${RECIPIENT}  rpc=${RPC}`)
})
