# DACS commerce showcase (reference backend)

A runnable backend for the "**two agents doing commerce on Telegram**" showcase: a
**Vendor** (seller) and a **Shopper** (buyer) execute a full **DACS-1 → DACS-5**
commerce session on this reference implementation, producing **real signed,
content-addressed artifacts** at every stage and a two-sided `AttestationBundle`
that `verifyBundle` **PASSES**.

## Run
```bash
npx tsx src/showcase/demo.ts
```
Console mode by default (no setup, no funds, no network). Exits 0 only if **both**
buyer and seller bundles verify PASS.

## Telegram mode
Set bot tokens + a group id and it posts each agent's turn to the group (Vendor
turns from the Vendor bot, Shopper from the Shopper bot, stage headers from the
Narrator bot — via the Telegram Bot API over `fetch`, no extra deps):
```
SHOWCASE_VENDOR_BOT_TOKEN=...   SHOWCASE_SHOPPER_BOT_TOKEN=...   SHOWCASE_NARRATOR_BOT_TOKEN=...
SHOWCASE_TG_GROUP_ID=...        npx tsx src/showcase/demo.ts
```
Create the three bots via BotFather; add them to the group.

**Honest constraint:** Telegram bots can't read each other's messages in a group,
so this is backend-coordinated DACS traffic *displayed* per-agent — not bots
literally reading each other. That's the only buildable shape, and the protocol
traffic underneath is real.

## Settlement
Defaults to a deterministic **mock** (`mock-settle.ts`) — no keys, no funds, so it
runs anywhere. Set `SHOWCASE_SETTLE=testnet` (and wire `settle/htlc-testnet.ts`)
to settle for real over Base Sepolia + Solana devnet via the reference impl's HTLC
evidence.

## Files
- `flow.ts` — the Vendor↔Shopper DACS-1→5 orchestrator (produces the artifacts + verified bundles)
- `mock-settle.ts` — deterministic mock SettlementEvidence
- `display.ts` — renders each stage to console / Telegram
- `config.ts` — env-driven, surface-agnostic
- `demo.ts` — entry point

## Scope (no overclaiming)
Proves the artifact + verification shape end-to-end on the reference impl. It is
**not** live on-chain (mock settlement) and uses local keypairs, not deployed
identities — by design, so the demo runs with zero setup. Phasing: P0 (here) over
`secure-channel` + mock; P1 real HTLC testnet; P2 SR-4 L2PS once that lands.
