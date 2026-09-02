# DACS Organ Gateway — live seller on the Demos devnet

Sells a PATH-OS proof-organ answer through a full **DACS-1→5** session on the
sanctioned v0.1 machinery — real signed listing, both-party signed + anchored
agreement, **pay-dem** (§9.5.9, exact `included` + block-witness `bft-final`) settlement, **deliver-storage-program**
(§9.6.1) delivery of the organ answer, and two-sided `AttestationBundleV1`
anchoring verified ENFORCING by `verifyBundleV1Full`.

First good: `nws_alerts` — severe-weather severity band near a committed point.
The raw feed + location are bound by a keyed HMAC commitment (nonce never
anchored); only the category-band answer is disclosed.

## Run

```bash
npx tsx src/live/organ-gateway.mts                 # dry-run (default): no chain writes, no funds
LIVE=1 npx tsx src/live/organ-gateway.mts          # real devnet session (~6-7 DEM in fees/writes)
```

Live mode needs in `~/axiom/.env`: `DEMOS_MNEMONIC` (buyer, funded) and
`DEMOS_SELLER_MNEMONIC` (seller). Exit 0 iff the bundle verification rollup is PASS.

## Files
- `organ-gateway.mts` — the DACS-1→5 orchestrator (dry-run + live)
- `../adapters/dacs/pay-dem.ts` — SDK-faithful native-DEM adapter; only exact
  `included` with a block-number witness can emit `bft-final` evidence
- `anchor-naming.ts` — Demos substrate-equivalent anchor addressing (name-based,
  owner-checked resolution — see the §10.4.3 "substrate-equivalent" note inside)
- axiom-side bridge: `~/axiom/tools/organ_answer.py` (organ answer + keyed commitment)

## Honest scope
- cci primary claims are per-run ed25519 keys recorded in the anchored artifacts;
  durable gateway identities + listing discovery/indexing are the next slice.
- Dry-run artifacts are self-labelled (`organ-gw-dry-…` jobIds, `dry-…` locators,
  `demos:DRYRUN-…` tx refs) and never leave the process.
- Review: Codex NEEDS REVISION → all findings fixed → APPROVED (2026-07-07).
