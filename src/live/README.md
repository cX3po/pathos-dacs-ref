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

## Wrapped text anchors

String SR-2 payloads are stored with JSON encoding as
`{"v":"dacs-ref-text:1","text":"<original string>"}`. This works around Demos node
0.9.8 (stabilisation) behaviour observed on 2026-09-02: binary-encoded storage
programs were accepted for propagation but never included. Read-back is transparent:
`fetchAnchored()` returns the exact original string and marks the result `wrapped: true`.
The live canary can still reproduce the affected path with `ANCHOR_ENCODING=binary`.

The node's `searchStoragePrograms` name index can lag immediately after an anchor is
included. Post-anchor gateway checks therefore read each bundle copy by the `stor-`
address returned by `anchor()` first, then fall back to exact owner/name resolution
with a bounded retry window (at most 50 seconds); an RPC error remains indeterminate
and is never interpreted as an absent party anchor.

## DACS testnet coordinator

`dacs-testnet-run.mts` is a second entry point. It does not import
`organ-gateway.mts`, whose top-level session executes on import. It retains the
gateway's organ, query, fixed DEM price, and pipeline terms, then delegates
agreement commitment and bundle finalization to the receipt-enforcing adapters.

`--dry-run` is the explicit default. It uses public deterministic fixture keys,
one in-memory store indexed by logical and native address, simulated payment and
delivery, finalized fixture receipts, and cold verification of the agreement and
both bundle copies. Its dependency `capabilityPreflight` is intentionally a no-op.
`LIVE=1` selects LIVE; combining it with `--dry-run`, or using
`--fixture-seed` in LIVE, is a usage error. LIVE also requires
`GATEWAY_LIVE_APPROVED=1` and the exact parameter hash from a passing dry run.

Exit 0 means both cold verifiers passed. Exit 1 means a phase failed or either
verifier failed or was indeterminate. Exit 2 means usage, configuration, payment
policy, spend preflight, or LIVE capability refusal. With no `DACS_PAY_POLICY`, LIVE
exits 2 with reason `policy`. With an allowing testnet policy, LIVE resolves its
journal, completes native-payment authorization, constructs the durable journals
and authorization gate, checks the exact dry-run hash, then exits 2 with reason
`capability` at the CORE §5.1 check, before dotenv or credentials are loaded,
unless the run names a finality-proving receipt source. The default observer
reads storage back and reports stored content and creation metadata, but its
finality observation remains `indeterminate`; it is never converted into a
finalized receipt.

`--receipt-provider demos-node` selects `demos-node-receipt-provider.ts`, which
establishes finality from the node's own statement over its public read path only: the storage program
(owner, creating transaction, stored bytes), the creating transaction (status,
block number, signer nonce), the node's transaction status, and the block that
lists the transaction (`confirmed` status, hash, consensus timestamp). It emits
state `finalized` under profile `demos-por-bft:block-confirmed:v1` only when the
transaction is `confirmed` in a `confirmed` block that lists it; `included`
without a confirmed block stays `included`, which the adapters reject; missing or
inconsistent reads return `indeterminate` with the fields observed. The receipt
reports the JCS-canonicalised content after text-anchor unwrapping and the SHA-256
of those canonical bytes; the adapters compare that hash with the expected
`contentHash`, so a tampered store fails rather than staying unknown.
The flag enters the parameter hash, so the dry run and the LIVE run must both
name it. No credential is read and nothing is written by the provider.

## Files
- `organ-gateway.mts` — the DACS-1→5 orchestrator (dry-run + live)
- `dacs-testnet-run.mts` — fail-closed testnet lifecycle coordinator and CLI
- `testnet-run-fixtures.ts` — deterministic dry-run dependency factory and receipt store
- `../adapters/dacs/pay-dem.ts` — SDK-faithful native-DEM adapter; only exact
  `included` with a block-number witness can emit `bft-final` evidence
- `anchor-naming.ts` — Demos substrate-equivalent anchor addressing (name-based,
  owner-checked resolution — see the §10.4.3 "substrate-equivalent" note inside)
- axiom-side bridge: `~/axiom/tools/organ_answer.py` (organ answer + keyed commitment)

## Honest scope

The reusable `agreement-commitment.ts` and `bundle-finalizer.ts` adapters now expose the DACS-3 finality-commitment and DACS-5 EBFAB flows behind an injected CORE §5.1 `receiptProvider`. This live gateway is intentionally not wired to them yet: `storage.ts` can show inclusion/read-back but cannot authenticate all receipt/finality fields, so a live Demos receipt provider and gateway migration remain a follow-up rather than treating SDK inclusion as protocol finality.

- cci primary claims are per-run ed25519 keys recorded in the anchored artifacts;
  durable gateway identities + listing discovery/indexing are the next slice.
- Dry-run artifacts are self-labelled (`organ-gw-dry-…` jobIds, `dry-…` locators,
  `demos:DRYRUN-…` tx refs) and never leave the process.
- Review: Codex NEEDS REVISION → all findings fixed → APPROVED (2026-07-07).
