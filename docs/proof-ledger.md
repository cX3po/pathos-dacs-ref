# SR-2 proof ledger

The proof ledger turns PATH-OS internal decisions into small, tamper-evident Demos SR-2 records.
It anchors projections, not the source receipt or Case document.

## Anchored projections

An outbound-gate receipt contributes:

- `kind: "outbound-receipt"`
- `ref`, formed from the receipt action and target
- the receipt's existing `content_sha256`
- the gate verdict and timestamp
- `tier` and `verdictCode`

A Case history event contributes:

- `kind: "gate-verdict"`
- `ref`, formed from the Case ID and destination stage
- PASS or FAIL and the event timestamp
- the source stage, destination stage, and gate identifier
- a SHA-256 hash of the JCS form of `{ id, from, to, by, gate, passed, ts }`

The actor field participates in that hash but is not copied into the public entry. The projection
never copies intent text, checks, process history, gate output, source file paths, personal names,
mnemonics, arbitrary extra properties, or other secret-bearing data.

## Immutable append design and addresses

The repository's Demos `anchor()` path creates an SR-2 Storage Program; it does not rewrite an
existing program at the same address. The proof ledger therefore uses immutable versions. Append
`n` anchors the complete ledger through entry `n` under the program name `<ledgerName>#<n>`. Every
entry after the first includes the preceding version's storage address as `detail.prev`.

A version's address is the SDK-derived address for the owner, versioned program name, and wallet
nonce used to create it. The append result is the authoritative locator and must be persisted by a
caller that will resume in another process. A ledger instance retains its latest locator for
subsequent `plan`, `append`, `read`, and `verify` calls. It never treats an unreadable known version
as an empty ledger.

This creates an immutable chain while avoiding an unsupported same-address update. It also means
there is no single permanent head address: the latest append result identifies the current head.

## CLI

Build one or more entries from receipts and Case events:

```sh
node --import tsx src/live/proof-ledger.mts --dry-run \
  --fresh \
  --receipt receipt.json \
  --case case.json --event 0 \
  --ledger pathos-proof
```

`--receipt` is repeatable. Each repeat of `--case` is followed by its `--event` index. The ledger
name defaults to `pathos-proof`. Pass `--fresh` only when deliberately creating version `#1`.
Otherwise `--head stor-…` is required and identifies the persisted latest append result; the CLI
fetches and validates that complete ledger before it plans the next linked version. `--fresh` and
`--head` are mutually exclusive. Dry-run mode is offline, requires `--fresh`, and prints JSON plans containing only
`address`, `op`, `entryCount`, `sizeBytes`, `feeOS`, and `withinSizeLimit`; it never broadcasts.

For a live append, set `LIVE=1`. The CLI loads dotenv from `DACS_ENV_PATH` (default `.env`), uses
`DEMOS_RPC` (defaulting to the repository's Demos endpoint), and obtains the wallet credential only
through `mnemonicFromEnv('DEMOS_MNEMONIC')`. It never prints that credential. Live mode refuses to
create `#1` unless `--fresh` was explicit. It broadcasts the exact create payload whose destination
was checked during planning, establishes a fresh Demos connection, performs a cold verification
fetch, and exits nonzero unless verification passes.

## Verification

Each successful append returns `storageAddress` and `contentHash`. The latter is SHA-256 of the JCS
canonical form of the exact ledger object sent to SR-2. A verifier can fetch the object from that
address, JCS-canonicalize and hash it, and compare the result with the returned hash. Public ledgers
can be fetched by any verifier; private ledgers require ACL access. A changed ledger produces FAIL,
a missing anchor produces INDETERMINATE, and RPC transport errors are propagated rather than being
misclassified as absence.
