# DEM meter

The DEM meter is a local, off-chain cost log. It performs no Demos write.

## JSONL read contract

The file contains one JCS-canonical JSON object per line. A row has these fields:

- `agent`: a `cci:` claim with lowercase hexadecimal or a lowercase seat name containing only `a-z`, digits, `.`, `_`, or `-`. CCI input is canonicalized to lowercase when recorded; mixed-case CCI in stored rows is rejected.
- `kind`: `seat-call`, `tool-call`, `anchor`, `transfer`, `receipt-read`, or `verify-call`.
- `os`: a canonical non-negative integer string. OS is the smallest DEM unit.
- `at`: an ISO timestamp with an explicit timezone.
- `receiptHash`: optional 64-character lowercase SHA-256 hex. It references a receipt; receipt content is not copied into the meter.
- `ref`: optional string for a storage address, transaction hash, or caller-defined reference.
- `prevRowHash`: the preceding row's `rowHash`; it is absent on the first row.
- `rowHash`: 64-character lowercase SHA-256 hex.

For each row, remove `rowHash`, encode the remaining object with JCS, append the UTF-8 bytes of `prevRowHash` (or no bytes for the first row), and SHA-256 the result. A reader rejects malformed rows, blank lines, partial trailing lines, a `prevRowHash` mismatch, or a `rowHash` mismatch.

The adjacent `<path>.head` sidecar is the truncation guard. It contains JSON `{ "rowCount", "meterHead" }` and is replaced atomically after each appended row is fully written and synced. Reads compare both fields to the log and fail closed when the guard is missing for a non-empty log, when rows were removed, or when the head differs. The meter is not tamper-proof against an attacker who can rewrite both the JSONL and its head file.

Meter operations use their own exclusive `<path>.lock`, created with `O_EXCL`; they retry for at most two seconds and then fail with `meter-busy`. This lock is separate from the pay-DEM journal lock. A short write or sync failure does not update the head. If a crash leaves a partial trailing line, reads and records fail closed until `--repair` truncates only that tail; repair is allowed only when the intact prefix matches the sidecar head.

## Conversion and totals

There are 1,000,000,000 OS in one DEM. Decimal DEM input is converted by integer arithmetic and permits at most nine fractional digits. Output DEM strings use the unique canonical form: no exponent, no redundant leading or trailing zeroes, and no decimal point for whole DEM. Summaries use bigint arithmetic and apply `since` inclusively and `until` exclusively.

## Invoice

An invoice groups the selected period by meter kind, lists `meteredReceiptHashes`, and binds the selected meter head. It takes one locked snapshot for its lines, totals, receipt hashes, and head. `contentHash` is SHA-256 over the JCS form of the invoice without `contentHash`, including the required in-band notice `unsigned internal accounting; not a DACS artifact, not settlement proof, not a payment request`.

## CLI

The default file is `~/.pathos-dacs-ref/dem-meter.jsonl`. `DACS_DEM_METER` can select another file and `--path` takes precedence.

```text
node --import tsx src/live/dem-meter.mts --summary [--since ISO] [--until ISO] [--agent name] [--path file]
node --import tsx src/live/dem-meter.mts --invoice --from cci:… --to cci:… --since ISO --until ISO [--path file]
node --import tsx src/live/dem-meter.mts --verify [--path file]
node --import tsx src/live/dem-meter.mts --repair [--path file]
```

Successful commands write one JSON document to stdout and exit 0. Invalid input or a broken chain exits 1 without printing environment values.
