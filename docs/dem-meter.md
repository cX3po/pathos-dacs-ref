# DEM meter

The DEM meter is a local, off-chain cost log. It performs no Demos write.

## JSONL read contract

The file contains one JCS-canonical JSON object per line. A row has these fields:

- `agent`: a `cci:` claim or a lowercase seat name containing only `a-z`, digits, `.`, `_`, or `-`.
- `kind`: `seat-call`, `tool-call`, `anchor`, `transfer`, `receipt-read`, or `verify-call`.
- `os`: a canonical non-negative integer string. OS is the smallest DEM unit.
- `at`: an ISO timestamp with an explicit timezone.
- `receiptHash`: optional 64-character lowercase SHA-256 hex. It references a receipt; receipt content is not copied into the meter.
- `ref`: optional string for a storage address, transaction hash, or caller-defined reference.
- `prevRowHash`: the preceding row's `rowHash`; it is absent on the first row.
- `rowHash`: 64-character lowercase SHA-256 hex.

For each row, remove `rowHash`, encode the remaining object with JCS, append the UTF-8 bytes of `prevRowHash` (or no bytes for the first row), and SHA-256 the result. A reader rejects a malformed row, a `prevRowHash` mismatch, or a `rowHash` mismatch. The file is append-only; record operations use an exclusive adjacent lock file and sync the appended line before returning.

## Conversion and totals

There are 1,000,000,000 OS in one DEM. Decimal DEM input is converted by integer arithmetic and permits at most nine fractional digits. Output DEM strings use the unique canonical form: no exponent, no redundant leading or trailing zeroes, and no decimal point for whole DEM. Summaries use bigint arithmetic and apply `since` inclusively and `until` exclusively.

## Invoice

An invoice groups the selected period by meter kind, lists referenced receipt hashes, and binds the selected meter head. `contentHash` is SHA-256 over the JCS form of the invoice without `contentHash`. The invoice is unsigned. It is an internal PATH-OS accounting document, not a DACS artifact, not proof of settlement, and not a payment request.

## CLI

The default file is `~/.pathos-dacs-ref/dem-meter.jsonl`. `DACS_DEM_METER` can select another file and `--path` takes precedence.

```text
node --import tsx src/live/dem-meter.mts --summary [--since ISO] [--until ISO] [--agent name] [--path file]
node --import tsx src/live/dem-meter.mts --invoice --from cci:… --to cci:… --since ISO --until ISO [--path file]
node --import tsx src/live/dem-meter.mts --verify [--path file]
```

Successful commands write one JSON document to stdout and exit 0. Invalid input or a broken chain exits 1 without printing environment values.
