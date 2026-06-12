# OS-string wire-grammar conformance vectors

Demos carries OS amounts (the smallest DEM denomination) as **decimal strings on the wire** (the v3
`osDenomination` migration: `bigint` internally, canonical OS-string on the wire). The canonical
**writer** is `toOsString(os) = os.toString()`, and `demToOs` rejects negatives, so the canonical
image is:

```
OS-string ::= "0" | [1-9][0-9]*      (non-negative decimal, no leading zeros, no sign/space/prefix/fraction)
```

## Why this matters
A conforming **reader** must accept *exactly* the writer's image. A permissive reader makes
re-serialisation **non-idempotent** — `toOsString(parseOsString(s)) !== s` for non-canonical `s` —
so two implementations disagree on what a valid wire amount is, and a round-trip silently changes the
bytes (→ hash / signature drift on anything that includes an OS amount).

`@kynesyslabs/demosdk` v4.0.8 `parseOsString` is bare `BigInt(s)` (`src/denomination/conversion.ts`),
which **admits outside the canonical grammar** — `""`, surrounding whitespace, a leading `+`, `0x`/`0b`/`0o`
radix prefixes, and leading zeros — **12 of the 16 reject cases here** (verified against `BigInt()` by the test).

## The vectors
- **`os-string-vectors.json`** — `grammar` (the strict regex) + `acceptVectors` (canonical, each
  round-trips) + `rejectVectors` (every non-canonical string a strict reader MUST reject, each tagged
  `bareBigIntAccepts` = whether bare `BigInt()` admits it).
- **`cases.ts`** — shared source of truth. **`generate.mts`** regenerates the JSON.
- Guarded by `test/vectors/os-string.test.ts` (round-trips, strict-rejects, and the laxity flags).

## Suggested fix (for a conforming reader)
```ts
export function parseOsString(s: string): bigint {
  if (typeof s !== 'string' || !/^(0|[1-9][0-9]*)$/.test(s))
    throw new Error(`non-canonical OS-string: ${JSON.stringify(s)}`);
  return BigInt(s);
}
```

Offered as **candidate** conformance data (PATH-OS Labs · MIT). Scoped to the OS-string wire grammar;
the steward decides what becomes normative.
