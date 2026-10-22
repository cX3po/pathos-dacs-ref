# Passport Diff

Observe a public Demos testnet identity and compare its projected claims. This standalone experiment uses the real DACS SDK's wallet-free `createAgent` and `resolveIdentity`; it never supplies a wallet or requests writes.

Prerequisites: Bun and an existing source checkout of dacs-sdk with installed dependencies and built `dist/`. Packages are not assumed available from npm. The default checkout is `~/dacs-sdk`; set `DACS_SDK_ROOT` to use another checkout. Snap Bun's `SNAP_REAL_HOME` is honored. Run from this directory:

```sh
bun test ./test.mjs
bun main.mjs snapshot 0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2 > before.json
bun main.mjs snapshot 0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2 > after.json
bun main.mjs diff before.json after.json
```

The address is a public testnet subject; it may have no claims or cease to resolve after a testnet reset. A canonical parameter-free lower-case `did:demos:agent:<64 hex>` or lower-case bare/`0x` key is accepted. The optional third snapshot argument is exactly `https://node2.demos.sh` or `https://demosnode.discus.sh`; URLs with paths, credentials, queries or other hosts are rejected. The backup endpoint may be unavailable. A failed read exits nonzero; it never becomes an empty successful observation.

Output includes only the canonical subject, projected canonical claim references/kinds, and selected numeric freshness/score values. Raw RPC metadata and proof bodies are omitted. The demonstrated subject currently has **zero linked claims**: the two real observations produce empty added/removed/changed arrays. Tests separately demonstrate synthetic added, removed and changed claims, input reordering, altered content, wrong subjects, malformed claims, limits and timeout behavior.

Snapshots are limited to 256 KiB and 256 claims; references are limited to 2,048 characters. Diff accepts snapshots only for the same subject and endpoint. Claim order is canonicalized before hashing; changes in observation time alone do not become claim changes. Each snapshot records the source checkout HEAD SHA, with SDK canonicalization and SHA-256 content hashing. This source pin identifies the checkout, not proof that its prebuilt `dist/` is clean or matches HEAD. Rebuild the SDK when changing checkout revisions.

These are **unverified RPC observations**, not identity attestations, provider-score authentication, finality proofs, or purchase authorization. A content hash catches accidental edits; an author can recompute it and forge an observation. Diff does not authenticate snapshot authors. A modified test fixture is not evidence of a real chain change. SDK calls get a 15-second operation deadline; the CLI has an additional 20-second process watchdog and exits after completion to release SDK network handles. The injectable `read` seam is for offline tests; the CLI always uses the SDK. No server, scheduler, key, DEM spend, or service change is needed.


See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
