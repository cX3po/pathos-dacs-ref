# Recipe Studio

A local CLI over the real DACS SDK ParserSpec engine. Try JSONPath, CSS, XPath,
and RE2 against detached bodies. It reports `pass`, `fail`, `error`, and
`indeterminate` separately and preserves audit-only extraction.

Prerequisites: local `~/dacs-sdk` checkout with its dependencies and built `dist/`
(the SDK is not on npm), and Bun. Tested with `~/.bun/bin/bun` 1.2.22. Override
`DACS_SDK_ROOT` to use another trusted source checkout. No wallet or secrets needed.

From this directory:

```bash
~/.bun/bin/bun test ./test.mjs
~/.bun/bin/bun main.mjs demo
~/.bun/bin/bun main.mjs evaluate --spec sample-spec.json --body sample-body.json
```

The live demo resolves the public PATH-OS test identity at `https://node2.demos.sh`
through `createAgent({demosRpc})` without a wallet, then evaluates four local recipes
over a minimal detached projection. A present primary DID passes, a missing field
fails, negative absence without completeness remains indeterminate, and linked
claim presence reflects the actual response. The measured identity has zero linked
claims; this is not a proof of absence or authentication of its owner.
`--rpc https://demosnode.discus.sh` selects the other permitted testnet endpoint.
`--subject did:demos:agent:<64 lowercase hex>` selects a public subject.

For local evaluation, exit codes are 0 pass, 1 fail, 2 parser/input/runtime error,
and 3 indeterminate. A live demo exits 0 only if the read and evaluations completed;
it intentionally includes failing predicates. Results include the exact SDK git
HEAD, a inventory hash over `dist/**/*.js` (including unused modules, excluding dependencies), and lockfile hash. A git HEAD
alone does not prove the installed dist was built from that revision.

`--negative-match` flips listing semantics. `--list-complete` is an explicitly
untrusted caller assertion for experimentation; use it only to inspect PSP-5
behavior. This tool does not create a signed RecipeDescriptor, VerifyResult,
attestation, authenticated completeness evidence, payment approval, or trust verdict.
Use the SDK's authenticated recipe/response/provider capabilities for production Vet.

Inputs: regular non-symlink UTF-8 files only, 16 KiB spec / 256 KiB body, bounded
expressions and map entries. The public CLI runs parsing in a child process with a separately enforced 20-second kill deadline, including
SDK import and live connect. Errors omit raw RPC/config content. Bodies never
trigger network fetches; all four formats use the SDK's detached parser.

This is a manually invoked experiment, not an installed service or timer. The README
commands are its caller. Tests cover genuine parser decisions, precedence,
completeness, all four engines, malformed data, input limits and endpoint refusal.


See [the examples index](../README.md) for shared SDK setup. These examples are restricted to offline synthetic data and wallet-free testnet reads.
