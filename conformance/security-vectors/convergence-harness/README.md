# DACS multi-impl convergence harness

A small, standalone harness where **independent DACS implementations measure where they agree** on a
shared corpus of AttestationBundles. It is offered to the ecosystem so that impls can *align* rather
than each maintain a private, parallel runner. Peers are validated **against**, not graded.

This is non-normative tooling. It does not change the DACS spec; it measures convergence with it.

## What it measures

- **PRIMARY — canonical bundle-hash agreement.** Every registered impl independently computes the
  §10.4.1 / R5-1 canonical bundle signed-scope hash:
  `sha256(JCS(bundle WITHOUT signatures and WITHOUT anchoredByRole))`. If two impls produce the same
  hash for the same bundle, they agree on canonicalization. This is **key-free** — no key resolution,
  no signature verification, no identity layer — which makes it the cleanest convergence proof.

- **SECONDARY — decision agreement** (portable-resolvable bundles only). Each impl's §7.5.1 verdict,
  normalized to "verified vs not" for comparison. Decision divergence across impls is usually a
  claim/key-resolution **convention** difference, not a spec gap, so it is contextualized rather than
  graded. See the interop conventions below.

## Run it

```bash
npx tsx conformance/security-vectors/convergence-harness/harness.mts
```

It loads every `*.json` in `corpus/`, runs every registered adapter over every bundle, prints a summary,
and writes `report.md` + `report.json` next to the harness.

> With only the pathos adapter registered, the run is a **self-report**: every "AGREE" cell is trivially
> true (one impl always agrees with itself). The pathos hash + decision values it prints are real and
> reproducible — they are exactly what a second impl should target. Register a second adapter to turn
> the self-report into a real convergence matrix.

## Add an adapter

1. Implement the `ConvergenceAdapter` interface from [`adapter.ts`](./adapter.ts):

   ```ts
   interface ConvergenceAdapter {
     name: string;
     verify(bundle): { decision: string; hash: string; error?: string };
   }
   ```

   The contract: `hash` = the §10.4.1 / R5-1 canonical bundle signed-scope hash (hex); `decision` =
   your impl's §7.5.1 verdict in your own native enum. Make the adapter a **thin shim** over your real
   verifier + canonical-hasher — do not re-implement either.

2. See [`adapters/external-template.ts`](./adapters/external-template.ts) for a worked stub showing
   where to call your own verifier and hasher. (It is a stub by design — no third-party code lives here;
   each impl owns and imports its own code.)

3. Register it in [`harness.mts`](./harness.mts) by adding it to the `ADAPTERS` array.

The PATH-OS reference adapter is [`adapters/pathos.ts`](./adapters/pathos.ts).

## Interop conventions to align

These are alignment items surfaced by the harness, not bugs:

1. **Claim / key resolution.** Self-describing `cci:<hex>` vs resolvable `did:demos:*`. A bundle
   cross-verifies on *decision* only if both impls can resolve the signer key. Hash agreement holds
   regardless (canonical form needs no keys). Target: agree a portable test-fixture claim convention so
   decisions cross-verify, not just hashes.

2. **Signature encoding.** base64 vs base64url for the bundle signature `value` field. Lenient decoders
   bridge it; a strict one would not. Target: pin one encoding.

## Corpus

`corpus/` holds in-repo shared §10.4 fixtures. Add bundles by dropping more `*.json` files in there;
the harness picks them up automatically. Bundles whose claims are opaque `did:demos:*` are still hashed
(PRIMARY metric) but are not decision-compared by the portable harness — their native identity resolver
belongs to the impl that owns them.
