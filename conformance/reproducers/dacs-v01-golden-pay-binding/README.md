# DACS v0.1 golden Listing pay-binding reproducer

This offline reproducer demonstrates a reference-to-reference inconsistency at the pinned revisions below. The DACS-Standard v0.1 happy-path vector labels its lifecycle as a happy path, but its Listing (`lst-regen-0001`) does not satisfy the directory reference implementation's `payBindingsOk` predicate.

The Listing has a `pay-evm-erc20` pipeline step and accepts `evm-erc20:8453:USDC`. The pay step has no `parameters.rail`, so it is not bound to that accepted rail. The directory predicate requires every `pay-*` step's `parameters.rail` to equal one of the Listing's `acceptedRails[].railId` values; for this Listing it evaluates to `false`.

This is only a reproducer of the observed mismatch. It does not determine which artifact should change, claim that the predicate is normative, or propose DACS specification text. The normative fix belongs to the DACS stewards and is tracked in [DACS-Standard #243](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/243), filed by OmniX.

## Pinned inputs

- Golden vector: [`DACS-Standard@2ff69b7f` `conformance/vectors/dacs-v0.1-happy-path.json`](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/2ff69b7f1fa13440a64cc865bd3f7e5fce6d34d2/conformance/vectors/dacs-v0.1-happy-path.json), copied byte-for-byte into `vectors/`; SHA-256 `19e5ce5c93917204ac76c1e3337e6e995000f9df2d87622a62217af16a6831e4`.
- Directory predicate: [`Community@07a008a8` `listingVerification.ts`](https://github.com/DACS-Agent-commerce/Community/blob/07a008a833a270ed1d58e578ce669d70e5c90c37/reference-implementations/dacs-directory/src/catalog/listingVerification.ts#L60-L66). `pay-bindings.ts` narrowly mirrors that predicate and reports the steps that fail it; it does not copy the directory's unrelated validation or cryptography.

## Run

From the repository root, after installing the repository's existing development dependencies:

```sh
npm run repro:dacs-v01-golden-pay-binding
```

The command performs no network access and reads only the checked-in vector. It exits nonzero if the fixture has no pay step or if the Listing ever satisfies `payBindingsOk`.

The regression guard is part of the normal test suite and can also be run alone:

```sh
npx --no-install tsx --test test/vectors/dacs-v01-golden-pay-binding.test.ts
```
