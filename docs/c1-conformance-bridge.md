# C1 conformance bridge

The C1 bridge demonstrates that `pathos-dacs-ref` can consume the shipped DACS spine independently. It reads artifacts from the pinned DACS-Standard commit, loads only the SDK's public `dist/index.js` exports, and compares the SDK canonical form and content hashes with this repository's `src/jcs.ts` implementation.

Run it with local source checkouts:

```sh
DACS_STANDARD_DIR=../DACS-Standard \
DACS_SDK_DIR=../dacs-sdk \
npx tsx conformance/c1-bridge.mts --ablate
```

Add `--json` for the complete machine-readable report. `DACS_STANDARD_REF` may select a ref, but it must resolve exactly to `662be1d4899a2cadf327fe2d5523e93a80334e5f`. The default configured ref is that pin, so the Standard checkout may remain on another branch. The bridge exports the pinned tree to a temporary directory and runs the walkthrough there; it does not switch or modify the checkout. The SDK's exported `DACS_STANDARD_PIN` must match as well.

## What is executed

The bridge executes, rather than merely inspects:

- exact golden signature reproduction with `signArtifact`, signature verification with `verifyArtifact`, SIG-2 wrong-domain rejection, and signed-field ablations;
- the pinned Standard lifecycle walkthrough, including its canonical trace hash, all 11 emitted signed artifacts and all 18 signatures;
- byte agreement between SDK canonicalization/content hashing and `jcsCanonical`/`jcsHashHex` for every signed scope;
- `verifySettlementEvidence` for both emitted settlement records;
- `verifyBundleCore`, `bundleConsistency`, and `deriveReputation` for emitted attestation bundles; and
- a one-field ablation for every reported verification area whose baseline succeeds.

The emitted implementation manifest records observed results. In particular, at this pin the Standard walkthrough signs `phaseIndex` into both SettlementEvidence records (`scripts/run_lifecycle_walkthrough.py:569` and `scripts/run_lifecycle_walkthrough.py:860`), while the shipped SDK's `isSettlementEvidence` rejects that field under DACS-4 SB-1 (`src/artifacts/validators.ts:1826-1828`). Each record fails shape validation with `phaseIndex` present and passes when only `phaseIndex` is removed, so the settlement decisions are `fail`.

The walkthrough also fixes `jobId` to the non-ULID value `walkthrough-261-0001` (`scripts/run_lifecycle_walkthrough.py:77`). The SDK requires a canonical 26-character uppercase Crockford ULID (`src/artifacts/validators.ts:171-172`) through `isPayeeBoundAgreementDocument` -> `hasAgreementCommon` -> `isCanonicalJobId` (`src/artifacts/validators.ts:1318`). `isAgreementArtifact` rejects the walkthrough agreement and accepts it when only `jobId` is replaced with a Crockford ULID; that is the specific cause of `verifyBundleCore` reporting the agreement as `invalid-shape`. These are executed incompatibility results, not suppressed failures or load-bearing ablations. Artifact signatures, canonical hashes, bundle consistency, and reputation derivation do pass their replay checks.

## What is read but not executed

The bridge reads the Standard manifest schema, golden vector, walkthrough pins, and generated walkthrough inputs. Reading a rule, fixture description, or example manifest is not counted as executing it.

It does not prove live-substrate behavior: the walkthrough declares `FakeSubstrate` and `liveSdkCalls=false`. It does not execute dispute or disclosure because their inputs are constructed inside dacs-verify's `conformance/run.ts` and are not shipped as replayable Standard artifacts. It also does not execute x402; the walkthrough settles over its EVM ERC-20 example. Accordingly, none of those areas appears as an executed capability in the emitted manifest.

## CLI flags and the GitHub Action

The bridge accepts the checkouts as flags as well as environment variables, and can write the JSON report to a file:

```sh
npx tsx conformance/c1-bridge.mts --json --ablate \
  --standard-dir=../DACS-Standard --sdk-dir=../dacs-sdk --out=c1-bridge-report.json
```

`--standard-ref=<ref>` selects the Standard ref; it must still resolve to the pin. Flags override `DACS_STANDARD_DIR`, `DACS_SDK_DIR` and `DACS_STANDARD_REF`. Without flags the behaviour is unchanged.

`.github/actions/c1-bridge` is a composite action around the same command. It takes `standard-dir` and `sdk-dir` (git checkouts; the SDK must have `dist/` built), runs the bridge, uploads the report byte-for-byte as a workflow artifact (`compression-level: 0`, missing file is an error) and writes the report's sha256, the OK/PARTIAL status, the divergence count and the three commits it ran against to the job summary. It fails the job whenever the bridge did not complete; PARTIAL (executed with divergences) is reported, not hidden, and does not fail the job.

`.github/workflows/c1-bridge.yml` runs it on `workflow_dispatch` (inputs `sdk_ref`, `standard_ref`) and weekly. The SDK repository is private, so the workflow needs a read token in the `DACS_SDK_TOKEN` secret and stops with an error before any checkout when it is absent; a run that never executed the bridge is never green.
