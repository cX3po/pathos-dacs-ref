# Cross-impl DECISION convergence — pathos-dacs-ref ↔ dacs-sdk

Canonicalization convergence is proven separately (the convergence harness: byte-identical signed-scope
hashes). This proves the **harder** thing: two independent implementations reach the **same §7.5.1
verdict** (`pass | fail | indeterminate | error`) on bundles engineered to trigger each decision.

Built **empirically** — `run.mts` builds a ground-truth corpus, runs *both real verifiers*
(`verifyBundleV1` from pathos-dacs-ref, `verifyBundleCore` from dacs-sdk), normalizes each impl's native
enum to the §7.5.1 4-value model, and reports the actual matrix. Mismatches are findings, not hidden.

## Result (dacs-sdk @ `ca3bac7`, 2026-06-29)

| case | pathos | dacs-sdk | |
|---|---|---|---|
| valid | pass | pass | ✅ |
| tampered-sig | fail | fail | ✅ |
| unresolvable-key | indeterminate | indeterminate | ✅ |
| malformed | error | error | ✅ |
| compound (tampered + unresolvable) | fail | fail | ✅ |
| mixed (valid + unresolvable) | indeterminate | indeterminate | ✅ |

**Decision convergence: 6/6**, and both match ground truth 6/6. The `mixed` case is deliberate: it's the
one that catches a dishonest `ok→pass` normalization — both impls must (and do) return `indeterminate`,
never `pass`, when one signature verifies and another can't be resolved (do-not-collapse). A signed convergence receipt
(`convergence-receipt.json`, PROOF_CONVERGENCE separator) attests this run — evidence, not authority.

## HONEST SCOPE (do not over-read)

- **Self-describing `cci:<hex>` keys, NO live DID resolver.** This proves the decision **logic** converges
  on these ground-truth cases — *not* "all bundles," *not* live-resolver behaviour under key rotation/outage.
- 6 synthetic cases. Real bundles (nested attestations, key chains, policy constraints) are not covered.
- The honest claim is exactly the table above, no broader.

## Bonus finding — a real shape divergence

dacs-sdk's `isAttestationBundle` **requires** `phaseSummary[].attestationRef`; pathos-dacs-ref treats it
**optional**. The corpus includes `attestationRef` to satisfy both so the *decision* logic can be compared.
Which is normative is a **spec question** (for the standard / steward), surfaced here — not resolved here.

## Enum normalization (semantic, not blind)

- pathos `accept`→pass; `indeterminate`→indeterminate; `reject` → **error** if structurally invalid (verifier
  couldn't process), else **fail** (bad signature).
- dacs-sdk **`fullyVerified`** (every sig valid)→pass; `"not an attestation bundle"`→error; any sig
  `invalid`→fail; any sig `error`→error; otherwise (some valid + some unverified, all unverified, or no
  sigs)→indeterminate. **NOTE:** `ok` is deliberately NOT used for pass — dacs-sdk's `ok` means "≥1 valid
  & none invalid/error," which is weaker than fully-verified; mapping it to pass would collapse a mixed
  valid+unverified result into pass (dishonest). The `mixed` corpus case verifies this distinction holds.

## Run

```
cd <dacs-sdk clone> && npm ci          # so its verifier's deps resolve
DACS_SDK_PATH=<dacs-sdk clone> npx tsx conformance/security-vectors/decision-convergence/run.mts
```

CI follow-on (#6): pin dacs-sdk as an npm dep + add `dacs-verify` as a 3rd impl.
