# Regenerated DACS-Standard lifecycle vectors (v0.1)

These replace the **quarantined** hand-authored lifecycle vectors in the DACS-Standard
conformance corpus. They are **machine-emitted by `pathos-dacs-ref`** — every signature and
hash is real and produced by the reference verifier's own emit path, not hand-typed. That is
the point: the quarantine happened because hand-faked artifacts drifted out of sync with the
current v0.1 shapes. Regenerating from the code closes that drift class.

## Reproduce (deterministic — byte-stable)

```bash
npx tsx conformance/regen-lifecycle.mts          # emit both vectors + self-verify
npx tsx conformance/regen-lifecycle.mts --check  # assert re-emit is byte-identical (tombstone)
```

Fixed keys (`0x41` buyer / `0x42` seller), fixed timestamps, fixed preimage → identical bytes
on every run. Re-run `--check` after any dependency bump to detect silent shape drift.

## What's covered — and what's deliberately NOT

| Stage | Artifact | Status in `pathos-dacs-ref` |
|---|---|---|
| DACS-1 | `Listing` | structurally valid (this impl has no listing-signature verifier) |
| DACS-2 | `CompositeVerificationRecord` | aggregation invariant asserted (§7.7.1: all pass → pass) |
| DACS-3 | `AgreementDocument` | **OMITTED — out of this impl's scope.** Not fabricated. |
| DACS-4 | `SettlementEvidence` | real round-trip: `buildHtlcSettlementEvidence` → `verifyHtlcSettlementEvidence` → **pass** |
| DACS-5 | `AttestationBundleV1` | real round-trip: emit → `verifyBundleV1` → **accept** |

**DACS-3 is intentionally absent.** `pathos-dacs-ref` has no `AgreementDocument` type
(CONTRIBUTING: "DACS-3 / DACS-4 deliberately out of scope until SR-3/SR-4"); fabricating one
is exactly the hand-faking that rotted the originals. Source the DACS-3 artifact from the SDK
or the steward's own fixtures. **Do not read its absence here as a conformance failure.**

## Files

- `dacs-v0.1-happy-path.regen.json` — full lifecycle, every covered artifact verifies.
- `dacs-v0.1-negative-paths.regen.json` — valid artifacts then **tampered**; the reference
  verifiers must **reject** them (bundle: a real 64-byte but cryptographically-wrong signature;
  settlement: a reveal preimage that no longer hashes to the hashlock). A compliant verifier
  MUST NOT accept these.
