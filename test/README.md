# Test vectors — `pathos-dacs-ref`

These tests exercise the universal signature scheme and bundle verifier against
the test categories in DACS v0.7 §14.6.

## Categories covered (v0.1 skeleton)

| Category | File | Status |
|---|---|---|
| JCS canonicalization round-trip (RFC 8785 vectors) | `vectors/canonicalization.test.ts` | 🚧 skeleton |
| Domain-separator unknown-key rejection (§7.7 closure) | `vectors/domain-sep-rejection.test.ts` | 🚧 skeleton |
| ed25519 sign/verify round-trip with domain separation | `vectors/signature-roundtrip.test.ts` | 🚧 skeleton |
| Bundle hash + signature recomputation (§10.4.1) | `vectors/bundle-verify.test.ts` | ⏳ planned v0.2 |
| Two-sided anchor address derivation (§10.4.2) | `vectors/anchor-pair.test.ts` | ⏳ planned v0.2 |
| VerifyResult decision invariants (§7.5.1 — no coercion) | `vectors/verify-result-invariants.test.ts` | ⏳ planned v0.2 |

## Running

```bash
npm test
```

Uses `node --test` via tsx. Each test file is self-contained.
