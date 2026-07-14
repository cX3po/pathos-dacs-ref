# Architecture — `pathos-dacs-ref` v0.1

## Composition map

```
                    DACS-1 listing.json (16KB, JCS-canonical)
                              │
                              │ produced by
                              ▼
                ┌──────────────────────────┐
                │  src/cli/listing-pub.ts  │  (DACS-1 publisher)
                └──────────────────────────┘
                              │
                              │ anchored via SR-2 (Storage Program)
                              ▼
                       Demos chain (stor-…)

                    DACS-2 VerifyResult (per recipe)
                              │
                              │ aggregated by §7.7 algorithm into
                              ▼
                  CompositeVerificationRecord
                              │
                ┌─────────────┼──────────────┐
                │             │              │
        ┌───────▼──────┐  ┌───▼─────────┐ ┌──▼──────────┐
        │ evm-rpc      │  │ cbp-gleif   │ │ (other      │
        │ §7.3.7       │  │ §7.3.5      │ │  recipes,   │
        └──────────────┘  └─────────────┘ │  v0.x+)     │
                                          └─────────────┘

                    DACS-5 AttestationBundle
                              │
                              │ anchored at TWO addresses (§10.4.2):
                              │   stor-{sha256(jobId+"-bundle-buyer")}
                              │   stor-{sha256(jobId+"-bundle-seller")}
                              ▼
                ┌──────────────────────────┐
                │  src/cli/verify.ts       │  ← THE load-bearing CLI
                └──────────────────────────┘
                              │
                              │ verifies:
                              │   - Both anchors present (else "aborted-by-self")
                              │   - Both bundles equal canonical form
                              │   - Both signatures verify against DACS-1 keys
                              │   - Every AttestationRef.contentHash matches anchor
                              ▼
                  PASS / FAIL / UNCLEAR
                  (NEVER coerced — §7.5.1)
```

## Four CLIs, one shared lib

### `src/cli/listing-pub.ts` (DACS-1)
Reads a listing JSON from disk, validates the in-scope §6.3.4 structure, derives and carries the CF-4 `logical_address`, checks the signature-omitted canonical form is ≤ 16 KB, and anchors the complete record via an opaque colon-free Demos Storage Program name. After the native `stor-` locator exists it emits the hash-protected §6.3.5 index and §6.3.6 catalog artifacts. Signing remains the caller's responsibility; an existing signature field is preserved on the anchored record and omitted only from `contentHash` computation.

### `src/cli/discovery-gen.ts` (DACS-1 discovery)
Emits host-ready `.well-known/agent.json`, `.well-known/dacs/listings.json`, and catalog collection/detail artifacts for a known listing/native locator. `--legacy-record-without-logical-metadata` publishes an explicit `legacy-absent` binding for immutable older anchors without rewriting them. The seller/reputation catalog endpoint remains outside this addressing-only slice.

### `src/cli/verify.ts` (DACS-5) — **the moat for v0.1**
Given either a `stor-` anchor or a local bundle JSON file:
1. If anchor: fetch from Demos chain; if local: read from disk
2. Compute canonical form via `src/jcs.ts`
3. Recompute `bundleHash`; compare to claimed hash
4. For each signature: prepend `"dacs5-bundle:v1:" || bundleHash`, verify against signer's DACS-1 primary-claim public key (resolved via Demos CCI or ERC-8004 if EVM-keyed)
5. For each `AttestationRef`: fetch from `AttestationRef.anchor.locator`, hash bytes, compare to `AttestationRef.contentHash`. Mismatch → reject (per §7.5.2 normative MUST)
6. If §10.4.2 two-sided anchoring: verify both party-specific addresses are populated. Unilateral → mark as `aborted-by-self` (per §10.4.3)
7. Return structured JSON: `{ decision: "pass" | "fail" | "unclear", steps: Step[], canonical_bundle_hash, signers_verified, attestations_verified }`

**Conformance to §7.5.1**: `unclear` (==`indeterminate`) MUST NOT be coerced to `pass`. The CLI surfaces unclear-with-reason explicitly and returns non-zero exit code distinct from `fail`.

### `src/cli/vet-gleif.ts` (DACS-2)
Runs a `consensus-backed-proxy` recipe against the GLEIF API (`https://api.gleif.org/api/v1/lei-records`) for a specific LEI. Returns a §7.5.1 `VerifyResult` with `decision`, `recipeVersion`, freshness, claim payload, and a DAHR attestation reference (`AttestationRef`) anchored on Demos.

Initial scope is GLEIF only because it's the cleanest live public API the spec maps (open API, no key required, deterministic LEI → entity name + status). Future recipes (`ofac-clear`, `sam-uei`, `fedramp`) compose the same way.

## Shared lib

### `src/jcs.ts` — RFC 8785 JSON Canonicalization
Thin wrapper over the `canonicalize` npm package. Returns a `Uint8Array` (UTF-8 bytes of the canonical form). Used by listing-pub for §6.3.4 canonicalisation, by verify for §10.4.1 recomputation, by vet-gleif for §7.5.2 attestation hashing.

### `src/domain-sep.ts` — domain separators per the §B.7 closed registry
A single source of truth for every domain separator the spec defines. The universal signature scheme lives in **CORE §B.7** (the closed registry has 20 separators); `domain-sep.ts` carries the §B.7 separators this impl signs/verifies plus the SIG-4 `dacs-x-` extensions. Imported by everything that signs or verifies. The registry is closed; any caller passing an unknown separator MUST fail (per the §B.7 / SIG-1..4 closure rule). *(Not §7.7 — that is the separate DACS-2 composite verification record; CORE.md disambiguates the two.)*

```typescript
export const DOMAIN_SEPARATORS = {
  LISTING: 'dacs-listing:v1:',
  BUNDLE_PRESENTATION: 'dacs-bundle-presentation:v1:',
  CHANNEL_MSG: 'dacs-channelmsg:v1:',
  AGREEMENT: 'dacs-agreement:v1:',
  BUNDLE_DACS5: 'dacs5-bundle:v1:',  // preserved from reference impl per §10.4.2 comment
  // ... 12 more — see file
} as const;
```

### `src/lib/sign.ts` — ed25519 with domain separation
- `sign(payload: Uint8Array, separator: keyof DOMAIN_SEPARATORS, key: Uint8Array): Uint8Array`
- `verify(sig: Uint8Array, payload: Uint8Array, separator: keyof DOMAIN_SEPARATORS, pubkey: Uint8Array): boolean`

The separator MUST be from the closed registry; unknown separators throw immediately.

## What's missing v0.1 (deliberate)

- **DACS-3 channel layer** (L2PS subnet, sealed envelopes, RFQ, fixed-price) — SR-4 wire protocol is v2.
- **DACS-4 settlement layer** (x402, ERC-20, SPL, HTLC, Liquidity Tank) — SR-3 wire protocol is v2.
- **DACS-2 TLSN / zkTLS / verifiable-credential / oauth-attested / domain-tls-control / self-signed** — these compose the same way as evm-rpc + consensus-backed-proxy but each pulls in a sub-dependency we don't need for the v0.1 receipt-loop demonstration.
- **ERC-8004 reputation publication** — optional in spec (§10.7), out of scope here.

## Posture

This is a third-party ref-impl. Where the spec is ambiguous, we surface the ambiguity in code comments + the spec-section reference, and pick the interpretation we believe is intended. We do not extend the spec. If we hit a normative gap, we file it (see `docs/spec-gaps-observed.md` once it exists) rather than paper over it.

The audit that preceded this build flagged the absence of a public envelope-receipt verifier as a v1 conformance gap (FIND-008). The DACS spec §11.3 acknowledges the same. `src/cli/verify.ts` is that gap, closed from outside the KyneSys org.
