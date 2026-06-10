# Canonical-form conformance vectors

Portable test vectors for the **JCS canonical form + DACS §B.2 pre-pass** — the layer where two
independent DACS implementations most often silently diverge (different hash → different signature →
broken cross-impl conformance). Offered to the foundation SDK build as **candidate** conformance data
(the steward + golden-vector owner decide what becomes normative).

- **`canonical-form-vectors.json`** — generated, the artifact you test against.
  - `acceptVectors[]`: `input` → `expectedSha256` = `sha256(JCS_canonical_form(input))`. A conforming
    canonicaliser MUST reproduce `expectedSha256`. `sameHashAs` flags inputs that MUST hash identically
    (NFC value vs NFD value; out-of-order keys; NFC key vs NFD key).
  - `rejectVectors[]`: cases a conforming canonicaliser MUST reject. Not JSON-representable
    (BigInt, lone UTF-16 surrogate, integer > 2^53−1, NFC key-collision) — construct them per the
    builders in `cases.ts`.
- **`cases.ts`** — the shared case definitions (source of truth; all Unicode via explicit `\u` escapes).
  > Consumer caveat: `cases.ts` (with explicit escapes) is canonical. The `input` field in the JSON
  > carries NFD bytes literally — do NOT let an editor/tool re-normalise the JSON to NFC, or the
  > NFD vectors lose their meaning. When in doubt, regenerate from `cases.ts`.
- **`generate.mts`** — `npx tsx vectors/canonical-form/generate.mts` regenerates the JSON.
- Guarded by `test/vectors/canonical-form.test.ts` (re-derives every hash; asserts equivalence + rejects).

**What each case proves (the foot-guns):**
1. NFC normalisation of string **values** (DACS §B.2 CF-1) — NFD input must hash like NFC.
2. NFC normalisation of object **keys** (gap V2 in §B.2 — keys are in the hash too).
3. JCS object-key sorting — key order must not change the hash.
4. Safe-integer bound — numbers > 2^53−1 have no reproducible form; reject (carry as string).
5. Unpaired UTF-16 surrogate — no valid UTF-8; reject (gap V1 in §B.2).
6. NFC key-collision — two keys normalising to the same key are ambiguous; reject.

Oracle: `src/jcs.ts` (PATH-OS Labs `pathos-dacs-ref`). See `memory` report `dacs-conformance-partner-kit` for the full asset map.
