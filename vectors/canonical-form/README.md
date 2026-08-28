# Canonical-form conformance vectors

Portable test vectors for the **JCS canonical form + DACS §B.2 pre-pass** — the layer where two
independent DACS implementations most often silently diverge (different hash → different signature →
broken cross-impl conformance). Offered to the foundation SDK build as **candidate** conformance data
(the steward + golden-vector owner decide what becomes normative).

- **`canonical-form-vectors.json`** — generated, the artifact you test against.
  - `acceptVectors[]`: `input` → `expectedSha256` = `sha256(JCS_canonical_form(input))`. A conforming
    canonicaliser MUST reproduce `expectedSha256`. Each vector also carries **`canonicalUtf8Hex`** — the
    exact UTF-8 bytes of the canonical form, hex-encoded — as the **editor-proof portable ground truth**:
    verify `sha256(unhex(canonicalUtf8Hex)) == expectedSha256` and that your canonicaliser reproduces
    those bytes, without trusting how your editor saved the literal-Unicode `input`. `sameHashAs` flags
      inputs that MUST hash identically (NFC value vs NFD value; out-of-order keys). An NFC member
      name and its NFD spelling are NOT in that set: CF-1 normalises string VALUES only, and RFC
      8785 preserves member names as received, so those are two DISTINCT canonical forms.
  - `rejectVectors[]`: cases a conforming canonicaliser MUST reject, each with a `reason`. These carry no
    `input` field — they are **not faithfully JSON-serialisable** (BigInt; lone UTF-16 surrogate; an
      integer >= 2^53 that a JSON reader rounds) - so
    construct them via the builders in `cases.ts`. NB the safe-integer case uses `9007199254740992`
    (= 2^53, exactly representable); a producer emitting the text `9007199254740993` is read back as the
    same value, and both are outside the IEEE-754 safe-integer range and MUST be rejected.
- **`cases.ts`** — the shared case definitions (source of truth; all Unicode via explicit `\u` escapes).
  > Consumer caveat: `cases.ts` (with explicit escapes) is canonical, and `canonicalUtf8Hex` in the JSON
  > is editor-proof. The human-readable `input` field carries NFD bytes literally — do NOT let an
  > editor/tool re-normalise the JSON to NFC (the test guards against this). When in doubt, regenerate.
- **`generate.mts`** — `npx tsx vectors/canonical-form/generate.mts` regenerates the JSON.
- Guarded by `test/vectors/canonical-form.test.ts` (re-derives every hash; asserts equivalence + rejects).

**What each case proves (the foot-guns):**
1. NFC normalisation of string **values** (DACS §B.2 CF-1) — NFD input must hash like NFC.
2. Member names are NOT NFC-normalised - preserved exactly as received and sorted by raw UTF-16
   code units (RFC 8785 3.2.3). An NFC name and its NFD spelling are distinct members with
   distinct hashes. CF-1's scope is string VALUES only.
3. JCS object-key sorting — key order must not change the hash.
4. Safe-integer bound — integers outside ±(2^53−1) are not safely IEEE-754 representable; reject (carry as string). Boundary: `safe-int-max` (2^53−1) accepts; `number-over-2pow53` (2^53) rejects.
5. Unpaired UTF-16 surrogate — no valid UTF-8; reject.
6. An NFC/NFD member-name PAIR is ACCEPTED, not rejected - with names preserved they cannot
   collide, so the object carries two distinct members. This was a reject case while we
   normalised names.
7. **ECMAScript number serialisation** (RFC 8785 §3.2.2.3) — negative-zero → `0`, small magnitude → exponent (`1e-7`), shortest round-trip (`0.30000000000000004`, not `0.3`), negative fractions. This is where independent impls diverge most.
8. **String escaping** (RFC 8785 §3.2.2.2) — control chars → lowercase `\u00xx`, tab/newline → two-char `\t`/`\n`, quote/backslash escapes, and non-BMP emoji passing through as **raw UTF-8** (not escaped).
9. **Non-ASCII key ordering** — keys sort by UTF-16 code unit (`a` < `b` < `ä`), and empty object/array edge cases.
10. **DACS-vs-pure-JCS divergence** — `1e21` is valid RFC 8785 JCS but DACS §B.2's safe-integer bound rejects it (a deliberate DACS tightening a pure-JCS impl will miss).

The test also pins number serialisation against an **independent ECMAScript reference table** (not our own oracle), so a number-formatting bug in the underlying canonicaliser can't be enshrined on regeneration.

Oracle: `src/jcs.ts` (PATH-OS Labs `pathos-dacs-ref`).
