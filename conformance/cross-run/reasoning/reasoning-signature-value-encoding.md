# SIG-6 reasoning — pathos-dacs-ref@cross-run-1

Independent second implementation. Written from `spec/CORE.md` §B.7 (lines 404–449, conformance
clause SIG-6 at line 458) and `blind/signature-value-encoding-v0.1.json` only. The `sets/`
directory was never opened and the upstream vector file was never fetched.

SIG-6 decomposes into four obligations; every verdict below names which one decided it.

| # | Obligation | CORE.md lines |
|---|---|---|
| O1 | unpadded Base64URL wire encoding | 404–414 |
| O2 | canonicality check (reject padding / whitespace / `+` `/` / impossible lengths / invalid residual bits; decode + exact re-encode compare) | 416–422 |
| O3 | algorithm-specific validation of decoded length and internal format, validated *separately* | 424–425 |
| O4 | legacy-import boundary (explicitly selected, declared out of band, strict decode, no auto-detect, never on the conforming path) | 435–443 |

## Per-vector

| # | Vector | Verdict | Deciding obligation and justification |
|---|---|---|---|
| 1 | `canonical-base64url-unpadded` | **accept** | O1/O2 pass: 86 chars, wire alphabet only, no padding, `len%4==2` is a possible length, decode→unpadded-Base64URL re-encode is byte-identical. O3 passes: decodes to exactly 64 bytes, the Ed25519 signature length. |
| 2 | `standard-base64-same-bytes-rejected` | **reject** | O2 — "A verifier MUST reject padding … the standard-Base64 `+` or `/` characters" (CORE.md:416-418). Contains `/` and `==`. Encoding the *same bytes*, which is precisely the point: O4's "legacy inputs, not alternate conforming encodings" (CORE.md:436) means byte-equality does not rescue a non-canonical spelling on the conforming path. |
| 3 | `padded-base64url-same-bytes-rejected` | **reject** | O2 — right alphabet, but trailing `==`. "omitting all `=` padding" (CORE.md:407) and "MUST reject padding" (CORE.md:416). |
| 4 | `embedded-whitespace-rejected` | **reject** | O2 — "MUST reject … whitespace" (CORE.md:416). A space at offset 20 is outside the `A-Z a-z 0-9 - _` canonical set (CORE.md:413-414). |
| 5 | `impossible-length-rejected` | **reject** | O2 — "MUST reject … impossible lengths". Length 1, `len%4==1`; no byte count encodes to `4n+1` unpadded Base64 characters. |
| 6 | `non-zero-residual-bits-rejected` | **reject** | O2 — "MUST reject … invalid residual bits" plus the "decode and compare with an unpadded Base64URL re-encoding … comparison MUST be exact" round trip (CORE.md:420-422). `"AB"` decodes to `0x00`, which re-encodes to `"AA"` ≠ `"AB"`; the four unused low-order bits of `B` are non-zero. (O3 would also reject it — 1 byte ≠ 64 — but O2 fires first.) |
| 7 | `canonical-wire-wrong-ed25519-length-rejected` | **reject** | O3 *alone*. This value is fully canonical on the wire (84 chars, `len%4==0`, exact round trip) — O1 and O2 both pass. It decodes to 63 bytes. "Decoded length and internal signature format remain algorithm-specific. A verifier MUST validate them separately" (CORE.md:424-425) with `algorithm: "ed25519"`, whose signature is 64 bytes (RFC 8032 §5.1.6, `R‖S` = 32+32). This is the only vector that isolates O3, and it is my least spec-grounded verdict — see Uncertainty U1. |
| 8 | `declared-standard-base64-legacy-import` | **accept** | O4 — `mode: legacy-import` with `declaredEncoding: standard-base64-padded` supplied out of band. That path "MUST strictly decode the declared encoding, preserve the exact signature bytes, and emit the canonical DACS value" (CORE.md:438-440). The value is an exact, canonical padded standard-Base64 string; it decodes to the same 64 bytes as vector 1 and re-encodes to vector 1's canonical string byte-for-byte. Note this is the identical string rejected in vector 2 — the declared mode is the whole difference, exactly as CORE.md:442-443 intends. |
| 9 | `declared-lowercase-hex-legacy-import` | **accept** | O4 — `declaredEncoding: lowercase-hex`; hex is one of the three legacy spellings CORE.md:435 enumerates. 128 lowercase hex digits, even length, strict decode → the same 64 bytes as vector 1; canonical emission matches vector 1 exactly. |
| 10 | `undeclared-legacy-encoding-rejected` | **reject** | O4 — `mode: legacy-import` with **no** `declaredEncoding`. The path is defined as one "supplied with the source encoding out of band", and "It MUST NOT auto-detect by trying decoders" (CORE.md:438, 442). With nothing declared there is no encoding to strictly decode and the only way forward is the prohibited guess. (The value happens to be standard Base64 — recognising that *is* the auto-detection the clause forbids.) |

**Distribution: 3 accept / 7 reject.**

## Verified decode facts (computed, not assumed)

- Vectors 1, 8, 9 all decode to the **same 64 signature bytes**; `base64url_unpadded(bytes)` of that
  value reproduces vector 1's string exactly. The set is testing three spellings of one signature.
- Vector 7 decodes to **63** bytes — one short of Ed25519.
- Vector 6 (`"AB"`) → `0x00` → re-encodes to `"AA"`, proving the residual-bit failure.

## No per-vector hardcoding

`grep` of the evaluator source against all ten vector names returns **zero** hits. Two vector
*values* appear as substrings — `"A"` and `"AB"` — but only because they are substrings of the
alphabet constants `"ABCDEFGHIJKLMNOPQRSTUVWXYZ..."`. There is no branch keyed on any name or
literal value; every decision is a pure function of `(mode, declaredEncoding, algorithm, value)`.

## Genuine uncertainties (flagged, not papered over)

**U1 — Ed25519's 64-byte length is not in the spec (affects vector 7).** CORE fixes the algorithm
enum (`ed25519 | ecdsa-secp256k1 | sr1-aggregate`, DACS-1:535/666, DACS-3:452/633, DACS-4:1061) and
requires algorithm-specific length validation, but **never states any expected byte length**, and
RFC 8032 / SEC1 are absent from its normative references (CORE.md:653-660 lists only RFCs 2119,
4648, 7231, 8174, 8555, 8785). My `reject` therefore rests on external cryptographic knowledge, not
on quotable spec text. An implementation that scoped its SIG-6 evaluator to encoding only —
defensible, since CORE gives it no length to check — would return `accept` here. **This is the
single most likely divergence point in the set.**

**U2 — `MAY` on the legacy-import path (affects vectors 8 and 9).** CORE.md:438 says an
implementation *MAY* expose a legacy-import path. A conforming implementation that exposes no such
path would `reject` both, and would still be conforming. I read `mode: "legacy-import"` in the
vector as the harness stipulating "evaluate as an implementation that does expose this path", which
makes `accept` the intended answer — but the permissive `MAY` means `reject` is not obviously wrong,
and the vector set does not say which reading it wants.

**U3 — does O3 apply on the legacy-import path?** Vectors 8, 9 and 10 carry **no `algorithm`
field**. CORE.md:424-425 phrases algorithm-specific validation as a *verifier* obligation while the
legacy-import path is described as a *producer* obligation, so it is unclear whether an importer
must also enforce decoded length. I apply the check only when an algorithm is declared, so the
question is moot for these vectors (all three legacy values are 64 bytes anyway) — but it would
matter for a vector pairing `legacy-import` with a declared algorithm and a wrong length.

**U4 — the scope of "impossible lengths".** I read it as `len%4==1` (structurally impossible
unpadded Base64). It could alternatively be read as "a length no signature of this algorithm could
have", which would collapse O2 and O3 together. Vector 5 (`"A"`) is impossible under both readings,
so this does not change any verdict here, but it changes which obligation a divergence report would
cite.

## Spec findings worth reporting upstream

1. **SIG-6 mandates a check the spec supplies no data for.** "Decoded length … remain
   algorithm-specific. A verifier MUST validate them separately" is unimplementable from CORE alone:
   no lengths are given and no algorithm standard is cited normatively. Two conforming
   implementations can disagree on a canonical-wire/wrong-length value — the exact class vector 7
   probes. **Fix:** add a length column to the algorithm enum (ed25519 = 64; ecdsa-secp256k1 = 64
   raw or 65 with recovery byte; sr1-aggregate = ?) and add RFC 8032 to the normative references.
   `sr1-aggregate` in particular has no length defined anywhere in the four spec files.

2. **`MAY` on legacy-import makes accept/reject implementation-dependent.** Any conformance vector
   in `legacy-import` mode is asking a question the spec permits two answers to (U2). Either make
   the path `MUST`-if-exposed with a stated conformance profile, or have the vector set declare the
   profile it assumes.

3. **The legacy-import path has no stated registry of declarable encodings.** CORE.md:435 names
   three families ("standard Base64, Base64URL, and hex") in prose, but there is no normative list of
   `declaredEncoding` tokens or their padding/case discipline. I inferred the token set
   (`standard-base64-padded`, `lowercase-hex`, …) from those three families plus the vector data.
   Two implementations could accept/reject differently on a declared encoding one of them does not
   recognise.

4. **"internal signature format" is required but undefined.** CORE.md:424 requires validating
   internal format, yet no DACS document states whether, for example, ECDSA-secp256k1 must be low-s
   normalised or whether a recovery byte is permitted in a DACS `value`. I deliberately did not
   implement this beyond decoded length, and said so in the evaluator docstring.

5. **Blinding leak in the vector set (process finding, not a spec finding).** Seven of the ten
   vector *names* end in `-rejected`, and the others describe their expected outcome. The "blind"
   file therefore encodes the answer key in plain sight. My evaluator does not read names (proven by
   grep above), but a reviewer should know that name-independence has to be *verified* here rather
   than assumed, and future sets should use opaque vector ids.
