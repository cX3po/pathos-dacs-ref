# SB-3 EIP-3009 nonce — independent evaluation reasoning

Implementation: `impl/eval_sb3_eip3009_nonce.py` (`pathos-dacs-ref@cross-run-1`)
Sources consulted: `spec/DACS-4-SETTLE.md` §9.5.8 (SB-1/SB-2/SB-3), §9.5.6 (AP2-1/AP2-6
cross-references), §9.5.1 (PB-3), `spec/CORE.md` §B.1, §B.2, §B.7.
**Not** consulted: anything under `sets/`, and no upstream vector file was fetched.

## The derivation implemented

DACS-4 §9.5.8, SB-3, EIP-3009 arm — quoted verbatim:

```text
preimage = UTF8("dacs-sb3:v1:")
           || UTF8(NFC(jobId))
           || 0x3a
           || ASCII(decimal(phaseIndex))
nonceBytes = SHA-256(preimage)
```

with the pinning prose: *"`UTF8` is UTF-8 without a byte-order mark. `0x3a` is the
single ASCII colon byte. `decimal(phaseIndex)` is the non-negative integer's minimal
base-10 ASCII representation (`0` for zero; no sign and no leading zeroes). `nonceBytes`
is used directly as the 32-byte EIP-3009 value; when a DACS implementation serialises
that value as text it MUST use `0x` followed by exactly 64 lower-case hexadecimal
digits."*

CORE.md §B.7 states the identical preimage a second time, independently, as one of the
two sanctioned non-signature hash-domain tags:

> `dacs-sb3:v1:` — the EIP-3009 session-binding nonce preimage
> `sha256(UTF8("dacs-sb3:v1:") || UTF8(NFC(jobId)) || 0x3a || ASCII(decimal(phaseIndex)))` (§9.5.8).

Concretely:

```python
preimage   = b"dacs-sb3:v1:" + NFC(jobId).encode("utf-8") + b"\x3a" + str(phaseIndex).encode("ascii")
nonceBytes = sha256(preimage).digest()          # 32 raw bytes
text       = "0x" + nonceBytes.hex()            # 64 lower-case hex digits
```

Exactly one colon between jobId and phaseIndex; no trailing separator; the two colons
inside the literal tag are part of the tag.

**Independent confirmation.** My derivation, computed from the spec before looking at
any expected value, reproduces every `expectedNonce` present in the blind file
(5 distinct `(jobId, phaseIndex)` pairs). The NFC step is load-bearing and verified: for
the decomposed jobId (`cafe` + U+0301), skipping NFC yields
`0x3ad46f47…` while applying NFC yields `0xc4d6eb3c…`, and the latter is what the vector
carries. That is a genuine independent check of the normalisation leg.

## Verdict mapping (from SB-3's three branches)

DACS-4 §9.5.8 verbatim:

> - **present and matches** → the binding guarantee is satisfied;
> - **present and mismatches** → reject the evidence;
> - **absent or unverifiable** … the binding guarantee is **not established** for that
>   record: fall back to the SB-1 + SB-2 + §9.5.1 amount/payee posture of an unbound
>   rail. This is **never** an automatic accept and **never** a hard fail …

and: *"A well-formed nonce that differs is a **present-and-mismatches** rejection under
the branch rule below; a malformed nonce encoding is `error`."*

| condition | verdict |
|---|---|
| present + matches recomputation | `pass` |
| present + well-formed + differs | `fail` |
| malformed nonce encoding | `error` |
| `decimal(phaseIndex)` undefined for the input | `error` |
| absent / unverifiable | `pass` (non-rejecting) — see Uncertainty 1 |

## Per-vector reasoning

| # | vector | verdict | reasoning |
|---|---|---|---|
| 1 | `reported-live-vector` | pass | `sha256(b"dacs-sb3:v1:"+jobId+b":"+b"3")` = `0x2fc3598e…e1ff`; presented equals derived → present-and-matches. |
| 2 | `phase-index-changes-nonce` | pass | Same jobId, `phaseIndex` 4 → `0x80fa4732…a969`. Presented equals derived. Confirms `phaseIndex` is inside the preimage. |
| 3 | `job-id-changes-nonce` | pass | `…0002`, phase 3 → `0x69256a3b…ce29`. Presented equals derived. Confirms `jobId` is inside the preimage. |
| 4 | `job-id-nfc-normalized` | pass | jobId is `cafe`+U+0301 (decomposed), phase `0`. NFC → precomposed `café`; derived `0xc4d6eb3c…4397` equals presented. Also exercises `decimal(0) == "0"`. Skipping NFC would have produced `0x3ad46f47…` → fail, so this vector discriminates correctly. |
| 5 | `random-nonce-mismatch` | fail | Presented is 32 zero bytes — well-formed encoding, differs from the recomputation → present-and-mismatches → *"reject the evidence"*. Explicitly **not** the fallback branch: the binding is present, just wrong. |
| 6 | `wrong-phase-nonce-mismatch` | fail | `phaseIndex` 4, but the presented nonce is the phase-3 derivation. Well-formed, differs → present-and-mismatches. This is the PIPE-5 repeated-phase defence: *"required because a repeated phase type (PIPE-5) settles the same `phase` more than once."* |
| 7 | `short-nonce-error` | error | 62 hex digits after `0x`. Spec requires *"`0x` followed by exactly 64 lower-case hexadecimal digits"*; *"a malformed nonce encoding is `error`."* Not a mismatch — you cannot compare 32 decoded bytes you do not have. |
| 8 | `missing-hex-prefix-error` | error | 64 correct lower-case hex digits but no `0x` prefix. The `0x` is a MUST in the serialisation rule, so the encoding is malformed → `error`. Deliberately **not** rescued by "the digits are right": that would be exactly the kind of lenient repair a byte-exact rule forbids. |
| 9 | `negative-phase-index-error` | error | `phaseIndex` = −1. `decimal()` is defined only for *"the non-negative integer's minimal base-10 ASCII representation … no sign"*. No preimage exists → `error`, and no derivation is attempted. |
| 10 | `leading-zero-phase-index-error` | error | `phaseIndex` = `"03"` (a string, with a leading zero). *"no leading zeroes"* — the minimal representation of 3 is `"3"`. My rule accepts textual carriage only when it already matches `^(0|[1-9][0-9]*)$`, so `"03"` is rejected structurally rather than silently re-canonicalised to `"3"`. Re-canonicalising would defeat the vector: two implementations disagreeing on `"03"` is precisely the interop hazard. |
| 11 | `used-same-transfer-resumes` | pass | `op: retry`. `derivedNonce` equals my recomputation. Prior authorization `used`, `sameTransferParameters: true`, and a `settlementTxId` is supplied → *"If chain evidence proves that the same authorization and transfer parameters already settled this `(jobId, phaseIndex)`, the handler MUST resume with that existing settlement reference rather than charge again."* Correct behaviour is resume → `pass`. |
| 12 | `used-different-transfer-fails-closed` | fail | Prior authorization `used`, `sameTransferParameters: false`, no settlement reference → not reconcilable to a completed transfer. *"A nonce that is used or cancelled but cannot be reconciled to that completed transfer MUST fail closed; the handler MUST NOT generate a fresh nonce for the same `(jobId, phaseIndex)`."* Fail-closed → `fail`. |
| 13 | `cancelled-nonce-fails-closed` | fail | Prior authorization `cancelled`. A cancelled authorization by definition has no completed transfer to reconcile against, so the same fail-closed clause applies regardless of the `sameTransferParameters` flag. |
| 14 | `valid-ulid-full-input` | pass | `validationScope: "full-input"`, jobId `01ARZ3NDEKTSV4RRFFQ69G5FAV` — a canonical 26-char Crockford-base32 ULID, satisfying CORE §B.1 *"In every case `{jobId}` is a ULID (no reserved delimiters)"*. Input validation passes; derived `0xaeed3b79…e9e2` equals presented → present-and-matches. |

Distribution: **pass 6 / fail 4 / error 4**.

## `validationScope`

`validationScope` does not appear anywhere in the normative text — a grep of
`spec/CORE.md` and all four `spec/DACS-*.md` files returns zero hits. It is read here as
a harness-level knob on how much of the *input* is validated:

- `"derivation-only"` — treat `jobId` as an opaque string; do not check DACS identifier
  well-formedness. Required for coherence: the NFC leg of the derivation can only be
  exercised by a non-ASCII `jobId`, and no ULID is non-ASCII, so a strict-identifier
  reading would make the NFC vector unevaluable.
- `"full-input"` — additionally require `jobId` to be a canonical ULID (CORE §B.1;
  echoed at DACS-4 §9.5.1 *"`jobId` (a ULID)"*); a non-ULID is a malformed input →
  `error`.
- Unknown or missing scope → treated as `"full-input"` (strict), so an unrecognised
  value can never silently relax a check.

Note that this set contains no vector with `validationScope: "full-input"` and an
**invalid** jobId, so the strict branch is never exercised as a failure here. My
interpretation is therefore untested by the data and is a convergence risk if the other
implementation read the scope differently.

## Uncertainties — stated plainly, not papered over

1. **The absent/unverifiable branch has no home in a three-valued verdict.** The spec is
   emphatic that this branch is *"never an automatic accept and never a hard fail"* — the
   binding guarantee is simply *not established* and the record falls back to the unbound
   SB-1 + SB-2 + §9.5.1 posture (mirroring the §7.5.1 unresolvable-signer →
   `indeterminate` rule, and reinforced by PB-3: *"An implementation MUST NOT apply SB-3's
   fallback arm to the PB-2 decision"*). A `pass`/`fail`/`error` harness has no token for
   that state; the natural token would be `indeterminate`, which the harness does not
   offer. I mapped it to `pass` on the grounds that SB-3 raised no objection — **not**
   because the binding was proven. **No vector in this set exercises the branch**, so the
   choice is inert for this run, but it is a genuine expressiveness gap between the rule
   and the verdict vocabulary and should be raised upstream.

2. **`op: "derive"` has no defined success verdict.** Both `derive` vectors in this set
   are error cases, so the successful-derive verdict is never observed. I return `pass`
   when the preimage is constructible and (if an `expectedNonce` claim is present) agrees
   with the recomputation. A different implementation could plausibly have returned the
   nonce string rather than a verdict for this op.

3. **`expectedNonce` as input vs authority.** I treated `expectedNonce` as a *claim* the
   record carries, never as authority: the spec requires the verifier to *"independently
   recompute `nonceBytes` from `evidence.jobId`"*. If a present `expectedNonce` had
   disagreed with my recomputation I would have returned `fail` (a present-and-mismatches
   class rejection on the record's own claim), and `error` if it were malformed. In this
   set **all five present `expectedNonce` values agree with my derivation**, so this
   policy never fired and is untested. Had a vector deliberately carried a wrong
   `expectedNonce`, `fail` vs `error` would be a coin-flip between implementations.

4. **`missing-hex-prefix-error` → `error` vs `fail`.** The 64 digits are correct; only the
   `0x` is missing. A lenient reading ("decode it anyway, it matches") would yield `pass`;
   a mismatch reading would yield `fail`. I chose `error` because the spec classes the
   text form as a MUST and says *"a malformed nonce encoding is `error`"*. I am confident
   in this, but note it is the vector most sensitive to a reviewer's leniency.

5. **Uppercase-hex nonce.** The spec requires *lower-case* hex; an uppercase-but-otherwise-
   valid nonce would be `error` under my reading. Not exercised in this set. (Contrast
   SB-1's `settlement-tx-id` projection, which explicitly says a *"verified legacy
   spelling with `0x` or upper-case characters collapses to that form"* — SB-3 grants no
   such collapse, so I did not import one.)

6. **Textual `phaseIndex` generally.** `phaseIndex` is spec'd as a JSON number
   (`BundlePhaseEntry.index`), yet one vector carries it as a string. I accept a string
   only when it is already the minimal decimal form. Accepting `"3"` at all is a leniency;
   an implementation that rejected every non-number `phaseIndex` would still produce
   `error` on the one string vector in this set (`"03"`), so the two readings converge
   here — but they would diverge on a hypothetical `"3"` vector.

## Upstream finding on "byte-exactness"

The derivation **is** byte-exactly specified, and unusually well so: preimage
construction, domain tag, Unicode normalisation form, colon as a single named byte value,
decimal minimality including the zero case, hash function, digest width, and text
serialisation (prefix, digit count, case) are all pinned, and CORE §B.7 restates the whole
preimage a second time as a cross-check. I found no under-specification in the derivation
itself.

The gap is one level up, in *verdict vocabulary*, not in bytes: SB-3's third branch is a
three-state outcome (satisfied / rejected / not-established) that a `pass`/`fail`/`error`
conformance harness cannot express, and the spec explicitly forbids collapsing it into
either `pass` or `fail`. Two conforming implementations could legitimately diverge on any
future absent-binding vector purely because of this. Recommendation: either add an
`indeterminate` verdict to this vector set's vocabulary, or state normatively which of
the three tokens the fallback branch maps to for conformance purposes.

A second, smaller gap: `validationScope` is a vector-file field with no normative
definition anywhere in the spec, so its semantics are implementation-guessed rather than
specified.
