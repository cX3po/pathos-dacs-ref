# Cross-run — second-implementation runs over DACS-Standard candidate sets

DACS-Standard's `conformance/vectors/security/CROSS-RUN.md` promotes a candidate set
toward golden only when **at least two independent implementations converge** on it.
Every set in that directory is candidate tier, and at the time of this run no run file
had ever been filed by anyone.

This directory holds our runs. The source sets covered here were **authored by the
Standard steward, not by us** — that is the point. The delivery-or-remedy blind-set
generator also carries one explicitly identified review-regression vector derived from
the steward's release base. Running our implementation only over sets we wrote ourselves
would be self-convergence and would prove nothing.

## Method — how the independence was enforced

A second implementation is only evidence if it did not read the first one's answers.

1. Each set's vectors were **blinded**: `expected`, `want` and `note` stripped. The stripped
   files are the only vector input the implementer saw; absence of those keys was verified
   mechanically before any implementation began.
2. The answer keys were held **outside the implementer's reach** and were not consulted
   until every run file was written.
3. Each evaluator was written from the **normative spec text only** — the rule sections
   named in each set's `spec` field.
4. **No per-vector-name logic is permitted.** Each evaluator's `evaluate()` is a pure
   function of the vector's *data*; none of them receives or reads `name`. This is checked
   by AST inspection plus a grep of every vector name against every evaluator source —
   both must return nothing. A hit invalidates the run.

Point 4 matters more than it looks: in `signature-value-encoding-v0.1`, seven of the ten
vector *names* end in `-rejected`. A name-reading evaluator would score highly while
proving nothing. Blind runs are only credible if name-independence is verified rather
than assumed — worth considering for future sets (opaque case ids).

## Result

| Set | Vectors | Exact verdict token | Accept-vs-reject decision |
|---|---|---|---|
| `signature-value-encoding-v0.1` | 10 | 10/10 | 10/10 |
| `artifact-reference-shapes-v0.1` | 23 | 23/23 | 23/23 |
| `sb3-eip3009-nonce-v0.1` | 14 | 14/14 | 14/14 |
| `x402-receipt-hash-v0.1` | 12 | 11/12 | 12/12 |
| `transcript-suite-mlkem768-v0.1` | 30 | 30/30 | 30/30 |
| `dacsx-dispute-artifacts-v0.1` | 77 | 77/77 | 77/77 |
| **total** | **166** | **165/166** | **166/166** |

The transcript run also reproduces the upstream deterministic envelope field by
field. Its source is `kynesyslabs/sdks` PR #130 at commit
`31389e5176afb642fdae6c72fd4819d85973773a`; the pinned fixture SHA-256 is
`e9c8c0a60da017c7d5f33e6c47c811ef77b30c4127258b3ecc78efc3ba5ec95d`.

The convergence is not label-matching. Seven stored `paymentReceiptHash` values were
reproduced byte-exactly from the header alone — including a reordered/pretty-printed
response (only reproducible if RFC 8785 JCS re-serialisation is real) and an NFD-Unicode
response (only reproducible if CORE §B.2 CF-1 normalisation is applied). All five distinct
SB-3 nonces were re-derived from `(jobId, phaseIndex)`, including the NFC leg, which
changes the digest.

## The one divergence

`x402-receipt-hash-v0.1` / `v2-non-success-response` — the set expects `fail`, we produce
`error`. **Both are rejections; the disagreement is vocabulary, not behaviour.**

DACS-4 §9.5.7 X402-4 assigns a single action to five distinct conditions:

> Invalid base64, invalid JSON/schema, a non-success response, a non-canonical stored
> hash, or a hash mismatch MUST be rejected.

The set splits those five across `error` and `fail`. Neither §9.5.7 nor the security-vector
README states which rejection maps to which token, so two conforming implementations can
reach the same decision and still diverge on the recorded verdict. Filed upstream rather
than silently adjusted — adjusting our verdict after seeing theirs would destroy the
independence this run exists to establish.

## Reproducing

From this directory:

```sh
python3 impl/eval_signature_value_encoding.py
python3 impl/eval_x402_receipt_hash.py
python3 impl/eval_artifact_reference_shapes.py blind/artifact-reference-shapes-v0.1.json \
        --out runs/run-pathos-artifact-reference-shapes-v0.1.json
python3 impl/eval_sb3_eip3009_nonce.py blind/sb3-eip3009-nonce-v0.1.json \
        runs/run-pathos-sb3-eip3009-nonce-v0.1.json
python3 impl/eval_transcript_suite_mlkem768.py \
        --reproduce upstream/sdks-130-31389e51-transcript-encryption-v0.1.json
python3 impl/eval_transcript_suite_mlkem768.py \
        blind/transcript-suite-mlkem768-v0.1.json \
        --out runs/run-pathos-transcript-suite-mlkem768-v0.1.json
python3 scripts/build_dacsx_dispute_blind_set.py --check
python3 impl/eval_dacsx_dispute_artifacts.py \
        blind/dacsx-dispute-artifacts-v0.1.json \
        --out runs/run-pathos-dacsx-dispute-artifacts-v0.1.json
python3 scripts/build_transcript_suite_blind_set.py --check
python3 -m unittest discover -s . -p 'test_*.py'
python3 verify_independence.py
```

The blind runners rewrite their run files from vector data alone; the transcript
reproduction command separately reads the pinned upstream fixture. The transcript
generator derives every blind vector and answer entry from that fixture, while the
evaluator never imports or reads the generator.
Then, from a DACS-Standard checkout:

```sh
python3 scripts/diff_vector_runs.py run-pathos-<set>.json
```

`reasoning/` carries the per-vector spec justification for every verdict, so a divergence
is diagnosable rather than merely reported.
