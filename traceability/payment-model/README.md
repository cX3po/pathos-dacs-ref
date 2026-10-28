# Payment model interpretation inventory

Python >=3.10 and Git; Python standard library only. From the pathos-dacs-ref
repository root, with no existing `DACS-Standard` directory, run:

```sh
git clone https://github.com/DACS-Agent-commerce/DACS-Standard.git DACS-Standard
git -C DACS-Standard checkout --detach 4bb9e48a1095ab32c06c25b7c0b52018d3ce4091
python3 traceability/payment-model/check.py --spec-dir DACS-Standard
```

The checker requires the Standard checkout root, verifies HEAD equals the pin,
then verifies the complete mapped chapter SHA-256 and every cited span hash.
It reads only `spec/DACS-4-SETTLE.md`. No Standard file is vendored here.
A missing checkout, wrong commit or changed chapter fails closed. Other files
in that checkout are outside this checker. See the
[upstream MIT license](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/4bb9e48a1095ab32c06c25b7c0b52018d3ce4091/LICENSE).

The last command reports inventory integrity PASS and interpretation INCOMPLETE,
and regenerates REPORT.md. Appending `--require-complete` deliberately exits 2;
exit 0 means inventory integrity only. It does not establish correct interpretation,
semantic equivalence, SDK conformance or a complete implementation.

For offline synthetic controls from the repository root, run
`python3 -m unittest discover -s traceability/payment-model/tests -v`.
No external checkout is needed for these controls. The existing model and seven
mutation witnesses run with `python3 traceability/payment-model/model/explore.py`.

The inventory covers every State field, reachable categorical journal/worker/read/
truth value, reachable reference transition label (worker indices normalized), and
invariant returned by violation(). Boolean and integer domains are represented by
fields; concrete values occur in the finite-state closure. Mutant-only transitions
are negative controls, not reference obligations.

mapping.json records clause IDs, sections, exact pinned line spans, hashes and
reviewed rationales. Its 88 elements comprise 13 partial clause connections and
75 explicit local assumptions. The inverse inventory has 118 uppercase MUST/SHALL
lines in one chapter, including possible examples/comments; REQUIRED-only lines
and other chapters are outside it. No normative obligation is claimed fully modelled.
Template rationales still need independent clause-by-clause interpretation review.

Five negative controls cover mapping deletion, wrong spans, changed source bytes,
STALE delivery and MISSING release. They use minimal artificial citation text
derived from the mapping's section structure, not upstream text. Their states are
synthetic rather than replay-derived. MISSING non-execution is a stronger local
assumption. A wrong prose rationale can still pass the mechanical checker.

Native DEM and PIPE-3 links remain partial: cryptography, agreement/schema gates,
amount, payee, anchoring, cross-session uniqueness, refunds and other rails are not
verified. The local reservation return named refund is not an on-chain refund.
Model bytes are checked before import; this still requires trusted repository
code and mapping. No SDK adapter, wallet, RPC, signing, broadcast, credentials,
service or dependency installation is added.
