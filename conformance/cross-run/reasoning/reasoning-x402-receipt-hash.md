# Reasoning — x402-receipt-hash-v0.1 (pathos-dacs-ref@cross-run-1)

Independent second implementation for the cross-implementation convergence run.
Sources read: `spec/DACS-4-SETTLE.md` (§9.5.7 X402-1..X402-4, §9.5.8 SB-1),
`spec/CORE.md` (§B.2 CF-1 / canonical form / safe-integer), plus corroborating
error-vs-fail taxonomy lines in `spec/DACS-1-IDENTIFY.md` (DCR-4) and
`spec/DACS-2-VET.md` (verification outcome table).
**Nothing under `sets/` was opened, and no upstream vector file was fetched.**

## The pipeline implemented

From X402-2 verbatim:

> "Before hashing, the handler MUST apply CORE §B.2 CF-1 to the complete X402-1
> object. It MUST recursively NFC-normalise every JSON string value. It MUST then
> set `paymentReceiptHash = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))`,
> where `nfcSettlementResponse` is that normalised object and JCS is RFC 8785.
> The value MUST be exactly 64 lower-case hexadecimal digits without `0x`."

```
select header by protocolVersion   (X402-1: "1"->X-PAYMENT-RESPONSE, "2"->PAYMENT-RESPONSE)
  -> base64 decode                 (X402-4: "Invalid base64 ... MUST be rejected")
  -> UTF-8 decode -> json.loads    (X402-4: "invalid JSON/schema")
  -> require success == true       (X402-1)
  -> recursive NFC on every string (CORE §B.2 CF-1)
  -> RFC 8785 JCS serialise        (UTF-16 code-unit key sort; ECMAScript string
                                    escaping; ECMAScript Number::toString)
  -> SHA-256 over the UTF-8 bytes  -> lower-case hex, 64 chars, no 0x
  -> compare to evidence.paymentReceiptHash  (X402-4 "compare the resulting 32 bytes")
  -> X402-3 transaction / network-to-chainId consistency
```

JCS was implemented from RFC 8785 rather than approximated with
`json.dumps(sort_keys=True, separators=(',',':'))`, because `sort_keys` orders by
Python code point while RFC 8785 §3.2.3 orders by **UTF-16 code units** (these
diverge above the BMP). Every vector here has ASCII member names, so the set does
not actually exercise that difference — but an implementation that used
`sort_keys` would still converge on this set while being non-conforming.

## Verdict taxonomy used

§9.5.7 says all X402-4 conditions "MUST be rejected" without splitting `error`
from `fail`. The split was taken from the taxonomy the rest of the spec states:

- §9.5.8 SB-1: *"A well-formed tuple mismatch is `fail` ... A malformed or
  non-canonical address ... is `error`."*
- §9.5.8 SB-1: *"a resolved index whose event does not match is `fail`; a missing,
  non-integer, negative, non-safe-integer, or otherwise malformed signed
  coordinate is `error`."*
- DACS-2: *"malformed JSON/HTML/XML, parser exception → `error` (verifier-side
  failure to obtain a decision, never `fail`)."*
- DACS-1 DCR-4: *"A malformed legacy hostname is `error`, not a new identity."*

Generalised: **`error` = the verifier cannot obtain the comparison at all**
(input is not a processable, conforming X402-1 success object, or a value it must
compare against is malformed/non-canonical). **`fail` = the comparison was
obtained and is negative.**

## Per-vector

| # | vector | verdict | reasoning |
|---|--------|---------|-----------|
| 1 | `v1-success-x-payment-response` | **pass** | protocolVersion `"1"` selects `X-PAYMENT-RESPONSE` (supplied ✓). Decodes to a `success:true` object. Computed hash `9856a8f9…4be0` equals the stored hash **byte-exactly**. X402-3: `transaction` equals `settlementTxHash`; v1 legacy network `base-sepolia` maps to `chainId` 84532. Note this vector depends on the unpublished v1 registry — see A1. |
| 2 | `v2-success-payment-response` | **pass** | v2 selects `PAYMENT-RESPONSE` (✓). Computed `d8505c97…4332` = stored. `network` is exactly `eip155:84532` → matches recorded `chainId` "directly from v2 `eip155:{chainId}`". |
| 3 | `v2-reordered-pretty-json-same-hash` | **pass** | Header decodes to pretty-printed JSON with members in reverse order (`payer, network, transaction, success`). JCS re-sorts and strips whitespace, so the canonical bytes are identical to vector 2 and the hash is identical (`d8505c97…4332`) — computed independently, matching the stored value. This is the vector that proves JCS is doing real work. |
| 4 | `v2-decomposed-unicode-is-nfc-normalised` | **pass** | Carries `extensions["org.example.receipt-note"].note = "café"` (NFD, combining acute). CF-1 NFC-normalises it to `café` (U+00E9) before JCS. Computed `80d6579b…dec7` = stored. Had I skipped CF-1 the hash would differ, so this vector genuinely discriminates. |
| 5 | `v2-extension-member-is-committed` | **pass** | An `extensions.org.x402.offer-receipt` subtree with `signature: "sig:v1"`. X402-1 requires retaining "every received member, including `extensions` and unrecognised members" (and CORE SIG-5 forbids stripping unknowns before hashing), so the extension is inside the preimage. Computed `4d8c67f9…81e7` = stored. |
| 6 | `v2-extension-mutation-breaks-hash` | **fail** | Byte-identical to vector 5 except the extension's `signature` is `"sig:v2"` — while the stored `paymentReceiptHash` is still vector 5's `4d8c67f9…81e7`. Because the extension is committed, my computed hash is `361d6d93…c3f0` ≠ stored. Well-formed input, well-formed 64-lower-hex stored hash, negative comparison → X402-4 "a hash mismatch" → `fail`. |
| 7 | `transaction-hash-placeholder-is-not-receipt-hash` | **fail** | Header identical to vector 2, but the stored hash is `6b47456d…909a`. I verified independently that this equals `SHA-256("0x1fb8611c…14de")` — i.e. the producer hashed the **transaction hash string**, precisely one of the preimages X402-2 rules out: *"the base64 header text, decoded non-canonical JSON bytes, an on-chain transaction receipt, and `settlementTxHash` alone are not conforming preimages."* The stored value is still canonical in form (64 lower-case hex, no `0x`), so this is a well-formed negative comparison, not malformed input → `fail`. |
| 8 | `v2-wrong-v1-response-header` | **error** | `protocolVersion` is `"2"`, which X402-1 binds to `PAYMENT-RESPONSE`, but the header supplied is the v1 `X-PAYMENT-RESPONSE`. The header the declared version selects is absent, so there is nothing to decode and no comparison can be reached. No `evidence` is recorded either. → `error`. See ambiguity A5. |
| 9 | `v2-invalid-base64` | **error** | Value `%%%not-base64%%%` is outside the base64 alphabet. X402-4 names "Invalid base64" explicitly; DACS-2's table classes a parser exception as *"`error` (verifier-side failure to obtain a decision, never `fail`)"*. → `error`. |
| 10 | `v2-non-success-response` | **error** | Decodes to well-formed JSON `{"success":false,"errorReason":"insufficient_funds","transaction":"", …}`. X402-1 makes `success == true` a precondition of the object that enters the X402-2 preimage, so no conforming receipt hash exists to compare and no `evidence` is recorded. → `error`. **This is my one genuinely arguable verdict — see ambiguity A4.** |
| 11 | `v2-transaction-mismatch` | **fail** | Response `transaction` is `0x2fb8…` while `evidence.settlementTxHash` is `0x1fb8…`. My computed receipt hash `3dfb0fd2…e7f8` **does** equal the stored hash — so X402-1/X402-2 both verify and the record is rejected purely on X402-3: *"A successful response's `transaction` MUST equal `settlementTxHash` when that field is recorded."* A well-formed comparison with a negative result → `fail`. X402-3's *"it MUST NOT be repaired by hashing a different receipt interpretation"* is honoured: no fallback preimage is attempted. |
| 12 | `v2-network-chainid-mismatch` | **fail** | Response `network` is `eip155:1` (Ethereum mainnet) while `evidence.chainId` is 84532. Again the computed hash `897e6aa9…ee92` equals the stored hash, so the rejection is X402-3's network→chainId mapping alone. `eip155:1` is a *well-formed* CAIP-2 id naming the wrong chain — a mismatch, not malformed input → `fail`. (Had `network` been unparseable as `eip155:{digits}`, my implementation would return `error`.) |

**Distribution: 5 pass / 4 fail / 3 error.**

## Self-validation strength

Seven of the twelve vectors carry a stored `paymentReceiptHash` that my
implementation reproduced **byte-exactly** without ever seeing an expected
verdict: vectors 1, 2, 3, 4, 5, 11, 12. Vectors 3 and 4 in particular can only
match if JCS re-serialisation and CF-1 NFC are both implemented correctly, and
vector 5 only if unknown/extension members are committed. That is independent
evidence the canonicalisation itself converged, not merely the verdict labels.

## Ambiguities and underspecification (upstream findings)

### A1 — The v1 legacy-network registry is not published *(material)*
X402-3 requires `network` to map to `chainId` *"through the registered v1
legacy-network mapping"*, but no such registry appears anywhere in the supplied
normative text (CORE, DACS-1..DACS-4 were all grepped for `legacy-network`,
`base-sepolia`, `network mapping` — the only hit is X402-3 itself). Conformance
on every v1 vector therefore depends on a table the spec never publishes, names,
or anchors. I supplied one from the well-known x402 network names
(`base-sepolia` → 84532 etc.) and vector 1 happened to agree, but two
implementations with different tables would diverge and both could claim
conformance. **§9.5.7 should either inline the mapping, cite a registry anchor,
or state that an unregistered v1 network is `error`.**

### A2 — CF-1 is silent on object *member names* *(latent hash-divergence risk)*
CF-1 says *"every JSON string **value**"*. JSON member names are strings but are
not values. RFC 8785 performs no normalisation of its own, so if one
implementation NFC-normalises names and another does not, a receipt with a
non-ASCII extension key hashes to two different values — a silent
cross-implementation split in exactly the "commitment" field the rail depends
on. I normalise names as well as values (and before sorting), reasoning that
leaving them raw defeats CF-1's stated purpose. **Every vector in this set has
ASCII member names, so the set does not test this at all** — the one non-ASCII
payload (vector 4) puts the decomposed text in a *value*. A vector with a
decomposed extension **key** would be worth adding.

### A3 — `error` vs `fail` is never stated in §9.5.7 *(process gap)*
X402-4 lists five rejection conditions under one verb ("MUST be rejected") that
clearly span both categories: "invalid base64" is unprocessable input while "a
hash mismatch" is a negative comparison. The split had to be imported from
§9.5.8 SB-1, DACS-2's outcome table, and DCR-4. Any implementer reading §9.5.7
alone could reasonably return `fail` for all five. **§9.5.7 should label each
condition.**

### A4 — `success == false` is the one verdict I am not confident in *(flagged honestly)*
This is the single vector where I can construct a serious argument for the other
answer. Against my `error`: the document is well-formed JSON, parses cleanly, and
the verifier reaches a definite, non-ambiguous conclusion — which is exactly what
DACS-2's gloss calls *not* an error (*"verifier-side failure to obtain a
decision"*), and a `success:false` body with `errorReason` is presumably
*schema-valid* for `SettlementResponse`, so calling it "invalid schema" is a
stretch. For my `error`: X402-1 makes `success == true` a precondition for the
object entering the X402-2 preimage at all, so there is no conforming receipt
hash and therefore no comparison for a `fail` verdict to report on; the vector
also records no `evidence`, so there is literally no stored value that could
mismatch. I went with `error` on the "no comparison is obtainable" principle.
**If the two implementations diverge anywhere in this set, I expect it to be
here, and the divergence would be a spec defect rather than an implementation
bug.**

### A5 — Wrong-version header: undefined behaviour
X402-1 binds a version to a header *name* but never says what a verifier does
when the *other* version's header is supplied (as opposed to no header at all).
I treat it as "the selected header is absent" → `error`. An implementation that
instead sniffed whichever header was present would return `pass` on vector 8,
defeating the point of version-gated selection. **The spec should say the
non-selected header MUST be ignored and its absence is a hard rejection.**

### A6 — Number canonicalisation is untested by this set
RFC 8785 §3.2.2.3 requires ECMAScript `Number::toString`, which Python's `repr`
matches only approximately (exponent spelling, `1.0` vs `1`). **No vector in this
set contains a single JSON number inside the hashed object** — all payload values
are strings, booleans, or objects — so the hardest part of JCS conformance is
completely unexercised. X402-2 also does not restate CORE §B.2's safe-integer
constraint for the settlement response (I enforce it and return `error`
out-of-range). A vector with a numeric extension member (e.g. a block number or
a float) would materially strengthen the set.

### A7 — EVM hash equality tolerance in X402-3 is unstated
X402-3 says `transaction` "MUST equal" `settlementTxHash` without saying whether
that is byte equality or equality of canonical EVM hashes. §9.5.8 SB-1 does
define a canonical EVM spelling ("64 lower-case hexadecimal digits without `0x`;
a verified legacy spelling with `0x` or upper-case characters collapses to that
form"), so I compare after that collapse. Every vector here spells both sides
identically (`0x` + lower-case), so the set does not discriminate — but an
implementation doing raw `==` would diverge from mine on a mixed-case receipt.
