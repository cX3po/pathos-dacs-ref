# Per-vector reasoning — `artifact-reference-shapes-v0.1`

Implementation: `pathos-dacs-ref@cross-run-1`
Evaluator: `impl/eval_artifact_reference_shapes.py`
Normative sources: DACS-2 §7.5 type block + §7.5.2; DACS-4 §9.3 (`type TxRef = ChainTxRef`);
DACS-4 §9.5.7 X402-1/X402-2/X402-4; DACS-4 §9.5.8 SB-1; DACS-1 §6.3.1 (ClaimReference grammar);
CORE §B.1, §B.2, §B.6, §B.7, §11 (additivity contract / new-type refusal).

Verdicts below are exactly what the committed evaluator produced.

| # | Vector | Verdict | Spec justification (one line) |
|---|--------|---------|-------------------------------|
| 1 | `attestation-storage-program` | pass | `anchor.kind` in the closed §7.5 enum, non-empty `locator`, `contentHash` = 64 lower-case hex (CORE §B.2/§B.7), `signer` parses as `Scheme ":" Identifier` per DACS-1 §6.3.1. |
| 2 | `attestation-ipfs` | pass | Required `anchor` + `contentHash` present and well-formed; `signer` is optional in the §7.5 type block. |
| 3 | `attestation-https` | pass | Same as above with `anchor.kind = "https"`, the third value of the closed enum. |
| 4 | `attestation-legacy-kind-id-rejected` | **fail** | Carries no `anchor` — a REQUIRED member of `AttestationRef` (§7.5) and the fetch target of §7.5.2 step 1 — and carries two members the type block does not declare. |
| 5 | `txref-evm` | pass | Matches the §9.3 `evm` arm exactly: `chainId` positive safe integer (SB-1), `txHash` string. `0x`-prefixed spelling is explicitly tolerated by SB-1 ("legacy spelling with `0x` … collapses to that form"). |
| 6 | `txref-evm-event` | pass | Matches the `evm-event` arm: `chainId`, `txHash`, and a non-negative safe-integer `logIndex` (SB-1). |
| 7 | `txref-solana` | pass | Matches the `solana` arm: `cluster` in the closed `mainnet\|devnet\|testnet` enum, `signature` string. §9.3 declares `signature` as bare `string`; see note N1. |
| 8 | `txref-solana-instruction` | pass | Matches the `solana-instruction` arm, with `instructionIndex` a non-negative safe integer (SB-1). |
| 9 | `txref-demos` | pass | Matches the `demos` arm: required `txHash`, optional `blockNumber` present as a non-negative safe integer (CORE §B.2). No format is pinned for a Demos tx hash anywhere in §9.3 or §9.5.9. |
| 10 | `txref-storage-program` | pass | Matches the `storage-program` arm: `address` + `writeTxHash`, both declared as bare `string` with no pinned format. |
| 11 | `txref-ap2` | pass | Matches the `ap2` arm; the optional `receiptAttestation` is itself a well-formed `AttestationRef` (anchor + 64-hex contentHash), as AP2-2 requires of the recorded attestation. |
| 12 | `txref-x402` | pass | Matches the `x402` arm; `paymentReceiptHash` is exactly 64 lower-case hex without `0x` (X402-2) and `protocolVersion` is a minimal unsigned-decimal string (X402-1). Optional `settlementTxHash` / `chainId` present and well-typed. |
| 13 | `txref-x402-event` | pass | Matches the `x402-event` arm; all six members present, `logIndex` and `chainId` safe integers (SB-1), receipt hash and version per X402-1/X402-2. |
| 14 | `txref-htlc-lock` | pass | Matches the `htlc-lock` arm: `chainId`, `contractAddress`, `lockTxHash`. |
| 15 | `txref-htlc-reveal` | pass | Matches the `htlc-reveal` arm (`revealTxHash` is the arm-specific hash member). |
| 16 | `txref-htlc-claim` | pass | Matches the `htlc-claim` arm (`claimTxHash`). |
| 17 | `txref-htlc-refund` | pass | Matches the `htlc-refund` arm (`refundTxHash`). |
| 18 | `txref-liquidity-tank` | pass | Matches the `liquidity-tank` arm: required `bridgeId`/`sourceChainId`/`destChainId`/`lockTxHash`, optional `releaseTxHash` + `recoveryDeadline` (unix-ms, safe integer) both well-typed. |
| 19 | `txref-legacy-rail-kind-rejected` | **fail** | `kind` value is not one of the arms enumerated in the closed §9.3 union; CORE §11 new-type refusal requires rejecting an unsupported discriminator rather than reinterpreting the record. |
| 20 | `txref-solana-missing-cluster-rejected` | **fail** | The `solana` arm declares `cluster` as a REQUIRED member (§9.3); it is absent. |
| 21 | `txref-evm-event-missing-index-rejected` | **fail** | The `evm-event` arm declares `logIndex` as REQUIRED (§9.3); SB-1 further states a *missing* signed coordinate is malformed. |
| 22 | `txref-extra-role-rejected` | **fail** | Carries a member no §9.3 arm declares, whose value is drawn from the union's own `kind` vocabulary. Under CORE §11 new-type refusal an implementation "MUST NOT reinterpret it as an existing type by discarding an unknown discriminator or action-bearing field", and DACS-4 §9.5.8 repeats this for `ChainTxRef` arms specifically. **This is the one genuinely contested verdict — see Ambiguity A1.** |
| 23 | `txref-ap2-legacy-receipt-attestation-rejected` | **fail** | `receiptAttestation` is typed `AttestationRef` (§9.3, AP2-2) but the supplied object has no `anchor` and carries undeclared members, so it fails the §7.5 type block. |

Distribution: **17 pass / 6 fail / 23 total.**

---

## Rules deliberately NOT enforced as shape gates

**N1 — SB-1 canonical rendering is projection-time, not shape-time.**
DACS-4 §9.5.8 says EVM hashes "are rendered as exactly 64 lower-case hexadecimal digits
without `0x`" and "A Solana signature is base58 that MUST decode to exactly 64 bytes",
and that a reference which cannot produce that form "is malformed and yields `error`".
These were **not** applied, because the same paragraph sequences them explicitly *after*
shape verification — "After signature, **shape**, anchor-address, and ledger-event
verification, the consumer deterministically projects the verified signed arm to
`settlement-tx-id`" — and their failure mode is the §7.5.1 *verification outcome* `error`,
which is not in this set's pass/fail vocabulary. §9.3 declares every one of these members
as a bare `string` with no format. Consequence: vectors 5–18 pass on hash/signature members
that would not survive a projection-time canonicalisation check.

**N2 — Cross-artifact and network-dependent rules.** §7.5.2 steps 1–4 (fetch, integrity,
signature), X402-3 receipt/chain consistency, AP2-1/AP2-2 binding, and the SB-1
anchor-address tuple all require the enclosing `SettlementEvidence`, the ledger, or the
network. Out of scope for a standalone reference shape.

**N3 — Scheme registration is not a shape gate.** DACS-1 §6.3.1 "Unknown-scheme handling"
requires a reader to preserve an unknown-scheme reference verbatim and treat it as
*unverified*; it does not authorise structural rejection. Only the §6.3.1 grammar is
enforced on `signer`.

---

## Genuine uncertainties (flagged, not papered over)

**A1 — Undeclared members: reject or ignore? (decides vector 22, and only vector 22.)**
The spec supports both readings and never states which governs shape conformance:
- *Reject* (what this implementation does): §9.3 enumerates each arm exhaustively;
  CORE §B.6 makes the v0.1 registries closed with `x-` as the only sanctioned escape hatch;
  CORE §11 new-type refusal forbids acting on a record while discarding an unknown
  discriminator or action-bearing field, and DACS-4 §9.5.8 applies that reasoning to
  `ChainTxRef` arms by name.
- *Ignore* (the tolerant reading): CORE §11 additivity contract says an older reader
  "safely consumes a newer-minor artifact by preserving unknown fields (SIG-5) and
  interpreting only what it knows", and SIG-5 says a verifier "MAY ignore the *meaning*
  of unknown fields". DACS-4 §9.5.8 legacy read/replay even says a caller-supplied
  annotation "MUST be ignored".

I chose *reject* because a `ChainTxRef` carries no per-artifact version discriminator of
its own — the only version signal is `kind` — so a validator has no basis to attribute an
undeclared member to a later minor, and cannot distinguish an inert annotation from an
act-requiring field. If the reference implementation took the tolerant reading, vector 22
is where the two runs will diverge, and the divergence is a spec gap, not an implementation
bug.

**A2 — `signer` identifier-level validation.** Vector 1's `signer` uses the registered `did`
scheme with the DID method `demos`. DACS-1 §6.3.1 pins exactly one Demos DID profile,
`did:demos:agent:<64hex>`, and requires 64 lower-case hex with no `0x` for that profile's
key component. Vector 1's identifier is *not* that profile. I passed it because §6.3.1
gives `did:` the identifier shape "per W3C DID method" and DACS does not claim exclusive
ownership of the `demos` DID method namespace, so identifier-level validation is
out of scope at shape level. A stricter reading — "`did:demos:` is profiled by DACS-1, so
anything under it that is not `agent:<64hex>` is non-canonical" — would fail vector 1.
This is a real coin-flip.

**A3 — `anchor.locator` non-emptiness.** §7.5.2 declares `locator: string` with no
emptiness or format constraint. I require non-empty on the grounds that §7.5.2 step 1
("fetching the anchor at `AttestationRef.anchor.locator`") is unsatisfiable otherwise.
No vector exercises this, so the choice is verdict-neutral here but could diverge on a
future set.

**A4 — `chainId > 0`.** SB-1 states "`chainId` MUST additionally be greater than zero",
but does so inside the *projection-key* paragraph. I lifted it to a shape constraint
because EIP-155 chain ids are positive by construction and no arm has a zero-chain
interpretation. No vector exercises it.

---

## Spec ambiguities / gaps worth reporting upstream

1. **No stated unknown-member policy for the §9.3 union or the §7.5 type block.** CORE §11
   argues both ways (additivity ⇒ tolerate; new-type refusal ⇒ reject) and neither passage
   is scoped to "shape conformance". This is the single highest-value fix: one normative
   sentence in §9.3 ("a `ChainTxRef` MUST NOT carry members other than those declared by
   its matched arm" — or the opposite) removes the only real divergence risk in this set.

2. **Transaction-hash and address formats are pinned in exactly one place, and it is the
   wrong place.** `txHash`, `settlementTxHash`, `lockTxHash`, `revealTxHash`, `claimTxHash`,
   `refundTxHash`, `contractAddress`, `address`, `writeTxHash`, and Solana `signature` are
   all bare `string` in §9.3. The only format text (SB-1 §9.5.8) is written as a rule for
   *rendering the projection key*, not for the wire field, and it covers only EVM hashes
   and Solana signatures — never Demos hashes, HTLC contract addresses, liquidity-tank
   hashes, or storage-program addresses. Two conformant implementations can therefore
   disagree on any of these members. Recommend hoisting an explicit per-member format
   table into §9.3.

3. **`0x`-prefixed vs bare hex is left as "legacy spelling that collapses".** SB-1 says a
   current producer "MUST emit the canonical spelling" (bare 64-hex) but also that a `0x`
   spelling collapses rather than being rejected. Whether a `0x`-prefixed `txHash` is a
   *conformance* failure for a new producer is not answerable from the text.

4. **`ap2.protocolVersion` has no pinned format**, while the sibling `x402.protocolVersion`
   is pinned by X402-1 to a minimal unsigned-decimal string. §9.5.6 step 6 only calls it
   "the wire version that produced the mandate/receipt". An AP2 version like `"0.9"` or
   `"v1"` is currently unjudgeable.

5. **`AttestationRef.signer` typing is under-constrained relative to its own §7.5 note.**
   The note makes `substrate-validator-set:` MANDATORY when the signer produced a
   `consensus-backed-proxy` or `evm-rpc` attestation — but the attestation method is not
   a member of `AttestationRef`, so a standalone reference can never be checked against
   that rule. Either the method belongs in the reference or the rule belongs on the
   enclosing `VerifyResult`.

6. **`DemosGCRDomainMetadata`-style precision is absent from `ChainTxRef`.** DACS-1 pins
   hostname, 64-hex account, and exact proof URL for its metadata type; the equivalent
   settlement-side type gets none. The asymmetry looks unintentional.
