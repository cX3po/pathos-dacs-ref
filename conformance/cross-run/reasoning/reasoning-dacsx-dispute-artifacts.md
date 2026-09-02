# Delivery-or-remedy artifact cross-run reasoning

## Scope and method

This is an independent, verdict-level implementation of the candidate text in
`.crossrun-input/candidate.md`. It uses the two DACS-Standard PR #372 fixture
packs pinned under `upstream/dacs-standard-372-e5384514-delivery-remedy/`; it
does not use or reconstruct the upstream generator or verifier.
The blind-set generator adds one review-regression vector,
`evaluation-seq-not-zero`, as a single-field patch over the steward's release
base; its expected `rejected / DRAA-6` pair comes directly from DRAA-6.

The verifier follows section 9 in this order: discriminator parsing; required
shape and canonical encodings; content-hash recomputation, Ed25519 signatures,
roles, references, and agreement bindings; authenticated-source resolution;
`indeterminate` for unavailable evidence; native/artifact comparison; then
`verified`. Because the fixture format contains no resolver, resolution means
the status labels in `externalEvidence`. Those labels are treated as supplied
authenticated resolution outcomes. They do not bypass locally checkable event
sets, finality records, hashes, signatures, or native summaries.

The candidate requires an exact signed, phase-bound delivery
`SettlementEvidence` through DRP-7 and DRE-2, but it does not pin the delivery
dependency's signing domain (and contains no `dacs-evidence` domain). The
verifier therefore cannot independently authenticate that carried delivery
signature under a candidate-defined domain. It does recompute the unsigned
delivery content hash and bind it to every evaluation, decision, terminal, and
native mapping reference, so a delivery-body substitution is rejected.

The fixture pack carries public keys but no Ed25519 seeds or private keys.
Tests that mutate signed funding or terminal bodies use an explicit signature
skip seam to reach DRF-3, DRF-6, and DRT-4. The seam requires both the private
`_skip_signatures_for_tests=True` argument and `fixtureOnly: true`; ordinary
evaluation and the blind runner never enable it, and non-fixture material is
refused.

The candidate defines DRV-1 through DRV-5 but no numbered success rule. This
implementation therefore reports a successful protocol result as
`verified / DRV`, as requested. The steward pack uses the undefined token
`DRV-7`. Likewise, the pack uses `DRV-6` for two contradictions although the
candidate has no DRV-6; this implementation reports the applicable candidate
rule instead.

## Rule mapping

The mapping below states both what is evaluated and where fixture abstraction
limits byte-level checking.

- DRP-1 counts exactly two escrow steps; DRP-2 orders `fund` then `terminal`;
  DRP-3 requires one intervening `deliver-*`; DRP-4 rejects any additional
  payment/delivery; DRP-5 compares both rail selectors and the hashed rail
  definition; DRP-6 requires finalized funding before delivery; DRP-7 compares
  the exact delivery reference when submitted and enforces omission before
  submission; DRP-8 is a projection rule with no second-price field in the
  fixture; DRP-9 rejects a delivery hash containing native-submission output.
- DRA-1/DRA-2 recompute and bind the bilateral agreement and overlay; DRA-3
  verifies exactly one buyer, seller, and evaluator Ed25519 signature over
  `dacs-delivery-remedy-agreement:v1:` plus the lowercase overlay hash; DRA-4
  validates carried claim/bundle/Vet reference shapes and uses the resolution
  labels for absent bundle/Vet bodies; DRA-5 parses the exact EIP-155 claim and
  selected chain; DRA-6/DRA-7 enforce evaluator identity/account separation;
  DRA-8 recomputes `requirementHash`; DRA-9 requires the supplied fresh Vet
  result `pass`; DRA-10 enforces minimal unsigned budget and the agreement
  amount; DRA-11 binds ordered pipeline indexes; DRA-12 is represented by
  agreement resolution before creation/funding; DRA-13 keeps the evaluator out
  of bilateral required signers; DRA-14 compares immutable rail/profile/native
  role, token, budget, code, and deadline facts; DRA-15 validates and applies
  the signed pre-submission refund policy.
- DRJ-1 validates minimal native-job decimal; DRJ-2 checks a unique canonical
  creation-event reference plus supplied finality resolution; DRJ-3 compares
  chain, contract, roles, and overlay-bound job facts; DRJ-4 compares the exact
  section 8.1 description; DRJ-5 compares pinned and resolved runtime hashes;
  DRJ-6/DRJ-7 consume authenticated code/authority resolution (proxy authority
  bodies are absent); DRJ-8 keeps mismatches fatal despite signatures; DRJ-9
  verifies the orchestrator-domain signature.
- DRF-1 binds overlay, job, and fund index; DRF-2 compares token and amount;
  DRF-3 requires a non-empty, tuple-deduplicated, unambiguous pinned-chain
  event set; DRF-4 uses
  the supplied finalized funding state abstraction; DRF-5 checks zero
  preterminal provider payout; DRF-6 requires both `finalized` in the funding
  record and verified external finality; DRF-7 verifies the orchestrator
  signature over `dacs-escrow-funding-evidence:v1:` plus its hash.
- DRE-1 verifies the evaluator signer/domain; DRE-2 verifies the delivery
  reference and delivery-resolution status; DRE-3 checks carried subject refs
  while disclosure bodies are absent; DRE-4/DRE-5 prevent an indeterminate
  evaluation from authorizing a terminal action; DRE-6 compares the evaluation
  result/finding with the authorized disposition under the bound rule
  reference abstraction; DRE-7 requires the carried reference and finalized
  status before use.
- DRD-1 verifies evaluator signer/domain; DRD-2 compares basis result or
  recommended disposition; DRD-3 requires delivery on post-submission
  decisions; DRD-4 requires a resolvable finalized decision; DRD-5/DRD-6 map
  release/refund to `complete`/`reject`; DRD-7 forbids an expiry decision;
  DRD-8 rejects cross-job and consumed replay; DRD-9 requires dispute basis and
  omitted delivery before submission; DRD-10 consumes authenticated decision
  ordering; DRD-11 rejects contradictory after-terminal ordering and ignores
  self-reported time; DRD-12 requires signed policy plus finalized dispute
  outcome for pre-submission evaluator rejection.
- DRX-1 rejects transfer semantics in the represented disposition separation;
  DRX-2 permits a signed preterminal outcome only through a separate decision;
  DRX-3/DRX-4 keep post-terminal accountability separate from financial state;
  DRX-5 validates faulted-party presence and identity; DRX-6 forbids projecting
  non-fault classifications as buyer/seller fault.
- DRAA-1 validates canonical job/case JIDs; DRAA-2 validates minimal numeric
  segments; DRAA-3 checks complete logical-address locators; DRAA-4/DRAA-5 use
  the single carried write-once record and reject carried conflicts; DRAA-6
  requires initial evaluation sequence zero; DRAA-7 forbids an initial
  supersedes link and requires prior-reference shape for later revisions;
  DRAA-8 selects through authenticated references rather than time/index.
- DRT-1 requires release decision, basis, and delivery; DRT-2 requires rejected
  refund decision/basis; DRT-3 forbids an expiry decision; DRT-4 requires a
  non-empty unique pinned-chain terminal event set and matching state/token;
  DRT-5/DRT-6 require the full budget and correct seller/buyer recipient;
  DRT-7 checks zero fees and preterminal payout; DRT-8 requires record and
  supplied terminal finality; DRT-9 returns `indeterminate` for unavailable
  chain evidence; DRT-10 verifies the orchestrator signature without treating
  it as chain proof; DRT-11 recomputes and binds funding evidence; DRT-12
  enforces delivery presence after submission and omission before it; DRT-13
  rejects invented expiry fault.
- DREB-1 compares the exact ASCII description prefix and overlay hash; DREB-2
  recomputes every carried source hash; DREB-3 validates 64 lowercase hex;
  DREB-4 compares direct `decode_hex_32` bytes and rejects rehash, prefix,
  truncation/padding, or reversal; DREB-5 rejects zero deliverable/reason;
  DREB-6 rejects any wrong bytes; DREB-7/DREB-8/DREB-9 compare native client,
  provider, and evaluator; DREB-10 is enforced by the terminal payout receiver;
  DREB-11 compares token/budget; DREB-12 compares native expiry; DREB-13 checks
  cutoff plus grace; DREB-14 requires a positive window at least the minimum;
  DREB-15 is represented by the deployment recovery capabilities; DREB-16
  binds the evaluator account directly; DREB-17/DREB-18 admit supported EOA or
  EIP-1271 control; DREB-19 distinguishes relayer from evaluator; DREB-20 has
  no adapter field and the direct account check is mandatory; DREB-21 compares
  authenticated native caller; DREB-22 permits an outer relayer without
  substituting it for the native caller.
- DRC-1 through DRC-12 map one-for-one to the deployment result keys: no
  preterminal payout; immutable zero fees; unblocked expiry; no alternate
  withdrawal; no weakening logic replacement; authenticated irreversible
  upgrade disablement; absent/immutable nonblocking hooks; exact-accounting
  token semantics; complete event identity; reproducible and independently
  matched bytecode; complete non-conflicting evidence; authenticated decision
  ordering. Any unavailable required capability is `indeterminate`. Regardless
  of twelve passes, `fixtureOnly` or `registrationStatus: not-a-deployment`
  makes registration eligibility false.
- DRV-1 prevents fallback when a pinned rail/authority is unavailable; DRV-2
  preserves unavailable resolution as `indeterminate`; DRV-3 rejects malformed
  encodings without repair; DRV-4 prevents internally consistent signatures
  from overriding resolved mismatches; DRV-5 requires reconciliation of the
  original job/action (the fixture describes one offline attempt only).
- DRQ-1 accepts only the two candidate disclosure policies; DRQ-2 treats
  explicit evidence as named-party supplied; DRQ-3 forbids transcript
  retrieval; DRQ-4 keeps transcript use disabled; DRQ-5 rejects an unrecognized
  transcript-enabled policy/profile revision.

The shipped `release`, `rejected-refund`, and
`pre-submission-rejected-refund` lifecycle controls each contain a non-empty
funding event set, finalized funding, and a non-empty terminal event set. All
three pass DRF-3, DRF-6, and DRT-4 and remain `verified`.

## Convergence

Exact verdict tokens converge at **61/61 protocol** and **16/16 deployment**.
Treating only `verified` as acceptance, accept-vs-reject converges at
**61/61 protocol** (and 16/16 deployment). Rule-pair comparison has 18 protocol
differences and 4 deployment differences; all are vocabulary/precedence or a
missing upstream rule field, not verdict differences.

### Per-vector comparison

| Vector | Ours (result / rule) | Steward (result / rule) | Rule-pair divergence |
|---|---|---|---|
| `release-complete-budget` | `verified / DRV` | `verified / DRV-7` | yes |
| `evaluator-rejection-refund` | `verified / DRV` | `verified / DRV-7` | yes |
| `pre-submission-evaluator-rejection` | `verified / DRV` | `verified / DRV-7` | yes |
| `expiry-before-submission` | `verified / DRV` | `verified / DRV-7` | yes |
| `expiry-after-submission-grace` | `verified / DRV` | `verified / DRV-7` | yes |
| `pipeline-missing-terminal` | `rejected / DRP-1` | `rejected / DRP-1` | no |
| `pipeline-actions-reversed` | `rejected / DRP-2` | `rejected / DRP-2` | no |
| `pipeline-second-delivery` | `rejected / DRP-3` | `rejected / DRP-3` | no |
| `pipeline-extra-payment` | `rejected / DRP-4` | `rejected / DRP-4` | no |
| `pipeline-rail-divergence` | `rejected / DRP-5` | `rejected / DRP-5` | no |
| `pipeline-phase-index-divergence` | `rejected / DRA-11` | `rejected / DRA-11` | no |
| `evaluator-added-as-bundle-party` | `rejected / DRA-13` | `rejected / DRA-13` | no |
| `delivery-submission-circularity` | `rejected / DRP-9` | `rejected / DRP-9` | no |
| `description-prefix-substitution` | `rejected / DREB-1` | `rejected / DREB-1` | no |
| `description-sha256-prefix` | `rejected / DREB-1` | `rejected / DREB-1` | no |
| `uppercase-delivery-hash` | `rejected / DREB-3` | `rejected / DREB-3` | no |
| `prefixed-delivery-hash` | `rejected / DREB-3` | `rejected / DREB-3` | no |
| `delivery-hash-text-rehash` | `rejected / DREB-4` | `rejected / DREB-4` | no |
| `delivery-byte-order-reversal` | `rejected / DREB-4` | `rejected / DREB-4` | no |
| `delivery-padding-truncation` | `rejected / DREB-4` | `rejected / DREB-4` | no |
| `zero-deliverable` | `rejected / DREB-5` | `rejected / DREB-5` | no |
| `decision-hash-text-rehash` | `rejected / DREB-4` | `rejected / DREB-4` | no |
| `zero-decision-reason` | `rejected / DREB-5` | `rejected / DREB-5` | no |
| `decision-hash-substitution` | `rejected / DREB-2` | `rejected / DREB-2` | no |
| `evaluator-primary-claim-collision` | `rejected / DRA-3` | `rejected / DRA-6` | yes |
| `evaluator-account-collision` | `rejected / DRA-7` | `rejected / DRA-7` | no |
| `evaluator-wrong-chain` | `rejected / DRA-5` | `rejected / DRA-5` | no |
| `native-evaluator-mismatch` | `rejected / DREB-9` | `rejected / DREB-9` | no |
| `evaluator-vet-failure` | `rejected / DRA-9` | `rejected / DRA-9` | no |
| `nonpositive-evaluation-window` | `rejected / DRA-14` | `rejected / DREB-14` | yes |
| `evaluation-deadline-divergence` | `rejected / DRA-14` | `rejected / DREB-13` | yes |
| `native-expiry-divergence` | `rejected / DREB-12` | `rejected / DREB-12` | no |
| `cross-job-delivery-replay` | `rejected / DRD-8` | `rejected / DRD-8` | no |
| `cross-job-decision-replay` | `rejected / DRD-8` | `rejected / DRD-8` | no |
| `consumed-decision-replay` | `rejected / DRD-8` | `rejected / DRD-8` | no |
| `wrong-evaluator-signer` | `rejected / DRE-1` | `rejected / DRE-1` | no |
| `relayed-outer-submitter` | `verified / DRV` | `verified / DRV-7` | yes |
| `eip1271-relayed-execution` | `verified / DRV` | `verified / DRV-7` | yes |
| `relayer-substituted-as-native-caller` | `rejected / DREB-21` | `rejected / DREB-21` | no |
| `reject-evaluation-release-action` | `rejected / DRD-2` | `rejected / DRD-2` | no |
| `accept-evaluation-refund-action` | `rejected / DRD-2` | `rejected / DRD-2` | no |
| `partial-terminal-release` | `rejected / DRT-5` | `rejected / DRT-5` | no |
| `wrong-release-recipient` | `rejected / DRT-5` | `rejected / DRT-5` | no |
| `wrong-refund-recipient` | `rejected / DRT-6` | `rejected / DRT-6` | no |
| `nonzero-preterminal-payout` | `rejected / DRL-7` | `rejected / DRL-7` | no |
| `nonzero-platform-fee` | `rejected / DRT-7` | `rejected / DRT-7` | no |
| `expiry-invented-decision` | `rejected / DRD-7` | `rejected / DRD-7` | no |
| `pre-submission-expiry-delivery-ref` | `rejected / DRT-12` | `rejected / DRT-12` | no |
| `expiry-invented-seller-fault` | `rejected / DRT-13` | `rejected / DRT-13` | no |
| `rail-resolution-unavailable` | `indeterminate / DRV-1` | `indeterminate / DRV-2` | yes |
| `runtime-code-unavailable` | `indeterminate / DRJ-7` | `indeterminate / DRV-2` | yes |
| `terminal-finality-unavailable` | `indeterminate / DRT-8` | `indeterminate / DRV-2` | yes |
| `cross-substrate-order-unavailable` | `indeterminate / DRD-10` | `indeterminate / DRD-10` | no |
| `self-reported-time-cannot-order` | `indeterminate / DRD-10` | `indeterminate / DRD-10` | no |
| `decision-finalized-after-terminal` | `rejected / DRD-11` | `rejected / DRV-6` | yes |
| `decision-artifact-unavailable` | `indeterminate / DRD-4` | `indeterminate / DRD-10` | yes |
| `authenticated-native-contradiction` | `rejected / DRJ-7` | `rejected / DRV-6` | yes |
| `noncanonical-job-id` | `error / DRAA-1` | `error / DRAA-1` | no |
| `malformed-native-bytes32` | `error / DRV-3` | `error / DRV-2` | yes |
| `unsupported-profile-discriminator` | `error / DRV-3` | `error / DRV-1` | yes |
| `evaluation-seq-not-zero` | `rejected / DRAA-6` | `rejected / DRAA-6` | no |
| `synthetic-all-rules-control` | `verified / DRC` | `verified / —` | yes |
| `drc-1-preterminal-payout` | `rejected / DRC-1` | `rejected / DRC-1` | no |
| `drc-2-mutable-fees` | `rejected / DRC-2` | `rejected / DRC-2` | no |
| `drc-3-blocked-expiry-recovery` | `rejected / DRC-3` | `rejected / DRC-3` | no |
| `drc-4-emergency-withdrawal` | `rejected / DRC-4` | `rejected / DRC-4` | no |
| `drc-5-logic-replacement` | `rejected / DRC-5` | `rejected / DRC-5` | no |
| `drc-6-live-upgrade-authority` | `rejected / DRC-6` | `rejected / DRC-6` | no |
| `drc-7-mutable-blocking-hook` | `rejected / DRC-7` | `rejected / DRC-7` | no |
| `drc-8-fee-on-transfer-token` | `rejected / DRC-8` | `rejected / DRC-8` | no |
| `drc-9-ambiguous-events` | `rejected / DRC-9` | `rejected / DRC-9` | no |
| `drc-10-bytecode-mismatch` | `rejected / DRC-10` | `rejected / DRC-10` | no |
| `drc-11-conflicting-evidence` | `rejected / DRC-11` | `rejected / DRC-11` | no |
| `drc-12-unauthenticated-ordering` | `rejected / DRC-12` | `rejected / DRC-12` | no |
| `source-to-bytecode-evidence-unavailable` | `indeterminate / DRC-10` | `indeterminate / —` | yes |
| `current-reference-142e669-ineligible` | `rejected / DRC-1` | `rejected / DRC-1, DRC-2, DRC-3, DRC-4, DRC-5, DRC-6, DRC-7` | yes |
| `malformed-deployment-manifest` | `error / DRC-1` | `error / —` | yes |

### Divergence reasons

- The seven verified protocol controls use `DRV`; the steward key uses
  nonexistent `DRV-7`. The candidate explicitly defines only DRV-1..DRV-5.
- `evaluator-primary-claim-collision` reaches DRA-3 first: changing the signed
  overlay claim without replacing all three signatures invalidates the overlay
  at section 9 step 3 before the DRA-6 identity comparison.
- `nonpositive-evaluation-window` and `evaluation-deadline-divergence` report
  DRA-14 because the separately supplied profile parameters differ from the
  agreement-selected, hashed rail parameters. That immutable-binding mismatch
  precedes the downstream DREB-14/DREB-13 deadline comparisons used by the key.
- `rail-resolution-unavailable` reports DRV-1 (no fallback from an unavailable
  pinned rail), while the key uses generic DRV-2.
- `runtime-code-unavailable` reports DRJ-7's explicit unavailable-code rule;
  the key uses generic DRV-2.
- `terminal-finality-unavailable` reports DRT-8's exact terminal-finality rule;
  the key uses generic DRV-2.
- `decision-finalized-after-terminal` reports DRD-11, the candidate rule that
  explicitly rejects this ordering. The key uses nonexistent DRV-6.
- `decision-artifact-unavailable` reports DRD-4 because decision finality is
  the first unavailable required decision fact; the key selects DRD-10's later
  ordering check. Both remain indeterminate.
- `authenticated-native-contradiction` reports DRJ-7 for contradictory
  authenticated runtime code. The key uses nonexistent DRV-6.
- `malformed-native-bytes32` reports DRV-3, which forbids repairing malformed
  encodings. The key uses DRV-2, which is about unavailable RPC evidence.
- `unsupported-profile-discriminator` reports DRV-3 as the closest named
  malformed-input rule after section 9's unnumbered discriminator step. The
  key uses DRV-1, which is about authority fallback.
- The deployment control, unavailable-bytecode, and malformed-manifest cases
  have no steward `expectedRule`; ours supplies `DRC`, `DRC-10`, and `DRC-1`
  respectively so every result has a rule.
- The current-reference deployment key supplies the complete seven-rule
  failure set. Our primary `rule` is the first failure, DRC-1, while the run's
  per-rule map independently reports DRC-1 through DRC-7 as rejected exactly.

## Fixture limits

The fixture does not carry:

- Ed25519 seeds;
- referenced bundles or Vet records;
- evaluation-rule or delivered-artifact bodies;
- dispute-case input;
- native receipts or log payloads; or
- synthetic-hash preimages.

It also supplies public keys and signed artifacts rather than signature-generation
inputs. Consequently byte-level regeneration of the fixture pack is out of scope;
this run is verdict-level convergence. Candidate-defined artifact hashes and
signatures are still independently recomputed and verified from the carried
public keys, and the event/finality abstractions are actively checked.
