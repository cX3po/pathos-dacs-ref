# DACS Shared Conformance Suite — Adapter Contract (v0, draft)

**Status:** proposal draft, seeded by an independent implementer (`pathos-dacs-ref`) for
**working-group adoption**. This is *not* a PATH-OS artifact to be owned — the intent is
that it lives in a neutral DACS-Agent-commerce repository and the vectors are governed
upstream. See `PROPOSAL-DRAFT.md`.

## What this is

A **cross-implementation** conformance suite. An implementation participates by providing
an **adapter**: a small module that exposes a handful of pure functions the suite calls
with vector inputs. The suite runs each vector through *every registered adapter* and
compares the outputs to (a) the vector's expected value and (b) each other.

The framing that matters:

- **Agreement across independent implementations is interop evidence.**
- **Disagreement is a spec question, filed upstream — never a verdict on any implementation.**

No implementation adopts another's code. No implementation defines "conformant" by itself.
The vectors are derived from the DACS specification; each impl is one adapter among several.

## The adapter interface (v0)

An adapter is a module exporting the functions below. **Every function is PURE**: no
network, no keys held, deterministic. An impl implements the families it supports; for a
family it does not implement, it exports nothing for it and the suite records **abstain**
(not "disagree").

### F1 — `canonicalize(value: object) -> { hex: string }`
RFC 8785 (JCS) canonical bytes of `value`, hex-encoded.
*Families:* `canonical-accept`, `canonical-reject` (reject → throw / `{ error }`).

### F2 — `signedScopeHash(artifact: object) -> { hex: string }`
`sha256` over the artifact's canonical **signed scope** (the `signature`/`signatures`
field omitted, JCS-canonicalized). *Family:* `drift-signed-scope` (bundleHash / evidenceHash).

### F3 — `signatureValueVerdict(value: string) -> "ACCEPT" | "REJECT"`
CORE SIG-6: **ACCEPT** iff `value` is a valid canonical signature-value — unpadded
Base64URL, or canonical standard Base64 during the migration window — with a
decode/re-encode canonical-form check; **REJECT** any non-canonical spelling.
*Family:* `sig-value-encoding`.

### F4 — `verifyBundle(bundle: object) -> { decision: "accept" | "reject" | "indeterminate" }`
DACS-5 §10.4 single-bundle acceptance: structural validation, the required-signer rule,
signature verification over the signed scope, **and referenced-artifact signer-authorization**
(the class behind dacs-sdk#38 — a referenced artifact must be signed by an authorized
signer, not merely hash-matched). *Family:* `bundle-verify`.

### F5 — `domainSepSign` / `domainSepVerify` *(optional)*
Domain-separated sign/verify round-trip over the CORE separators. *Family:* `domain-sep-sign`.

*The interface is versioned and extensible: new families (metered pricing, payee-binding,
two-sided divergence) are added as new optional functions without breaking existing adapters.*

## Result semantics (per vector)

| Adapters vs expected | Adapters vs each other | Outcome |
|---|---|---|
| all match expected | agree | **PASS** — interop-confirmed |
| all differ from expected | agree with each other | **SPEC-QUESTION** — vector or spec is wrong |
| — | disagree | **SPEC-QUESTION** — interop gap, filed upstream |
| adapter has no function for family | — | **ABSTAIN** — recorded, not a disagreement |

The suite's output is an **agreement matrix** + a list of spec-questions. It never emits
"implementation X is non-conformant" — that judgment belongs to the working group with the
disagreement as evidence.

## Seed corpus

The initial vectors are the 49 declared in [`../partner-kit/vectors.json`](../partner-kit/vectors.json)
(canonical-accept/reject, domain-sep-sign, drift-signed-scope), plus the standalone
[`../vectors/dacs-263-sig-value-encoding-v1.json`](../vectors/dacs-263-sig-value-encoding-v1.json)
(SIG-6) and the referenced-artifact-authorization case (dacs-sdk#38). Every seed vector is
reproducible from a fixed input; none is trust-me.
