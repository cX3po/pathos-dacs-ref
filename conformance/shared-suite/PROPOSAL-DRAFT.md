# Proposal (draft): a neutral cross-implementation conformance suite

*Draft for a DACS-Standard issue. Not yet posted. Reviewed through the PATH-OS gate before
any submission; framed for working-group ownership, not PATH-OS ownership.*

---

**Summary.** As a second independent implementation, we keep hitting the same pattern: two
conformant-looking impls diverge on an undefined spec corner, and it surfaces late (the
ComponentSignature value-encoding question — SIG-6, #263/#265 — is the recent worked
example; it converged once it was pinned normatively). Each impl's own harness can only
prove "you match me." I'd like to propose a **shared, neutral cross-implementation
conformance suite** so the ecosystem has an independent oracle: a common vector corpus run
through *every* implementation via a thin adapter, where **agreement is interop evidence and
disagreement is a spec question filed upstream** — never a verdict on anyone's code.

**What it is (and isn't).**
- A corpus of reproducible, spec-derived vectors + a runner that executes each vector through
  every registered implementation's adapter and reports an agreement matrix + disagreements.
- A minimal adapter contract (a few pure functions: canonicalize / signed-scope-hash /
  signature-value verdict / bundle verdict) so no implementation adopts another's code.
- **Not** a certification, **not** normative, **not** owned by any one implementer. The
  normative source stays the spec; this just makes divergence visible early and cheaply.

**Why now.** SIG-6 just merged; the SDK, this ref impl, and at least one other independent
implementation are all building the same normative surfaces in parallel. That parallelism is
exactly when a shared oracle pays off — it turns "we disagree" into a specific, attached spec
question instead of a late interop surprise.

**What we can contribute to seed it.** An initial corpus (49 canonicalization / domain-sep /
signed-scope vectors already packaged as a self-contained, tamper-evident kit, plus SIG-6 and
referenced-artifact-authorization vectors), the adapter contract, a reference adapter, and the
cross-run runner — offered as a *seed for working-group adoption*, to live in a neutral
`DACS-Agent-commerce` repository under working-group governance.

**What we're asking.** Is the working group open to hosting a neutral conformance-vector suite
of this shape? If so, we'll open a repo-ready PR against wherever you'd want it to live, and
invite the other implementations to register adapters. If a different shape is preferred, the
seed is a starting point, not a fixed design.

*Offered as an independent-implementer contribution — the goal is a shared oracle the whole
ecosystem owns, not a PATH-OS asset.*
