# Proposal #270 revision: neutral DACS cross-implementation runner

This repo-ready seed implements the steward's requested boundaries. It proposes non-normative
tooling, not a DACS specification change or certification.

The runner communicates with implementation-owned executables through the versioned JSONL
subprocess contract in `ADAPTER-PROTOCOL.md`. Reports retain each adapter's repository and
immutable revision. A one-adapter match is `SELF-CHECK`; `INTEROP-AGREE` requires two distinct,
genuine implementation repositories running the same vector.

Results distinguish a mismatch against the pinned expected value from divergence between
implementations. `SPEC-QUESTION` is an explicit post-triage flag and is never inferred merely
because one of those conditions occurred.

F3 now checks only canonical unpadded Base64URL and is algorithm-independent. Standard Base64
is rejected on the conforming path. Migration is a separate legacy-import operation whose
source encoding is supplied out of band. Algorithm-specific decoded length and cryptographic
validation remain in the applicable algorithm contract.

`DACS-Standard` remains authoritative for vector inputs, expected values, rule/profile
references, tiers, and manifest hashes. A neutral runner in `DACS-Agent-commerce` consumes a
pinned Standard manifest or release and never silently forks the corpus. Candidate vectors
become cross-implementation evidence only after two independent adapters execute them under
the existing Standard review and tiering process.

The seed's exact present coverage is 49 declared partner-kit vectors plus 3 declared standalone
SIG-6 cases. It executes 40 partner-kit and 3 SIG-6 assertions (43 total), reports 9 partner-kit
cases as not executed by this interface, and has zero per-vector abstentions in the default run.
F4 has zero declared and zero executed vectors; bundle verification and referenced-artifact
authorization remain an honest aspirational family.
