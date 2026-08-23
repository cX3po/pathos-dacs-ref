# DACS Shared Conformance Suite — adapter contract v1

The WG adapter boundary is the versioned subprocess protocol in
[`ADAPTER-PROTOCOL.md`](./ADAPTER-PROTOCOL.md), not a JavaScript module interface. TypeScript,
Python, Go, Rust, and other implementations participate on equal terms. JavaScript objects in
the comparison engine are runner-side subprocess clients or test doubles only.

Each implementation owns and versions its adapter. The metadata handshake must give its name,
version, repository, immutable revision, supported families, and operations; the runner copies
that provenance into the report.

The runner assigns every adapter run a unique runner-side `runId` and keys results by it, not by
the self-reported `metadata.name`. Two adapters may not collide in the results map even if they
self-report the same name (DACS-Standard#270 Blocker 1). Independence for `INTEROP-AGREE` is
counted over a *canonicalized* codebase identity (strip `.git`, trailing slash, `git+` prefix,
scheme/host case, default port; normalize `scp`-style remotes), so `…/impl` and `…/impl.git` are
one codebase and two wrappers over one implementation are not independent (Blocker 2). When
structural inference is insufficient, an adapter may carry an explicit `provenanceCodebase`
assertion that the runner records and uses instead of inferring independence from the URL.

The runner launches multiple external adapters over the subprocess protocol (`--adapter`
repeatable, or a `--config` file) and enforces a per-adapter wall-clock timeout and bounded output.
A hung/crashing/flooding adapter is recorded as `UNAVAILABLE` and abstains on every vector —
fail-closed (Blocker 3). Shipping a *second genuinely independent* implementation adapter plus a
pinned adapter manifest (Blocker 4) remains open and out of scope for this seed.

## Operations

- F1 `canonicalize`: RFC 8785 canonical bytes, hex encoded.
- F2 `signedScopeHash`: SHA-256 over the applicable artifact's canonical signed scope.
- F3 `signatureValueVerdict`: algorithm-independent CORE SIG-6 wire check. Only canonical
  unpadded Base64URL is accepted. Standard Base64 and padded Base64URL are rejected.
- Migration `legacySignatureValueImport`: separate, explicitly selected operation. The caller
  supplies `sourceEncoding` out of band; it is never the conforming verification default.
- F4 `verifyBundle`: optional DACS-5 §10.4 bundle decision, when vectors exist.
- F5 `domainSepSign` / `domainSepVerify`: domain-separated cryptographic operations.

F3 deliberately does not hardcode Ed25519's 64-byte signature length. Decoded length and
cryptographic validity are checked by the contract for the signature's declared algorithm.

## Results and coverage

`SELF-CHECK`, `INTEROP-AGREE`, `VECTOR-MISMATCH`, `IMPLEMENTATION-DIVERGENCE`, `ABSTAIN`, and
explicitly triaged `SPEC-QUESTION` have the distinct meanings in the README table. In
particular, a mismatch or divergence is evidence to triage, not an automatic spec question.

The current source lock declares 49 partner-kit vectors and 3 standalone SIG-6 cases. The
interface executes 40 + 3 = 43 assertions. Nine partner-kit vectors are listed as not executed,
not silently dropped. The default adapter supports every executed operation, so it records zero
per-vector abstentions. F4 has zero shipped vectors and zero executed rows; referenced-artifact
authorization is an aspirational F4 case, not shipped coverage.

The authoritative corpus, expected results, rule/profile references, tiers, and hashes belong
to `DACS-Standard`. The neutral runner consumes a reviewed pinned manifest/release. Candidate
evidence requires two independent real adapters; the reference-only run remains a self-check.
