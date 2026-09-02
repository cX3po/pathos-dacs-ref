# Agreement commitment and bundle finalization adapters

These adapters implement the DACS-3 v0.4 finality commitment and DACS-5 v0.4 evidence-bound bundle surfaces pinned to DACS-Standard `63793a39`.

## Implemented rules

`commitAgreement` implements DACS-3 artifact selection and shape, canonical agreement hashing and buyer/seller signing, and checks 1–9 of §8.5.2 for the supported `commit-agreement` path. That includes CD-1 currency/price validation (including negotiable bands and metered totals), complete-value rail selection, deliverable equality, receipt-relative deadline and expiry, negotiation-pattern and sealed-envelope direction checks, and artifact/commit-phase matching. `commit-payee-bound-agreement` and replacement disposition (APR-5/APR-6) are deliberately refused with typed `NotSupportedError`.

The commitment is a `FinalityCommitmentRecord`, signed by the authenticated orchestrator under `dacs-finality-commitment:v1:` and anchored at `dacs3:commit:{jobId}` (CA-1–CA-9). The adapter independently re-fetches the signed agreement when it is anchored and the commitment record, verifies the CORE §5.1 receipt binding (SR2-4–SR2-7), requires `state:"finalized"`, and derives `committedAt` only from `blockRef.timestamp`. It never emits the legacy `CommitmentRecord`.

`finalizeBundle` recomputes the effective pipeline, including an authenticated agreement selection for `pay-alternative`, and emits a contiguous, pipeline-indexed `phaseSummary` (SEB-1). It resolves every executed DACS-4 payment/delivery result, rejects duplicate or non-bijective references (SEB-2/SEB-4), verifies the record shape, job/index/kind/outcome binding, signature, phase-orchestrator authorship and receipt writer (SEB-3), and makes optional per-phase pointers equal the corresponding top-level reference (SEB-5). Deterministic contradictions reject before anchoring (SEB-6). Completed dependencies and bundle copies require independent resolution and finalized receipts (ST-11/SR2-9).

The default output is `EvidenceBoundFaultAttestationBundle`, signed under `dacs-evidence-bound-fault-bundle:v1:`. `kind:"fab"` selects `FaultAttestationBundle` and `dacs-fault-bundle:v1:`. Buyer and seller sign every non-abort output; a distinct injected orchestrator also signs. Role-specific copies are anchored at `stor-{sha256(jobId + "-bundle-" + role)}` and, when `publishBundleBinding` is supplied, a signed `BundleBinding` is published for each write (BB-1–BB-8). `bundleVersion:"1"` is never emitted. The verifier dispatches by the mutually exclusive discriminator while preserving legacy reads.

## Local decisions and conventions

1. A bundle's `agreementRef` references the finalized DACS-3 commitment record required by ST-11. The commitment carries `agreementHash`; an agreement artifact reference also carries that content hash where its schema permits.
2. The optional agreement-artifact anchor uses `dacs3:agreement:{jobId}` as a local implementation convention, not a DACS logical-address assignment. The mandatory commitment address is `dacs3:commit:{jobId}`.
3. EBFAB is the default; `kind:"fab"` is the explicit compatibility option. Legacy `bundleVersion:"1"` is read-only.
4. Top-level evidence references are emitted in executed phase-index order. This is a local deterministic rule; DACS requires exactness and preserves array order but does not prescribe a general sort.
5. `src/demos/storage.ts` does not prove CORE finality. Both adapters therefore inject `receiptProvider`, which must return authenticated status, logical/native address, content hash, transaction, writer, nonce, and `blockRef.timestamp`. Production throws for a non-final commitment receipt; cold verification returns `indeterminate`. A live Demos receipt provider is follow-up work.
6. Evidence authorship is established cryptographically: the evidence signer and receipt writer must both equal the authenticated orchestrator for that phase. Caller booleans are not accepted as authority.
7. The shared verifier dispatches among legacy, FAB and EBFAB discriminators and matching signing domains; legacy tests remain supported.

## Out of scope

Payee-bound agreements, APR-6 replacement disposition, ST-8 supersession graphs, a live Demos CORE receipt provider, live gateway wiring, private/encrypted agreement retention, non-Ed25519 signing implementations, pointer publication/fetching, and retries of anchor/broadcast operations are outside this change. The adapters do not modify `src/live/organ-gateway.mts`.
