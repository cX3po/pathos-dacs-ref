// Independent convergence read for DACS-Standard #230 (RB steward ruling 2026-07-11):
// "a conforming DACS-5 derive() MUST exclude a canonically-divergent jobId from ALL metrics and
//  MUST NOT select either party's copy for party-specific reputation."
//
// This mirrors RB's `verify-reputation-divergence-excluded` case against OUR independent impl
// (vendor/dacs-verify deriveReputation): feed a divergent buyer/seller pair + one clean control
// job to derive(), and prove only the control remains (bundleCount:1, disputed jobId absent from
// bundleRefs, completionRate:1). No network, no crypto — plain bundle objects exercise the
// §10.5.1 reconciliation guards directly.
import { deriveReputation, type AttestationBundle } from "./vendor/dacs-verify/src/dacs5/index.ts";

const BUYER = "did:key:buyer";
const SELLER = "did:key:seller";

function bundle(jobId: string, anchoredByRole: "buyer" | "seller", outcome: AttestationBundle["outcome"]): AttestationBundle {
  return {
    bundleVersion: "1",
    jobId,
    outcome,
    anchoredByRole,
    listingRef: { listingId: "L1", version: 1, contentHash: "h" },
    parties: [
      { role: "buyer", bundleHash: "bh", primaryClaim: BUYER },
      { role: "seller", bundleHash: "bh", primaryClaim: SELLER },
    ],
    phaseSummary: [],
    vetRecords: [],
    settlementEvidence: [],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1000,
    // both terminal-required signers present so hasRequiredTerminalSigners() passes and the
    // exclusion is driven by canonical divergence, not by a missing-signer drop.
    signatures: [
      { party: BUYER, algorithm: "ed25519", value: "sigB" },
      { party: SELLER, algorithm: "ed25519", value: "sigS" },
    ],
  };
}

// Job A — DIVERGENT: buyer self-copy says "completed"; seller counterparty-copy says "failed-perm".
// perspectiveFlip("failed-perm") = "failed-counterparty" != "completed"  ->  canonicallyDiverges = true.
const jobA_self = bundle("jobA", "buyer", "completed");
const jobA_counter = bundle("jobA", "seller", "failed-perm");

// Job B — CONTROL: a clean completed job with only the buyer's own anchored copy.
const jobB_self = bundle("jobB", "buyer", "completed");

const roleOf = (jobId: string): "buyer" | "seller" | undefined =>
  jobId === "jobA" || jobId === "jobB" ? "buyer" : undefined;

const d = deriveReputation(BUYER, roleOf, [jobA_self, jobA_counter, jobB_self], 0, 2000, 1500, {});

const refIds = d.bundleRefs.map((r) => r.id);
const checks = {
  bundleCount_is_1: d.bundleCount === 1,
  disputed_jobA_absent: !refIds.includes("jobA"),
  control_jobB_present: refIds.includes("jobB"),
  completionRate_is_1: d.metrics.completionRate === 1,
};
const pass = Object.values(checks).every(Boolean);

console.log(JSON.stringify({
  scenario: "divergent(jobA) + control(jobB) -> derive(buyer)",
  bundleCount: d.bundleCount,
  bundleRefs: refIds,
  completionRate: d.metrics.completionRate,
  checks,
  RESULT: pass ? "CONVERGES-WITH-RULING (#230)" : "DIVERGES",
}, null, 2));
process.exit(pass ? 0 : 1);
