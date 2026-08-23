import type { IdentityBundle } from "../dacs1.ts";
import {
  verifyDisputeRecord,
  verifyArbitratorCredential,
  verifyDisputeOutcome,
  reputationReweight,
  type DisputeCheck,
} from "./dispute.ts";
import type {
  DisputeRecord,
  DisputeOutcome,
  DisputedBundleRef,
  ArbitrationRule,
  SessionReputationContribution,
  ReputationReweight,
} from "./types.ts";

// End-to-end DACS-X dispute flow, returning the spec's 4-value decision shape
// (§7.5 VerifyResult): pass | fail | indeterminate | error.
//   - pass          : record + arbitrator + outcome all verify
//   - indeterminate : record + arbitrator verify, but no outcome yet (open)
//   - fail          : a verification step returned a definite negative
//   - error         : a step threw (malformed input, bad key, etc.)

export type DisputeDecision = "pass" | "fail" | "indeterminate" | "error";

export interface DisputeFlowInput {
  record: DisputeRecord;
  initiatorPublicKeyRaw: Uint8Array;
  knownBundles: DisputedBundleRef[];
  arbitratorBundle: IdentityBundle;
  agreedRule: ArbitrationRule;
  now: number;
  /** Outcome + arbitrator key are absent while the dispute is still open. */
  outcome?: DisputeOutcome;
  arbitratorPublicKeyRaw?: Uint8Array;
  /** Optional reputation contribution to reweight on a passing outcome. */
  priorReputation?: SessionReputationContribution;
}

export interface DisputeFlowStep {
  name: string;
  ok: boolean;
  reason?: string;
}

export interface DisputeFlowResult {
  decision: DisputeDecision;
  steps: DisputeFlowStep[];
  reweighted?: ReputationReweight;
}

export function verifyDisputeFlow(input: DisputeFlowInput): DisputeFlowResult {
  const steps: DisputeFlowStep[] = [];

  const step = (name: string, fn: () => DisputeCheck): boolean => {
    const r = fn(); // may throw → caught below as `error`
    if (r.ok) {
      steps.push({ name, ok: true });
      return true;
    }
    steps.push({ name, ok: false, reason: r.reason });
    return false;
  };

  try {
    const recordOk = step("dispute-record", () =>
      verifyDisputeRecord(input.record, input.initiatorPublicKeyRaw, input.knownBundles),
    );
    const credOk = step("arbitrator-credential", () =>
      verifyArbitratorCredential(input.arbitratorBundle, input.record, input.agreedRule, input.now),
    );
    if (!recordOk || !credOk) return { decision: "fail", steps };

    if (!input.outcome || !input.arbitratorPublicKeyRaw) {
      steps.push({ name: "dispute-outcome", ok: false, reason: "no outcome yet — dispute pending" });
      return { decision: "indeterminate", steps };
    }

    const outcome = input.outcome;
    const arbKey = input.arbitratorPublicKeyRaw;
    const outcomeOk = step("dispute-outcome", () =>
      verifyDisputeOutcome(outcome, arbKey, input.record),
    );
    if (!outcomeOk) return { decision: "fail", steps };

    // Omit `reweighted` entirely when there is no prior reputation
    // (exactOptionalPropertyTypes): never assign undefined to an optional field.
    return input.priorReputation
      ? { decision: "pass", steps, reweighted: reputationReweight(input.priorReputation, outcome) }
      : { decision: "pass", steps };
  } catch (e) {
    steps.push({ name: "exception", ok: false, reason: `error: ${(e as Error).message}` });
    return { decision: "error", steps };
  }
}
