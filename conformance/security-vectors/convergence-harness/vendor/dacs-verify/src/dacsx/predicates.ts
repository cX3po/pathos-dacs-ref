import { sha256Hex } from "../hash.ts";

/** Hashlock algorithm pinned by destination-chain rail selection. */
export const HASHLOCK_ALGO_BY_CHAIN = {
  evm: "keccak256",
  solana: "sha256",
  cosmos: "blake2b",
} as const;

export type DacsxDestinationChain = keyof typeof HASHLOCK_ALGO_BY_CHAIN;
export type DacsxHashlockAlgorithm =
  (typeof HASHLOCK_ALGO_BY_CHAIN)[DacsxDestinationChain];

export type RecomputeHashlock = (
  chain: DacsxDestinationChain,
  preimageHex: string,
) => string;

export type CrossChainHtlcStateInput = {
  destChain: DacsxDestinationChain;
  destHashlock: string;
  revealedPreimage?: string;
  sourceClaimObserved: boolean;
  recomputeHashlock?: RecomputeHashlock;
};

export type CrossChainHtlcState =
  | "dest-revealed-source-unclaimed"
  | "settled-symmetric"
  | "benign-timeout";

export type CrossChainHtlcStateResult = {
  state: CrossChainHtlcState;
  destRevealed: boolean;
  sourceUnclaimed: boolean;
  algoUsed: DacsxHashlockAlgorithm;
};

export type SettlementAmendmentType =
  | "refund"
  | "partial-refund"
  | "correction";

export type AmendmentSelectionResult =
  | {
      amendmentType: SettlementAmendmentType;
      isSettlementAmendment: true;
    }
  | {
      amendmentType: "timelock-refund-path";
      isSettlementAmendment: false;
    };

export type RefundAmendmentSelectionInput = {
  outcome: "success";
  destValueReceived: boolean;
  sourceClaimLanded: boolean;
  refundOrdered: true;
  partial: boolean;
  refundAmount?: string;
};

export type SuccessNoRefundSelectionInput = {
  outcome: "success";
  destValueReceived: boolean;
  sourceClaimLanded: boolean;
  refundOrdered: false;
  partial: boolean;
  refundAmount?: string;
};

export type FailureCorrectionSelectionInput = {
  outcome: "failure";
  destValueReceived: true;
  sourceClaimLanded: boolean;
  refundOrdered: false;
  partial: boolean;
};

export type FailureTimelockSelectionInput = {
  outcome: "failure";
  destValueReceived: false;
  sourceClaimLanded: boolean;
  refundOrdered: false;
  partial: boolean;
};

export type FailureInvalidRefundSelectionInput = {
  outcome: "failure";
  destValueReceived: boolean;
  sourceClaimLanded: boolean;
  refundOrdered: true;
  partial: boolean;
  refundAmount?: string;
};

export type FailureCorrectionInvalidRefundAmountInput = {
  outcome: "failure";
  destValueReceived: true;
  sourceClaimLanded: boolean;
  refundOrdered: false;
  partial: boolean;
  refundAmount: string;
};

export type AmendmentSelectionInput =
  | RefundAmendmentSelectionInput
  | SuccessNoRefundSelectionInput
  | FailureCorrectionSelectionInput
  | FailureTimelockSelectionInput
  | FailureInvalidRefundSelectionInput
  | FailureCorrectionInvalidRefundAmountInput;

export type SupersessionOutcome = {
  disputeId: string;
  decidedAt: number;
  contentHash: string;
  supersedes?: string;
  anchorTimestamp?: number;
};

export type SupersessionOptions = {
  maxSkewMs?: number;
};

export type RejectedSupersessionOutcome = {
  outcome: SupersessionOutcome;
  reason: string;
};

export type SupersessionOrderResult = {
  honored: SupersessionOutcome | null;
  rejected: RejectedSupersessionOutcome[];
};

/** Default skew window for anchor-vs-decision anti-backdating validation. */
export const DEFAULT_MAX_SKEW_MS = 300_000;

/**
 * Recompute a destination hashlock using the rail-pinned algorithm.
 *
 * The default sha256 path treats `preimageHex` as a UTF-8 string, matching the
 * repo demo semantics from the task specification rather than hex decoding.
 */
export const defaultRecomputeHashlock: RecomputeHashlock = (
  chain,
  preimageHex,
) => {
  const algo: DacsxHashlockAlgorithm = HASHLOCK_ALGO_BY_CHAIN[chain];
  if (algo === "sha256") {
    return sha256Hex(preimageHex);
  }

  throw new Error(`hashlock-algo-unavailable: ${algo} requires substrate lib`);
};

/**
 * Classify asymmetric HTLC settlement state from destination reveal evidence.
 */
export function classifyCrossChainHtlcState(
  input: CrossChainHtlcStateInput,
): CrossChainHtlcStateResult {
  const algoUsed: DacsxHashlockAlgorithm =
    HASHLOCK_ALGO_BY_CHAIN[input.destChain];
  const recomputeHashlock: RecomputeHashlock =
    input.recomputeHashlock ?? defaultRecomputeHashlock;

  let destRevealed = false;
  if (input.revealedPreimage != null) {
    let recomputedHashlock: unknown;
    try {
      recomputedHashlock = recomputeHashlock(
        input.destChain,
        input.revealedPreimage,
      );
    } catch (error: unknown) {
      const message: string =
        error instanceof Error ? error.message : String(error);
      throw new Error(`hashlock-resolver-failed: ${message}`);
    }

    if (typeof recomputedHashlock !== "string") {
      throw new Error("hashlock-resolver-invalid: expected string result");
    }

    destRevealed = recomputedHashlock === input.destHashlock;
  }

  const sourceUnclaimed = !input.sourceClaimObserved;
  if (destRevealed && sourceUnclaimed) {
    return {
      state: "dest-revealed-source-unclaimed",
      destRevealed,
      sourceUnclaimed,
      algoUsed,
    };
  }

  if (destRevealed && input.sourceClaimObserved) {
    return {
      state: "settled-symmetric",
      destRevealed,
      sourceUnclaimed,
      algoUsed,
    };
  }

  return {
    state: "benign-timeout",
    destRevealed,
    sourceUnclaimed,
    algoUsed,
  };
}

/**
 * Select the settlement remedy branch required by §9.7.1 amendment rules.
 */
export function selectAmendmentType(
  input: AmendmentSelectionInput,
): AmendmentSelectionResult {
  if (input.outcome === "failure" && input.refundOrdered) {
    throw new Error(
      "AMEND-2 violation: failure outcome cannot be unwound via refund amendment",
    );
  }

  if (input.outcome === "failure" && input.destValueReceived) {
    if ("refundAmount" in input) {
      throw new Error(
        "correction amendment cannot include refundAmount",
      );
    }

    return {
      amendmentType: "correction",
      isSettlementAmendment: true,
    };
  }

  if (input.outcome === "failure" && !input.destValueReceived) {
    return {
      amendmentType: "timelock-refund-path",
      isSettlementAmendment: false,
    };
  }

  if (input.outcome === "success" && input.refundOrdered) {
    return {
      amendmentType: input.partial ? "partial-refund" : "refund",
      isSettlementAmendment: true,
    };
  }

  return {
    amendmentType: "correction",
    isSettlementAmendment: true,
  };
}

function compareSupersessionOutcome(
  left: SupersessionOutcome,
  right: SupersessionOutcome,
): number {
  if (left.decidedAt !== right.decidedAt) {
    return left.decidedAt - right.decidedAt;
  }

  return left.contentHash.localeCompare(right.contentHash);
}

/**
 * Choose the honored dispute outcome under monotonicity and anti-backdating.
 */
export function supersessionOrder(
  outcomes: SupersessionOutcome[],
  opts?: SupersessionOptions,
): SupersessionOrderResult {
  if (outcomes.length === 0) {
    return { honored: null, rejected: [] };
  }

  const maxSkewMs = opts?.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
  const rejected: RejectedSupersessionOutcome[] = [];
  const accepted: SupersessionOutcome[] = [];
  let currentMax: SupersessionOutcome | null = null;

  for (const outcome of outcomes) {
    if (
      outcome.anchorTimestamp != null &&
      Math.abs(outcome.decidedAt - outcome.anchorTimestamp) > maxSkewMs
    ) {
      rejected.push({
        outcome,
        reason: "backdated: decidedAt diverges from anchor beyond skew",
      });
      continue;
    }

    if (currentMax == null) {
      accepted.push(outcome);
      currentMax = outcome;
      continue;
    }

    if (compareSupersessionOutcome(outcome, currentMax) <= 0) {
      const supersedesTarget = outcome.supersedes;
      if (supersedesTarget == null) {
        rejected.push({
          outcome,
          reason: "non-monotonic: decidedAt must increase unless explicitly superseding",
        });
        continue;
      }

      const matchesPrior = accepted.some(
        (acceptedOutcome) =>
          acceptedOutcome.disputeId === supersedesTarget ||
          acceptedOutcome.contentHash === supersedesTarget,
      );
      if (!matchesPrior) {
        rejected.push({
          outcome,
          reason:
            "non-monotonic: supersedes must name a prior disputeId or contentHash",
        });
        continue;
      }
    }

    accepted.push(outcome);
    if (compareSupersessionOutcome(outcome, currentMax) > 0) {
      currentMax = outcome;
    }
  }

  return {
    honored: currentMax,
    rejected,
  };
}
