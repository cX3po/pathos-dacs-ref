/**
 * Structural verifier for spec/SDK SettlementEvidence V1 (§9.7).
 *
 * §7.5.1 decision discipline (do-not-collapse): the verdict is one of
 *   - 'pass'          — structurally valid AND all §9.7/PC-2/PC-6 invariants hold
 *   - 'fail'          — a definite spec violation (wrong shape, bad phaseIndex,
 *                       missing/forbidden settlementFinality, bad outcome enum)
 *   - 'indeterminate' — cannot be evaluated (reserved; not produced by the pure
 *                       structural checks here, but the type is kept so callers
 *                       never coerce an unknown into 'pass')
 *   - 'error'         — malformed / not an object / unparseable input
 *
 * Invariants enforced (all FAIL on violation):
 *   - shape: object carrying evidenceVersion:"1", jobId (non-empty string),
 *     phase (string), outcome, observedAt (number).
 *   - phaseIndex: present, a SAFE integer ≥ 0. Matches the SDK/cross-impl fixture
 *     convention (phaseIndex carried in the evidence body); the spec §9.7 type block
 *     does not list it — to be reconciled with RB. (F4; was attributed to PC-2.)
 *   - outcome ∈ {success, failure}.
 *   - PC-6 finality binding:
 *       · a PAYMENT record with outcome:"success" MUST carry settlementFinality.
 *       · a PAYMENT record with outcome:"failure" MUST NOT carry settlementFinality. (F2)
 *       · a DELIVERY record MUST NOT carry settlementFinality.
 *   - nested validation tightened to match Marius's SDK verifier
 *     (_dacs-verify/src/dacs4/settlement.ts ~L235/261/306/317) — F3:
 *       · paymentTxRefs entries are {rail,txHash,kind?} objects — rail+txHash required, kind optional (SDK isChainTxRef)
 *       · deliverableContentHash is lowercase 64-hex
 *       · settlementFinality.model is a known string, finalityBlocks (if present) an
 *         integer, finalityObservedAt a safe-integer number
 *     A MALFORMED ROOT (not an object) → 'error'; field-level violations → 'fail'.
 *   - payment vs delivery discrimination is by the present fields (paymentTxRefs/
 *     paymentAmount ⇒ payment; deliverableContentHash/deliverableAnchor ⇒ delivery).
 *
 * SCOPE: structurally convergent with the SDK on the success-fixture shape; not a
 * field-for-field mirror of the SDK's isStructurallySupported (e.g. open-world
 * unknown fields per SIG-5 are tolerated).
 */

export type SettlementEvidenceV1Decision = 'pass' | 'fail' | 'indeterminate' | 'error';

export interface VerifySettlementEvidenceV1Result {
  decision: SettlementEvidenceV1Decision;
  /** Stable reason codes for the (first) determining check; empty on pass. */
  reasons: string[];
}

const ok = (): VerifySettlementEvidenceV1Result => ({ decision: 'pass', reasons: [] });
const fail = (...reasons: string[]): VerifySettlementEvidenceV1Result => ({ decision: 'fail', reasons });
const err = (...reasons: string[]): VerifySettlementEvidenceV1Result => ({ decision: 'error', reasons });

function isObject(x: unknown): x is Record<string, unknown> {
  return !!x && typeof x === 'object' && !Array.isArray(x);
}

/** Lowercase 64-hex hash (sha256), matching the SDK's HASH_RE (settlement.ts L123). */
const HASH_RE = /^[0-9a-f]{64}$/;

/** Known §9.7 settlementFinality models (settlement.ts isSettlementFinality L437). */
const FINALITY_MODELS: ReadonlySet<string> = new Set([
  'block-depth', 'commitment-level', 'provider-receipt', 'htlc-reveal', 'liquidity-tank',
]);
const FINALITY_COMMITMENTS: ReadonlySet<string> = new Set(['processed', 'confirmed', 'finalized']);

/**
 * A §9.7 ChainTxRef entry. The SDK's isChainTxRef (settlement.ts L506) requires
 * ONLY rail+txHash (non-empty strings); `kind` is `kind?: string` — OPTIONAL. So
 * the verifier validates rail+txHash as required and, IF kind is present, requires
 * it to be a string. (F2) The emitter still EMITS kind for the success fixtures
 * (they carry it) — but the verifier MUST NOT reject an entry that omits it.
 */
function isPaymentTxRef(tx: unknown): boolean {
  return isObject(tx)
    && typeof tx.rail === 'string' && tx.rail.length > 0
    && typeof tx.txHash === 'string' && tx.txHash.length > 0
    && (tx.kind === undefined || typeof tx.kind === 'string');
}

/** §9.7 SettlementFinalityRecord shape validation (settlement.ts isSettlementFinality L436). */
function isValidFinality(f: unknown): boolean {
  if (!isObject(f)) return false;
  if (typeof f.model !== 'string' || !FINALITY_MODELS.has(f.model)) return false;
  if (typeof f.finalityObservedAt !== 'number' || !Number.isSafeInteger(f.finalityObservedAt)) return false;
  if (f.finalityBlocks !== undefined && (typeof f.finalityBlocks !== 'number' || !Number.isSafeInteger(f.finalityBlocks))) return false;
  if (f.finalityCommitmentLevel !== undefined && (typeof f.finalityCommitmentLevel !== 'string' || !FINALITY_COMMITMENTS.has(f.finalityCommitmentLevel))) return false;
  return true;
}

/**
 * Verify a parsed SettlementEvidence V1. Pass a raw `unknown` (e.g. JSON.parse
 * output); non-objects / malformed input → decision 'error', never 'fail'.
 */
export function verifySettlementEvidenceV1(e: unknown): VerifySettlementEvidenceV1Result {
  if (!isObject(e)) return err('malformed: evidence is not a JSON object');

  // --- structural shape ---------------------------------------------------
  if (e.evidenceVersion !== '1') return fail(`shape: evidenceVersion must be "1" (got ${JSON.stringify(e.evidenceVersion)})`);
  if (typeof e.jobId !== 'string' || e.jobId.length === 0) return fail('shape: jobId must be a non-empty string');
  if (typeof e.phase !== 'string' || e.phase.length === 0) return fail('shape: phase must be a non-empty string');
  // SDK uses Number.isSafeInteger (settlement.ts L308) — reject 1.5 / 1e20. (F1)
  if (typeof e.observedAt !== 'number' || !Number.isSafeInteger(e.observedAt)) return fail('shape: observedAt must be a safe integer (unix ms)');

  // --- outcome enum -------------------------------------------------------
  if (e.outcome !== 'success' && e.outcome !== 'failure') {
    return fail(`outcome: must be one of {success,failure} (got ${JSON.stringify(e.outcome)})`);
  }

  // --- phaseIndex ---------------------------------------------------------
  // Matches the SDK/cross-impl fixture convention (phaseIndex carried in the evidence
  // body); the spec §9.7 type block does not list it — to be reconciled with RB. (F4)
  // SDK uses Number.isSafeInteger (settlement.ts L306), so mirror that (F3).
  if (!('phaseIndex' in e)) return fail('phaseIndex: REQUIRED (SDK/cross-impl fixture convention; not in §9.7 type block — reconcile with RB)');
  if (typeof e.phaseIndex !== 'number' || !Number.isSafeInteger(e.phaseIndex) || e.phaseIndex < 0) {
    return fail(`phaseIndex: must be a safe integer ≥ 0 (got ${JSON.stringify(e.phaseIndex)})`);
  }

  // --- payment vs delivery discrimination ---------------------------------
  const hasPaymentFields = 'paymentTxRefs' in e || 'paymentAmount' in e;
  const hasDeliveryFields = 'deliverableContentHash' in e || 'deliverableAnchor' in e;
  const hasFinality = 'settlementFinality' in e && e.settlementFinality !== undefined;

  if (hasPaymentFields && hasDeliveryFields) {
    return fail('shape: record mixes payment and delivery fields (not a valid §9.7 variant)');
  }

  if (hasDeliveryFields) {
    // DELIVERY: settlementFinality MUST be absent (PC-6).
    if (hasFinality) return fail('PC-6: delivery evidence MUST NOT carry settlementFinality');
    // deliverableContentHash MUST be a lowercase 64-hex sha256 (settlement.ts L319). (F3)
    if (typeof e.deliverableContentHash !== 'string' || !HASH_RE.test(e.deliverableContentHash)) {
      return fail('shape: delivery deliverableContentHash must be a lowercase 64-hex sha256');
    }
    if (!isObject(e.deliverableAnchor)
      || typeof e.deliverableAnchor.kind !== 'string' || e.deliverableAnchor.kind.length === 0
      || typeof e.deliverableAnchor.locator !== 'string' || e.deliverableAnchor.locator.length === 0) {
      return fail('shape: delivery evidence requires deliverableAnchor {kind,locator}');
    }
    return ok();
  }

  if (hasPaymentFields) {
    // PAYMENT
    // paymentTxRefs MUST be an array of {rail,txHash,kind?} objects — rail+txHash required, kind optional (matches SDK isChainTxRef, settlement.ts L506). (F3)
    if (!Array.isArray(e.paymentTxRefs)) return fail('shape: payment evidence requires a paymentTxRefs array');
    if (!e.paymentTxRefs.every(isPaymentTxRef)) {
      return fail('shape: each paymentTxRefs entry must be a {rail,txHash,kind?} object (rail+txHash required; kind optional)');
    }
    if (!isObject(e.paymentAmount) || typeof e.paymentAmount.amount !== 'string' || typeof e.paymentAmount.currency !== 'string') {
      return fail('shape: payment evidence requires paymentAmount {amount,currency}');
    }
    // PC-6: success-outcome payment evidence MUST carry settlementFinality.
    if (e.outcome === 'success' && !hasFinality) {
      return fail('PC-6: success-outcome payment evidence MUST carry settlementFinality');
    }
    // PC-6 (settlement.ts L240): failure-outcome payment evidence MUST NOT carry
    // settlementFinality — finality is forbidden outside success-payment. (F2)
    if (e.outcome === 'failure' && hasFinality) {
      return fail('PC-6: failure-outcome payment evidence MUST NOT carry settlementFinality');
    }
    // settlementFinality, when present, MUST match the §9.7 SettlementFinalityRecord
    // shape (model known, finalityBlocks int, finalityObservedAt safe-int number). (F3)
    if (hasFinality && !isValidFinality(e.settlementFinality)) {
      return fail('shape: settlementFinality requires {model∈known, finalityBlocks?:int, finalityObservedAt:int}');
    }
    return ok();
  }

  return fail('shape: record is neither a payment nor a delivery evidence (no payment/delivery fields present)');
}
