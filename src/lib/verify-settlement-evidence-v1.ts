/**
 * Structural verifier for spec/SDK SettlementEvidence V1 (§9.7).
 *
 * §7.5.1 decision discipline (do-not-collapse): the verdict is one of
 *   - 'pass'          — structurally valid AND all §9.7/PC-6/CD-1 invariants hold
 *   - 'fail'          — a definite spec violation
 *   - 'indeterminate' — cannot be evaluated (reserved; not produced by the pure
 *                       structural checks here, but the type is kept so callers
 *                       never coerce an unknown into 'pass')
 *   - 'error'         — malformed / not an object / unparseable input
 *
 * Derived from the DACS-4 normative text (NOT fitted to any impl's tests):
 *   - shape: evidenceVersion:"1", jobId (non-empty string), observedAt (safe int).
 *   - phase: MUST be drawn from the CLOSED §9.4 payment / §9.6 delivery sets
 *     ("a closed set of delivery phases", DACS-4 intro) — the phase is the
 *     variant discriminant; an unknown phase kind fails closed (§11.1.2 posture).
 *   - outcome ∈ {success, failure}.
 *   - PAYMENT evidence:
 *       · success MUST carry paymentTxRefs (non-empty), paymentAmount
 *         ("REQUIRED on any success-outcome evidence record", §9.7) and
 *         settlementFinality (PC-6).
 *       · failure MUST NOT carry settlementFinality (§9.7: "absent on delivery
 *         evidence and on failure-outcome payment evidence"). (F2)
 *       · paymentAmount/paymentFee amounts MUST be CD-1 canonical (CORE CD-1:
 *         producers canonicalise before any SettlementEvidence hash) and
 *         paymentAmount MUST be strictly > 0 ("PriceTerm.amount positivity",
 *         DACS-4 §9.2); a fee is never negative.
 *       · paymentTxRefs entries are {rail,txHash,kind?} — rail+txHash required,
 *         kind optional (SDK isChainTxRef convergence, F3).
 *   - DELIVERY evidence:
 *       · MUST NOT carry settlementFinality (PC-6).
 *       · deliverableContentHash MUST be a lowercase 64-hex sha256.
 *       · deliverableAnchor {kind,locator} required; a deliver-storage-program
 *         record's anchor kind MUST be "storage-program" (§9.6.1 step 5).
 *       · a STRAY payment-shaped field is tolerated (SIG-5 open-world; no §9.7
 *         rule forbids it — only settlementFinality is forbidden off payment).
 *   - phaseIndex: NOT required and NOT rejected. SB-1 (§9.5.8) is explicit that
 *     phaseIndex "is not a new evidence field: it is recovered from the §9.5.2
 *     payment-evidence anchor address" — so an in-body phaseIndex is an
 *     open-world extra, tolerated but validated when present (safe int ≥ 0).
 *     NOTE: the merged §14 fixtures DO carry it in-body (hash-significant),
 *     which conflicts with SB-1's wording — raised upstream (dacs-sdk #28
 *     convergence read). Supersedes the earlier F4 required-phaseIndex reading.
 *   - reason: validated as a non-empty string when present. Whether a
 *     failure-outcome record MUST carry it is a genuine spec ambiguity — the
 *     §9.7 type block says `reason?: string // when outcome == "failure"`
 *     (presence-scoping, not clearly requiredness). We do NOT enforce
 *     required-on-failure; the divergence vs dacs-sdk #28 (which does) is
 *     raised upstream rather than silently matched.
 *
 * A MALFORMED ROOT (not an object) → 'error' (unparseable input, not a definite
 * record-level violation); field-level violations → 'fail'. (dacs-sdk #28 grades
 * a non-object root 'fail' — a four-value philosophy divergence, raised upstream.)
 */

import { canonicalPrice } from '../types/settle.js';

export type SettlementEvidenceV1Decision = 'pass' | 'fail' | 'indeterminate' | 'error';

export interface VerifySettlementEvidenceV1Result {
  decision: SettlementEvidenceV1Decision;
  /** Stable reason strings for every violated check; empty on pass. */
  reasons: string[];
}

function isObject(x: unknown): x is Record<string, unknown> {
  return !!x && typeof x === 'object' && !Array.isArray(x);
}

/** Lowercase 64-hex hash (sha256), matching the SDK's HASH_RE (settlement.ts L123). */
const HASH_RE = /^[0-9a-f]{64}$/;

/** Closed §9.4 payment phase set (PC-1 handlers, incl. §9.5.9 pay-dem). */
const PAYMENT_PHASES: ReadonlySet<string> = new Set([
  'pay-evm-erc20', 'pay-solana-spl', 'pay-cross-chain-htlc',
  'pay-cross-chain-liquidity-tank', 'pay-ap2', 'pay-x402', 'pay-dem',
]);
/** Closed §9.6 delivery phase set ("a closed set of delivery phases"). */
const DELIVERY_PHASES: ReadonlySet<string> = new Set([
  'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload',
]);

/** Known §9.7 settlementFinality models (§9.7 type block incl. bft-final for pay-dem). */
const FINALITY_MODELS: ReadonlySet<string> = new Set([
  'block-depth', 'commitment-level', 'provider-receipt', 'htlc-reveal', 'liquidity-tank', 'bft-final',
]);
const FINALITY_COMMITMENTS: ReadonlySet<string> = new Set(['processed', 'confirmed', 'finalized']);

/**
 * A §9.7 ChainTxRef entry. The SDK's isChainTxRef (settlement.ts L506) requires
 * ONLY rail+txHash (non-empty strings); `kind` is OPTIONAL. The emitter still
 * EMITS kind for the success fixtures — but the verifier MUST NOT reject an
 * entry that omits it. (F3)
 */
function isPaymentTxRef(tx: unknown): boolean {
  return isObject(tx)
    && typeof tx.rail === 'string' && tx.rail.length > 0
    && typeof tx.txHash === 'string' && tx.txHash.length > 0
    && (tx.kind === undefined || typeof tx.kind === 'string');
}

/** §9.7 SettlementFinalityRecord shape validation. */
function isValidFinality(f: unknown): boolean {
  if (!isObject(f)) return false;
  if (typeof f.model !== 'string' || !FINALITY_MODELS.has(f.model)) return false;
  if (typeof f.finalityObservedAt !== 'number' || !Number.isSafeInteger(f.finalityObservedAt)) return false;
  if (f.finalityBlocks !== undefined && (typeof f.finalityBlocks !== 'number' || !Number.isSafeInteger(f.finalityBlocks))) return false;
  if (f.finalityCommitmentLevel !== undefined && (typeof f.finalityCommitmentLevel !== 'string' || !FINALITY_COMMITMENTS.has(f.finalityCommitmentLevel))) return false;
  return true;
}

/** CD-1 canonical? (canonicalising is a no-op). Rejects exponent/spaces via canonicalPrice's grammar. */
function isCanonicalCD1(amount: unknown): amount is string {
  if (typeof amount !== 'string') return false;
  try {
    return canonicalPrice({ amount, asset: '' }) === amount;
  } catch {
    return false;
  }
}

/** Strictly positive canonical decimal (never negative, not zero) — PriceTerm positivity (§9.2). */
function isStrictlyPositive(amount: string): boolean {
  return !amount.startsWith('-') && /[1-9]/.test(amount);
}

/**
 * Verify a parsed SettlementEvidence V1. Pass a raw `unknown` (e.g. JSON.parse
 * output); non-objects / malformed input → decision 'error', never 'fail'.
 */
export function verifySettlementEvidenceV1(e: unknown): VerifySettlementEvidenceV1Result {
  if (!isObject(e)) return { decision: 'error', reasons: ['malformed: evidence is not a JSON object'] };

  const reasons: string[] = [];
  const fail = (r: string) => { reasons.push(r); };

  // --- structural shape ---------------------------------------------------
  if (e.evidenceVersion !== '1') fail(`shape: evidenceVersion must be "1" (got ${JSON.stringify(e.evidenceVersion)})`);
  if (typeof e.jobId !== 'string' || e.jobId.length === 0) fail('shape: jobId must be a non-empty string');
  // SDK uses Number.isSafeInteger (settlement.ts L308) — reject 1.5 / 1e20. (F1)
  if (typeof e.observedAt !== 'number' || !Number.isSafeInteger(e.observedAt)) fail('shape: observedAt must be a safe integer (unix ms)');

  // --- phase: the closed-set variant discriminant ---------------------------
  const phase = typeof e.phase === 'string' ? e.phase : '';
  const isPayment = PAYMENT_PHASES.has(phase);
  const isDelivery = DELIVERY_PHASES.has(phase);
  if (!isPayment && !isDelivery) {
    fail(`phase: "${String(e.phase)}" is not a §9.4 payment or §9.6 delivery phase (closed sets; unknown kinds fail closed)`);
  }

  // --- outcome enum ---------------------------------------------------------
  if (e.outcome !== 'success' && e.outcome !== 'failure') {
    fail(`outcome: must be one of {success,failure} (got ${JSON.stringify(e.outcome)})`);
  }

  // --- reason (validated when present; requiredness-on-failure is a raised spec ambiguity) ---
  if ('reason' in e && e.reason !== undefined && (typeof e.reason !== 'string' || e.reason.length === 0)) {
    fail('shape: reason, when present, must be a non-empty string');
  }

  // --- phaseIndex: open-world extra (SB-1: not an evidence field) — validate when present ---
  if ('phaseIndex' in e && e.phaseIndex !== undefined) {
    if (typeof e.phaseIndex !== 'number' || !Number.isSafeInteger(e.phaseIndex) || e.phaseIndex < 0) {
      fail(`phaseIndex: when present must be a safe integer ≥ 0 (got ${JSON.stringify(e.phaseIndex)})`);
    }
  }

  const hasFinality = 'settlementFinality' in e && e.settlementFinality !== undefined;

  // --- payment-phase rules --------------------------------------------------
  if (isPayment) {
    const txRefs = e.paymentTxRefs;
    const amount = e.paymentAmount;

    if (e.outcome === 'success') {
      if (!Array.isArray(txRefs) || txRefs.length === 0) fail('§9.7: success payment evidence MUST carry non-empty paymentTxRefs');
      if (amount === undefined) fail('§9.7: paymentAmount is REQUIRED on success-outcome payment evidence (AMEND-3 basis)');
      if (!hasFinality) fail('PC-6: success-outcome payment evidence MUST carry settlementFinality');
    }
    // PC-6 / §9.7: finality is "absent on delivery evidence and on failure-outcome payment evidence". (F2)
    if (e.outcome === 'failure' && hasFinality) {
      fail('PC-6: failure-outcome payment evidence MUST NOT carry settlementFinality');
    }
    if (hasFinality && !isValidFinality(e.settlementFinality)) {
      fail('shape: settlementFinality requires {model∈known, finalityBlocks?:int, finalityObservedAt:int}');
    }
    if (txRefs !== undefined) {
      if (!Array.isArray(txRefs) || !txRefs.every(isPaymentTxRef)) {
        fail('shape: each paymentTxRefs entry must be a {rail,txHash,kind?} object (rail+txHash required; kind optional)');
      }
    }
    if (amount !== undefined) {
      if (!isObject(amount) || typeof amount.currency !== 'string' || amount.currency.length === 0) {
        fail('shape: paymentAmount requires {amount, currency} with a non-empty currency');
      } else if (!isCanonicalCD1(amount.amount)) {
        fail('CD-1: paymentAmount.amount must be a canonical minimal-digit decimal string');
      } else if (!isStrictlyPositive(amount.amount)) {
        fail('§9.2: PriceTerm.amount must be strictly greater than zero');
      }
    }
    const fee = e.paymentFee;
    if (fee !== undefined) {
      if (!isObject(fee) || !isCanonicalCD1(fee.amount) || (fee.amount as string).startsWith('-')) {
        fail('CD-1: paymentFee.amount must be a canonical non-negative decimal string');
      }
    }
  }

  // --- delivery-phase rules ---------------------------------------------------
  if (isDelivery) {
    // §9.7/PC-6: delivery evidence MUST NOT carry settlementFinality.
    if (hasFinality) fail('PC-6: delivery evidence MUST NOT carry settlementFinality');
    if (typeof e.deliverableContentHash !== 'string' || !HASH_RE.test(e.deliverableContentHash)) {
      fail('shape: delivery deliverableContentHash must be a lowercase 64-hex sha256');
    }
    const anchor = e.deliverableAnchor;
    if (!isObject(anchor)
      || typeof anchor.kind !== 'string' || anchor.kind.length === 0
      || typeof anchor.locator !== 'string' || anchor.locator.length === 0) {
      fail('shape: delivery evidence requires deliverableAnchor {kind,locator}');
    } else if (phase === 'deliver-storage-program' && anchor.kind !== 'storage-program') {
      // §9.6.1 step 5: deliverableAnchor = {kind: "storage-program", locator}.
      fail(`§9.6.1: deliver-storage-program anchor kind MUST be "storage-program" (got "${String(anchor.kind)}")`);
    }
    // A stray payment-shaped field is TOLERATED (SIG-5 open-world) — only finality is forbidden here.
  }

  return reasons.length > 0 ? { decision: 'fail', reasons } : { decision: 'pass', reasons: [] };
}
