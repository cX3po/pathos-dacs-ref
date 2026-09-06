/**
 * DACS-4 Settle — TypeScript types
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §9 (Settle) — in particular §9.5
 * (SettlementEvidence + HTLC TxRef variants) and the §B.7 universal signature
 * scheme (domain separator "dacs-evidence:v1:", v0.1 §9.7).
 *
 * DACS-4 covers the SETTLE phase: once a price is agreed (DACS-3 Negotiate), the
 * buyer pays and the seller delivers, producing SettlementEvidence that anchors
 * into the DACS-5 AttestationBundle. Settlement happens over a *rail* — a payment
 * mechanism whose availability is not assumed. §9.5 enumerates rail availability
 * so a verifier can tell "no rail wired" (mocked/disabled) apart from "rail tried
 * and failed" (failed) apart from "rail live and settled" (live).
 *
 * The HTLC (Hashed-TimeLock Contract) flow is the canonical cross-substrate
 * atomic-settlement primitive: the buyer locks funds against H = sha256(preimage)
 * on the *source* chain with a longer timelock; the seller reveals `preimage` on
 * the *destination* chain (or claims the source lock) before that timelock; if the
 * seller never reveals, the buyer refunds after the timelock expires. The safety
 * property — and the thing this module's verifier enforces — is the **timelock
 * asymmetry**: the reveal/claim window MUST close strictly before the refund
 * window opens, or the buyer can both refund and be claimed against.
 */

/* -------------------------------------------------------------------------- */
/*  Price terms (backs finding #27)                                            */
/* -------------------------------------------------------------------------- */

/**
 * A price term.
 *
 * **Finding #27:** amounts MUST be carried as a decimal STRING, never a JS
 * `number`. IEEE-754 floats cannot represent most decimal money values exactly
 * (`0.1 + 0.2 !== 0.3`), and JCS canonicalisation of a float is *not* guaranteed
 * to round-trip the value an agent agreed to. Carrying the amount as a string and
 * normalising via {@link canonicalPrice} gives every implementation a reproducible
 * decimal form to hash + sign over.
 */
export interface PriceTerm {
  /** Decimal amount as a STRING (e.g. "1.50", "0.000001"). Never a float. */
  amount: string;
  /** Asset / currency code (e.g. "USDC", "DEM", "USD"). Opaque to this layer. */
  asset: string;
  /**
   * Optional number of decimal places the asset settles in (e.g. 6 for USDC).
   * When present, {@link canonicalPrice} pads/validates the fractional part to it.
   */
  decimals?: number;
}

/**
 * Normalise a {@link PriceTerm} amount to a reproducible canonical decimal string.
 *
 * Rules (deterministic, no floating point — string surgery only):
 *   - reject anything that is not `[-]?digits[.digits]` (no exponent, no spaces)
 *   - strip a single leading '+'; preserve a leading '-' only for a non-zero value
 *   - strip leading zeros in the integer part (but keep one: "007" → "7", "0" → "0")
 *   - strip trailing zeros in the fractional part, then drop a bare '.'
 *   - if `decimals` is given, the fractional part MUST NOT exceed it, and the
 *     result is zero-padded to exactly `decimals` places (so "1.5" with decimals=6
 *     → "1.500000" — a single canonical form per asset precision)
 *   - normalise negative zero to "0"
 *
 * Returns the canonical `{ amount, asset }`-style string `"<amount> <asset>"` is
 * NOT produced here; this returns just the canonical amount so callers can rebuild
 * the PriceTerm. The whole PriceTerm is what gets JCS-canonicalised + signed.
 */
export function canonicalPrice(term: PriceTerm): string {
  const raw = term.amount.trim();
  if (!/^[+-]?\d+(\.\d+)?$/.test(raw)) {
    throw new Error(`canonicalPrice: amount "${term.amount}" is not a plain decimal (no exponent/spaces allowed)`);
  }

  let negative = false;
  let body = raw;
  if (body.startsWith('+')) {
    body = body.slice(1);
  } else if (body.startsWith('-')) {
    negative = true;
    body = body.slice(1);
  }

  // `body` already matched /^[+-]?\d+(\.\d+)?$/, so split always yields a non-empty
  // integer part; the `?? ''` keeps TS happy under noUncheckedIndexedAccess.
  const parts = body.split('.');
  let intPart = parts[0] ?? '';
  let fracPart = parts[1] ?? '';

  // Strip leading zeros in the integer part, keep at least one digit.
  intPart = intPart.replace(/^0+(?=\d)/, '');

  if (term.decimals !== undefined) {
    if (!Number.isInteger(term.decimals) || term.decimals < 0) {
      throw new Error(`canonicalPrice: decimals must be a non-negative integer, got ${term.decimals}`);
    }
    if (fracPart.length > term.decimals) {
      throw new Error(
        `canonicalPrice: amount "${term.amount}" has ${fracPart.length} fractional digits ` +
        `but asset "${term.asset}" settles in ${term.decimals} decimals`
      );
    }
    fracPart = fracPart.padEnd(term.decimals, '0');
  } else {
    // No declared precision — strip trailing zeros so "1.50" and "1.5" canonicalise alike.
    fracPart = fracPart.replace(/0+$/, '');
  }

  let result = fracPart.length > 0 ? `${intPart}.${fracPart}` : intPart;

  // Normalise negative zero (e.g. "-0", "-0.000") to "0".
  const isZero = /^0(\.0*)?$/.test(result);
  if (negative && !isZero) {
    result = `-${result}`;
  }
  return result;
}

/* -------------------------------------------------------------------------- */
/*  Rail availability (§9.5)                                                   */
/* -------------------------------------------------------------------------- */

/**
 * How available the settlement rail actually is (§9.5).
 *
 * A verifier MUST distinguish these so it never reads "we never wired the rail"
 * (`mocked` / `disabled`) as "the rail settled" (`live`), nor as "the rail tried
 * and broke" (`failed`).
 */
export enum RailAvailability {
  /** Rail is live and produced real on-chain settlement evidence. */
  Live = 'live',
  /** Rail exists but each settlement requires explicit operator action. */
  OperatorGated = 'operator_gated',
  /** Rail reads from closed / archival data; no live settlement path. */
  ClosedData = 'closed_data',
  /** Settlement happens bilaterally off this substrate (handshake recorded only). */
  Bilateral = 'bilateral',
  /** Evidence is synthetic — test vectors / reference fixtures, NOT real value. */
  Mocked = 'mocked',
  /** Rail is wired but turned off for this deal. */
  Disabled = 'disabled',
  /** Rail was attempted and failed (timeout, revert, insufficient funds, …). */
  Failed = 'failed',
}

/* -------------------------------------------------------------------------- */
/*  HTLC TxRef variants (§9.5)                                                 */
/* -------------------------------------------------------------------------- */

/** The three HTLC lifecycle phases a TxRef can record (§9.5). */
export type HtlcPhase = 'htlc-lock' | 'htlc-reveal' | 'htlc-refund';

/** Fields shared by every HTLC TxRef variant. */
interface HtlcTxRefBase {
  /** Which chain / substrate the transaction landed on (opaque chain id, e.g. "demos", "eip155:8453"). */
  chain: string;
  /** Transaction hash on `chain` (hex, with or without 0x — compared as a string). */
  txHash: string;
  /** Hashlock = sha256(preimage), hex. Binds all three phases of one HTLC together. */
  hashlock: string;
  /** When this transaction was observed/confirmed (ISO 8601). */
  observedAt: string;
}

/**
 * Buyer locks funds against `hashlock` on the SOURCE chain.
 *
 * `timelockExpiry` is the absolute time after which the lock can be refunded by
 * the buyer. Per the asymmetry rule, this MUST be strictly later than any
 * reveal/claim window (see {@link HtlcRevealTxRef.revealDeadline}).
 */
export interface HtlcLockTxRef extends HtlcTxRefBase {
  phase: 'htlc-lock';
  /** Absolute refund-eligibility time on the source chain (ISO 8601). */
  timelockExpiry: string;
  /** The locked amount (decimal-string PriceTerm). */
  amount: PriceTerm;
}

/**
 * Seller reveals `preimage`, claiming the lock before `revealDeadline`.
 *
 * The verifier recomputes sha256(preimage) and checks it equals the `hashlock`
 * carried on every phase of this HTLC.
 */
export interface HtlcRevealTxRef extends HtlcTxRefBase {
  phase: 'htlc-reveal';
  /** The revealed preimage (hex). sha256(preimage) MUST equal `hashlock`. */
  preimage: string;
  /** Absolute time by which the reveal MUST have landed (ISO 8601). MUST be < lock timelockExpiry. */
  revealDeadline: string;
}

/**
 * Buyer refunds after the source timelock expired and no valid reveal occurred.
 *
 * `refundedAfter` MUST be >= the lock's `timelockExpiry`.
 */
export interface HtlcRefundTxRef extends HtlcTxRefBase {
  phase: 'htlc-refund';
  /** The timelock the refund waited past (ISO 8601). MUST equal the lock's timelockExpiry. */
  refundedAfter: string;
}

/** Discriminated union over the HTLC lifecycle. */
export type HtlcTxRef = HtlcLockTxRef | HtlcRevealTxRef | HtlcRefundTxRef;

/* -------------------------------------------------------------------------- */
/*  SettlementEvidence (§9.5)                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Settlement evidence assembled by the settling party and signed under
 * "dacs-evidence:v1:" (v0.1 §B.7 / §9.7). Anchors into the DACS-5 bundle's SETTLE
 * phase.
 *
 * `outcome`:
 *   - 'settled'  — the happy path: lock + valid reveal (reveal landed before deadline)
 *   - 'refunded' — the timeout path: lock + refund (no valid reveal)
 *   - 'failed'   — the rail tried and broke (see `rail`)
 *
 * `signature` is base64 ed25519 over (domain_separator || sha256-hex-bytes(JCS(unsigned))),
 * where `unsigned` is this object with `signature` omitted — same discipline as
 * every other DACS signature (see src/lib/htlc-evidence.ts).
 */
export interface SettlementEvidence {
  v: 'dacs-4-settlement-evidence:0.1';
  /** Job/session this settlement belongs to (matches the DACS-5 bundle jobId). */
  jobId: string;
  /** The settlement mechanism. v0.1 reference impl ships the HTLC rail. */
  method: 'htlc';
  /** How available the rail was (§9.5) — verifier reads this to weight the evidence. */
  rail: RailAvailability;
  /** The agreed price being settled. */
  price: PriceTerm;
  /** Which party assembled + signed this evidence. */
  settler: 'buyer' | 'seller' | 'orchestrator';
  /** The settling party's ed25519 public key (hex) — the verifier checks the signature against this. */
  settlerPubkey: string;
  /** Final settlement outcome. */
  outcome: 'settled' | 'refunded' | 'failed';
  /**
   * The ordered HTLC transaction references that constitute this evidence.
   *   - settled  → [lock, reveal]
   *   - refunded → [lock, refund]
   *   - failed   → [lock] or [] depending on how far it got
   */
  txRefs: HtlcTxRef[];
  /** When the evidence was assembled (ISO 8601). */
  settledAt: string;
  /** base64 ed25519 signature (absent on the unsigned payload that gets hashed). */
  signature?: string;
}

/* -------------------------------------------------------------------------- */
/*  SettlementEvidence — spec/SDK v0.1 uniform form (§9.7)                      */
/* -------------------------------------------------------------------------- */

/**
 * The §9.7 universal evidence shape, keyed by `evidenceVersion: "1"`.
 *
 * This is the spec/SDK form (uniform across every payment + delivery phase),
 * distinct from the HTLC-specific {@link SettlementEvidence} above. It exists so
 * pathos can INDEPENDENTLY EMIT the exact bytes the dacs-sdk emits for the same
 * logical settlement (a byte-match convergence, not a shared-fixture re-hash).
 *
 * Signature discipline (§9.7): `signature` is OMITTED from the canonical form that
 * gets hashed; evidenceHash = sha256(JCS(evidence minus `signature`)), and the
 * signature value is ed25519 over "dacs-evidence:v1:" || evidenceHash.
 */

/** §9.7 ComponentSignature (object form — algorithm/signer/value). */
export interface SettlementSignatureV1 {
  algorithm: 'ed25519' | 'ecdsa-secp256k1' | 'sr1-aggregate';
  /** Signer ClaimReference (phase orchestrator), carried as a string DID/ref. */
  signer: string;
  /** Signature over "dacs-evidence:v1:" || evidenceHash (§B.7). */
  value: string;
}

/** §9.7 SettlementFinalityRecord — REQUIRED on success-outcome PAYMENT evidence (PC-6). */
export interface SettlementFinalityRecordV1 {
  /** §9.7 finality models; 'bft-final' = native Demos pay-dem (§9.5.9): inclusion is final. */
  model: 'block-depth' | 'commitment-level' | 'provider-receipt' | 'htlc-reveal' | 'liquidity-tank' | 'bft-final';
  /** model == "block-depth": number of blocks waited. */
  finalityBlocks?: number;
  /** model == "commitment-level": Solana commitment level accepted. */
  finalityCommitmentLevel?: 'processed' | 'confirmed' | 'finalized';
  /** unix ms at which the finality condition was observed to be met. */
  finalityObservedAt: number;
}

/** §9.7 ChainTxRef arms, exactly as the pinned dacs-sdk validates them (isChainTxRef: exact keys per arm). */
export type ChainTxRefV1 =
  | { kind: 'demos'; txHash: string; blockNumber?: number }
  | { kind: 'storage-program'; address: string; writeTxHash: string }
  | { kind: 'evm'; chainId: number; txHash: string }
  | { kind: 'evm-event'; chainId: number; txHash: string; logIndex: number }
  | { kind: 'x402'; httpResource: string; paymentReceiptHash: string; settlementTxHash?: string; chainId?: number; protocolVersion: string }
  | { kind: 'ap2'; mandateId: string; providerRef: string; protocolVersion: string; receiptAttestation?: Record<string, unknown> };

/**
 * The pre-spec reference form {rail, txHash, kind} that our AP2 extension still emits and that evidence
 * anchored before 2026-09-06 carries. Read by the verifier; new pay-dem evidence emits the ChainTxRef arm.
 */
export interface LegacyPaymentTxRefV1 {
  rail: string;
  txHash: string;
  kind: string;
}

export type PaymentTxRefV1 = ChainTxRefV1 | LegacyPaymentTxRefV1;

/** §9.7 PriceTerm carried on the spec evidence form (amount as a decimal STRING). */
export interface SettlementPriceV1 {
  amount: string;
  currency: string;
}

/** Fields shared by every spec-form SettlementEvidence (§9.7). */
interface SettlementEvidenceV1Base {
  evidenceVersion: '1';
  jobId: string;
  /** PaymentPhaseType | DeliveryPhaseType — opaque phase id string. */
  phase: string;
  /**
   * No phaseIndex: DACS-4 §9.5.8 SB-1 recovers the phase index from the PC-2 anchor address, and the
   * pinned dacs-sdk (isSettlementEvidence) refuses a record that carries one. Evidence anchored before
   * 2026-09-06 carries it; the verifier tolerates that legacy copy.
   */
  outcome: 'success' | 'failure';
  /** When the evidence was observed (unix ms). */
  observedAt: number;
  /** §9.7 ComponentSignature — OMITTED from the hashed canonical form. */
  signature?: SettlementSignatureV1;
}

/**
 * PAYMENT evidence (produced by every pay-* phase). On a success outcome,
 * `settlementFinality` is REQUIRED (PC-6).
 */
export interface SettlementEvidenceV1Payment extends SettlementEvidenceV1Base {
  paymentTxRefs: PaymentTxRefV1[];
  paymentAmount: SettlementPriceV1;
  /**
   * REQUIRED on success-outcome payment evidence (PC-6); MUST be omitted on a
   * failure-outcome payment (settlement.ts L240) and never present on delivery.
   */
  settlementFinality?: SettlementFinalityRecordV1;
  /** Optional failure-outcome explanation (§9.7 `reason`). */
  reason?: string;
}

/**
 * DELIVERY evidence (produced by every deliver-* phase). `settlementFinality`
 * MUST be absent (PC-6).
 */
export interface SettlementEvidenceV1Delivery extends SettlementEvidenceV1Base {
  deliverableContentHash: string;
  deliverableAnchor: { kind: string; locator: string };
}

/** Discriminated union over the spec/SDK v0.1 evidence form. */
export type SettlementEvidenceV1 = SettlementEvidenceV1Payment | SettlementEvidenceV1Delivery;
