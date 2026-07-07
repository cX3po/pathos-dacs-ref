/**
 * sealed-envelope-roles.ts — DACS-3 §8.4.3 / §8.5.2 SE-8 sealed-envelope role assignment.
 *
 * PATH-OS Labs independent implementation of the SE-8 role-binding rule (DACS-Standard #210 / #218),
 * derived from the normative text — NOT fitted to the golden assertions (that would make an
 * independent convergence read meaningless). The rule:
 *
 *  - The sealed-envelope MODE is read from the PINNED listing's phase kind (decided from the frozen
 *    artifact, not phase-time inference): `negotiate-sealed-envelope` = demand (default);
 *    `negotiate-sealed-envelope-procurement` = procurement and MUST carry `auctionMode: "procurement"`.
 *  - Demand → winning bidder is the agreement `buyer`, listing publisher is the `seller`.
 *    Procurement → listing publisher is the `buyer`, winning bidder is the `seller`.
 *  - `bid.price` is ALWAYS the amount payable by the agreement `buyer` to the agreement `seller`
 *    (money direction follows the agreement roles, never who ran the auction).
 *  - Do-not-collapse (@xm33's arm): a present-but-unresolvable/malformed `auctionMode`, or a missing
 *    `auctionMode` on the procurement phase, MUST reject (`failedAt: "auctionMode"`,
 *    `reason: "unresolvable-auctionMode"`) — it MUST NOT be coerced to demand.
 *  - Role inversion (agreement roles don't match the pinned mode) MUST reject before Settle
 *    (`failedAt: "sealed-envelope-role-direction"`).
 */

export type PhaseKind = 'negotiate-sealed-envelope' | 'negotiate-sealed-envelope-procurement';
export type Party = 'winningBidder' | 'listingPublisher';
export type AgreementRole = 'buyer' | 'seller';

export interface SealedEnvelopeInput {
  /** The pinned listing's sealed-envelope phase kind (the mode source). */
  phaseKind: string;
  /** The auctionMode marker as it appears on the pinned listing (may be absent/malformed). */
  auctionMode?: unknown;
  /** OPTIONAL: an already-assigned agreement, to validate against the pinned mode (role-inversion check). */
  agreement?: {
    /** which party the agreement assigned as `buyer`, and which as `seller` */
    buyer: Party;
    seller: Party;
  };
}

export interface SealedEnvelopeReject {
  ok: false;
  failedAt: 'auctionMode' | 'sealed-envelope-role-direction' | 'phase-kind';
  reason: string;
}

export interface SealedEnvelopeOk {
  ok: true;
  mode: 'demand' | 'procurement';
  /** the correct role assignment for the pinned mode */
  winningBidderRole: AgreementRole;
  listingPublisherRole: AgreementRole;
  derivedFromPattern: 'sealed-envelope';
  contextDeltaKey: PhaseKind;
}

export type SealedEnvelopeResult = SealedEnvelopeOk | SealedEnvelopeReject;

const DEMAND: PhaseKind = 'negotiate-sealed-envelope';
const PROCUREMENT: PhaseKind = 'negotiate-sealed-envelope-procurement';

/** The correct role tuple for a resolved mode. Money always flows buyer → seller. */
function rolesForMode(mode: 'demand' | 'procurement'): { winningBidderRole: AgreementRole; listingPublisherRole: AgreementRole } {
  return mode === 'demand'
    ? { winningBidderRole: 'buyer', listingPublisherRole: 'seller' }   // demand: bidder pays the lister
    : { winningBidderRole: 'seller', listingPublisherRole: 'buyer' };  // procurement: lister pays the bidder
}

/**
 * Resolve + validate SE-8 sealed-envelope roles from the pinned listing.
 * Never throws. If `agreement` is supplied, also enforces role-direction (inversion → reject).
 *
 * CALLER OBLIGATION: the Settle / commit-agreement path MUST call this with the ACTUAL agreement
 * roles (`input.agreement`) — the role-inversion gate is only exercised when `agreement` is present,
 * so omitting it lets an inverted agreement bypass the check. The returned role tuple also defines the
 * `bid.price` direction (payable by the agreement `buyer` to the `seller`); the caller MUST carry it.
 */
export function assignSealedEnvelopeRoles(input: SealedEnvelopeInput): SealedEnvelopeResult {
  const { phaseKind, auctionMode, agreement } = input;

  if (phaseKind !== DEMAND && phaseKind !== PROCUREMENT) {
    return { ok: false, failedAt: 'phase-kind', reason: `unknown sealed-envelope phase kind "${phaseKind}"` };
  }

  let mode: 'demand' | 'procurement';
  if (phaseKind === DEMAND) {
    // Demand phase: absent `auctionMode` and "demand" are identical (SE-8). Anything else is malformed.
    if (auctionMode !== undefined && auctionMode !== 'demand') {
      return { ok: false, failedAt: 'auctionMode', reason: 'unresolvable-auctionMode' };
    }
    mode = 'demand';
  } else {
    // Procurement phase MUST carry auctionMode: "procurement". Missing/unresolvable/malformed →
    // reject; NEVER coerce to demand (do-not-collapse).
    if (auctionMode !== 'procurement') {
      return { ok: false, failedAt: 'auctionMode', reason: 'unresolvable-auctionMode' };
    }
    mode = 'procurement';
  }

  const roles = rolesForMode(mode);

  // Role-inversion gate: if an agreement was supplied, its role assignment MUST match the pinned mode.
  if (agreement) {
    const bidderRole: AgreementRole | undefined =
      agreement.buyer === 'winningBidder' ? 'buyer' : agreement.seller === 'winningBidder' ? 'seller' : undefined;
    const listerRole: AgreementRole | undefined =
      agreement.buyer === 'listingPublisher' ? 'buyer' : agreement.seller === 'listingPublisher' ? 'seller' : undefined;
    if (bidderRole !== roles.winningBidderRole || listerRole !== roles.listingPublisherRole) {
      return { ok: false, failedAt: 'sealed-envelope-role-direction', reason: 'agreement roles inverted relative to the pinned sealed-envelope mode' };
    }
  }

  return {
    ok: true,
    mode,
    winningBidderRole: roles.winningBidderRole,
    listingPublisherRole: roles.listingPublisherRole,
    derivedFromPattern: 'sealed-envelope',
    contextDeltaKey: phaseKind,
  };
}
