/**
 * spend-preflight.ts — fail-closed DEM-spend gate for the live Organ Gateway.
 *
 * A live session anchors ~7 SR-2 writes + 1 pay-dem transfer, all costing DEM. This gate runs
 * BEFORE any of that and BLOCKS unless every arm passes — so a live run can never spend without an
 * estimate under the cap, a funded balance, an explicit operator go, and a binding to a verified
 * dry run. Pure (balance is injected), so it's unit-testable without a node.
 *
 * (Mirrors the canonical PATH-OS operational gate at axiom `tools/demos_spend_preflight.mjs`;
 * vendored here so this repo stays standalone. Keep the arms in sync.)
 */

export interface PreflightParams {
  purpose: string;
  estWrites: number;
  estCostPerWriteDem: number;
  createCostDem?: number;
  maxSpendDem: number;
  balanceDem: number;
  operatorApproved?: boolean;
  dryRunHash?: string | null;
  balanceMarginDem?: number;
}

export interface PreflightResult {
  verdict: 'PROCEED' | 'BLOCK';
  purpose?: string;
  estCostDem: number | null;
  balanceDem?: number;
  headroomDem?: number;
  reasons: string[];
}

const okNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0;

/** Pure preflight decision (all amounts in DEM). Never throws; malformed input → BLOCK. */
export function preflight(p: PreflightParams): PreflightResult {
  const reasons: string[] = [];
  const fail = (r: string) => reasons.push(r);

  if (!p.purpose || typeof p.purpose !== 'string') fail('purpose (job label) is required');
  if (!okNum(p.estWrites)) fail('estWrites must be a finite number >= 0');
  if (!okNum(p.estCostPerWriteDem)) fail('estCostPerWriteDem must be a finite number >= 0');
  if (!okNum(p.maxSpendDem)) fail('maxSpendDem (per-job cap) must be a finite number >= 0');
  if (!okNum(p.balanceDem)) fail('balanceDem must be a finite number >= 0');
  if (reasons.length) return { verdict: 'BLOCK', reasons, estCostDem: null };

  const createCost = okNum(p.createCostDem) ? p.createCostDem : 0;
  const margin = okNum(p.balanceMarginDem) ? p.balanceMarginDem : 0;
  const estCostDem = p.estWrites * p.estCostPerWriteDem + createCost;

  if (estCostDem > p.maxSpendDem) fail(`estimate ${estCostDem} DEM exceeds per-job cap ${p.maxSpendDem} DEM`);
  if (estCostDem + margin > p.balanceDem) fail(`estimate ${estCostDem} DEM (+${margin} margin) exceeds balance ${p.balanceDem} DEM`);
  if (p.operatorApproved !== true) fail('operatorApproved must be true (explicit human go for this job)');
  if (!p.dryRunHash || typeof p.dryRunHash !== 'string') fail('dryRunHash required — spend must be bound to a verified dry run');

  return {
    verdict: reasons.length ? 'BLOCK' : 'PROCEED',
    purpose: p.purpose,
    estCostDem,
    balanceDem: p.balanceDem,
    headroomDem: p.balanceDem - estCostDem,
    reasons,
  };
}
