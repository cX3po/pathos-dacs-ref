/**
 * se8-role-cross-run.mts — DACS-Standard #218 SE-8 sealed-envelope role-assignment convergence read.
 *
 * Drives THIS impl's independent SE-8 logic (src/lib/sealed-envelope-roles.ts) over the golden
 * `sealedEnvelopeRoleAssignment` assertions from PR #218 (conformance/vectors/golden.json) and reports,
 * per assertion, whether our result matches. Independent read — our logic is derived from the §8.4.3 /
 * §8.5.2 SE-8 text, not fitted to the golden.
 *
 *   npx tsx conformance/vet-drift/se8-role-cross-run.mts
 *
 * Exit 0 iff every assertion converges.
 */
import { assignSealedEnvelopeRoles } from '../../src/lib/sealed-envelope-roles.js';

// Golden expectations from DACS-Standard PR #218 golden.json → sealedEnvelopeRoleAssignment.
const GOLDEN = {
  defaultDemandWinnerRole: 'buyer',
  demandWinnerRole: 'buyer',
  procurementWinnerRole: 'seller',
  procurementPhaseKind: 'negotiate-sealed-envelope-procurement',
  procurementContextDeltaKey: 'negotiate-sealed-envelope-procurement',
  procurementDerivedFromPattern: 'sealed-envelope',
  roleInvertedProcurementAgreement: { ok: false, failedAt: 'sealed-envelope-role-direction' },
  unresolvableAuctionMode: { ok: false, failedAt: 'auctionMode', reason: 'unresolvable-auctionMode' },
  procurementPhaseMissingMode: { ok: false, failedAt: 'auctionMode', reason: 'unresolvable-auctionMode' },
} as const;

type Row = { name: string; expected: unknown; got: unknown; ok: boolean };
const rows: Row[] = [];
const check = (name: string, expected: unknown, got: unknown) =>
  rows.push({ name, expected, got, ok: JSON.stringify(expected) === JSON.stringify(got) });

// default demand (no auctionMode) → winning bidder is buyer
{
  const r = assignSealedEnvelopeRoles({ phaseKind: 'negotiate-sealed-envelope' });
  check('defaultDemandWinnerRole', GOLDEN.defaultDemandWinnerRole, r.ok ? r.winningBidderRole : r);
}
// explicit demand marker → winning bidder is buyer
{
  const r = assignSealedEnvelopeRoles({ phaseKind: 'negotiate-sealed-envelope', auctionMode: 'demand' });
  check('demandWinnerRole', GOLDEN.demandWinnerRole, r.ok ? r.winningBidderRole : r);
}
// procurement → winning bidder is seller + derived pattern + context delta key
{
  const r = assignSealedEnvelopeRoles({ phaseKind: 'negotiate-sealed-envelope-procurement', auctionMode: 'procurement' });
  check('procurementWinnerRole', GOLDEN.procurementWinnerRole, r.ok ? r.winningBidderRole : r);
  check('procurementDerivedFromPattern', GOLDEN.procurementDerivedFromPattern, r.ok ? r.derivedFromPattern : r);
  check('procurementContextDeltaKey', GOLDEN.procurementContextDeltaKey, r.ok ? r.contextDeltaKey : r);
}
// role inversion on procurement (bidder wrongly assigned buyer) → reject at role-direction
{
  const r = assignSealedEnvelopeRoles({
    phaseKind: 'negotiate-sealed-envelope-procurement', auctionMode: 'procurement',
    agreement: { buyer: 'winningBidder', seller: 'listingPublisher' },   // inverted for procurement
  });
  check('roleInvertedProcurementAgreement', GOLDEN.roleInvertedProcurementAgreement, { ok: r.ok, failedAt: r.ok ? undefined : r.failedAt });
}
// unresolvable/malformed auctionMode on procurement → reject, do-not-collapse
{
  const r = assignSealedEnvelopeRoles({ phaseKind: 'negotiate-sealed-envelope-procurement', auctionMode: 'garbage' });
  check('unresolvableAuctionMode', GOLDEN.unresolvableAuctionMode, { ok: r.ok, failedAt: r.ok ? undefined : r.failedAt, reason: r.ok ? undefined : r.reason });
}
// missing auctionMode on procurement phase → reject, never coerce to demand
{
  const r = assignSealedEnvelopeRoles({ phaseKind: 'negotiate-sealed-envelope-procurement' });
  check('procurementPhaseMissingMode', GOLDEN.procurementPhaseMissingMode, { ok: r.ok, failedAt: r.ok ? undefined : r.failedAt, reason: r.ok ? undefined : r.reason });
}

const converged = rows.every((r) => r.ok);
for (const r of rows) {
  console.log(`${r.ok ? '✓' : '✗'} ${r.name}${r.ok ? '' : `  expected=${JSON.stringify(r.expected)} got=${JSON.stringify(r.got)}`}`);
}
console.log(`\n${converged ? 'SE-8 cross-run CONVERGED' : 'SE-8 cross-run DIVERGED'} — ${rows.filter((r) => r.ok).length}/${rows.length} assertions (pathos-dacs-ref)`);
process.exit(converged ? 0 : 1);
