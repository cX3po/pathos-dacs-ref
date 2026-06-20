/**
 * Conformance vectors for DACS §8.5.2 (agreement-listing validation) — GAP vector #28.
 * Golden set covers: listing-binding, all 7 checks, boundary-inclusivity, fixed pricing, PS-3
 * (fixed-over-negotiable), fractional pct, half-cent half-up rounding, lower-bound≤0, schemaUrl,
 * zero-pay rail, and §7.5.1 fail-precedence-over-indeterminate. Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { validateAgreementAgainstListing, type Listing, type Agreement } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, ''); // portable: this script's dir
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const DHASH = sha('deliverable-spec');
const CA = 1780000000000;                 // committedAt (ms)
const DL_OK = CA + 3600 * 1000;           // exactly at the window edge (≤ inclusive)

// base: negotiable pricing, rfq pattern, band [90.00, 110.00]
const L: Listing = {
  listingId: 'L1', version: 1, contentHash: sha('listing-L1'),
  pricing: { kind: 'negotiable', bandCenter: { currency: 'USDC', amount: '100.00' }, minPct: 10, maxPct: 10 },
  offering: { deliverable: { deliverableType: 'application/json', hash: DHASH } },
  acceptedRails: ['pay-x402'], hasPayPhase: true,
  terms: { deadlineSecAfterCommit: 3600 }, validity: { notAfter: CA + 86400_000 }, pattern: 'rfq',
};
const A: Agreement = {
  listingRef: { listingId: 'L1', version: 1, contentHash: L.contentHash },
  terms: { price: { currency: 'USDC', amount: '95.00' }, rail: { railId: 'pay-x402' }, deliverable: { deliverableType: 'application/json', hash: DHASH }, deadline: DL_OK },
  derivedFromPattern: 'rfq',
};
const mk = (fa: (a: Agreement) => void = () => {}, fl: (l: Listing) => void = () => {}) => { const a = clone(A), l = clone(L); fa(a); fl(l); return { a, l }; };

type C = { name: string; expected: 'accept' | 'reject' | 'indeterminate'; committedAt?: number; a: Agreement; l: Listing };
const cases: C[] = [
  { name: 'valid-in-band-rfq', expected: 'accept', committedAt: CA, ...mk() },
  // listing binding + checks 1..7
  { name: '0-listing-binding-mismatch', expected: 'reject', committedAt: CA, ...mk((a) => { a.listingRef.contentHash = sha('other'); }) },
  { name: '1-currency-mismatch', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.currency = 'EUR'; }) },
  { name: '2-price-below-band', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.amount = '89.99'; }) },
  { name: '2-price-above-band', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.amount = '110.01'; }) },
  { name: '2-price-at-lower-bound', expected: 'accept', committedAt: CA, ...mk((a) => { a.terms.price.amount = '90.00'; }) },   // inclusive
  { name: '2-price-at-upper-bound', expected: 'accept', committedAt: CA, ...mk((a) => { a.terms.price.amount = '110.00'; }) },  // inclusive
  { name: '3-rail-missing-on-pay', expected: 'reject', committedAt: CA, ...mk((a) => { delete a.terms.rail; }) },
  { name: '3-rail-not-in-accepted', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.rail = { railId: 'pay-foo' }; }) },
  { name: '3-zero-pay-no-rail', expected: 'accept', committedAt: CA, ...mk((a) => { delete a.terms.rail; }, (l) => { l.hasPayPhase = false; }) },
  { name: '3-zero-pay-rail-present', expected: 'reject', committedAt: CA, ...mk(() => {}, (l) => { l.hasPayPhase = false; }) },
  { name: '4-deliverable-hash-mismatch', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.deliverable.hash = sha('forged'); }) },
  { name: '4-schemaUrl-mismatch', expected: 'reject', committedAt: CA, ...mk(() => {}, (l) => { l.offering.deliverable.schemaUrl = 'https://x/s.json'; }) }, // listing has it, agreement doesn't
  { name: '4-schemaUrl-match', expected: 'accept', committedAt: CA, ...mk((a) => { a.terms.deliverable.schemaUrl = 'https://x/s.json'; }, (l) => { l.offering.deliverable.schemaUrl = 'https://x/s.json'; }) },
  { name: '5-deadline-too-late', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.deadline = DL_OK + 10_000; }) },
  { name: '6-listing-expired', expected: 'reject', committedAt: CA, ...mk(() => {}, (l) => { l.validity!.notAfter = CA - 1; }) },
  { name: '7-pattern-mismatch', expected: 'reject', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'sealed-envelope'; }) },
  // fixed pricing
  { name: 'fixed-pricing-equal', expected: 'accept', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'fixed-price'; a.terms.price.amount = '100.00'; }, (l) => { l.pricing = { kind: 'fixed', currency: 'USDC', amount: '100.00' }; l.pattern = 'fixed-price'; }) },
  { name: 'fixed-pricing-unequal', expected: 'reject', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'fixed-price'; a.terms.price.amount = '99.00'; }, (l) => { l.pricing = { kind: 'fixed', currency: 'USDC', amount: '100.00' }; l.pattern = 'fixed-price'; }) },
  // PS-3 fixed-over-negotiable (must equal bandCenter, not merely in band)
  { name: 'ps3-fixed-over-negotiable-equal', expected: 'accept', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'fixed-price'; a.terms.price.amount = '100.00'; }) },
  { name: 'ps3-fixed-over-negotiable-inband-but-not-center', expected: 'reject', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'fixed-price'; a.terms.price.amount = '95.00'; }) },
  // fractional pct: band [97.50, 102.50]
  { name: 'fractional-pct-in', expected: 'accept', committedAt: CA, ...mk((a) => { a.terms.price.amount = '101.00'; }, (l) => { if (l.pricing.kind === 'negotiable') { l.pricing.minPct = 2.5; l.pricing.maxPct = 2.5; } }) },
  { name: 'fractional-pct-out', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.amount = '103.00'; }, (l) => { if (l.pricing.kind === 'negotiable') { l.pricing.minPct = 2.5; l.pricing.maxPct = 2.5; } }) },
  // half-cent half-up: center 100.05, ±10% → lower 90.045→90.05, upper 110.055→110.06
  { name: 'half-cent-at-rounded-lower', expected: 'accept', committedAt: CA, ...mk((a) => { a.terms.price.amount = '90.05'; }, (l) => { if (l.pricing.kind === 'negotiable') l.pricing.bandCenter.amount = '100.05'; }) },
  { name: 'half-cent-just-below-rounded-lower', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.amount = '90.04'; }, (l) => { if (l.pricing.kind === 'negotiable') l.pricing.bandCenter.amount = '100.05'; }) },
  // malformed listing: lower bound ≤ 0 (minPct 100)
  { name: 'lower-bound-le-zero', expected: 'reject', committedAt: CA, ...mk((a) => { a.terms.price.amount = '50.00'; }, (l) => { if (l.pricing.kind === 'negotiable') l.pricing.minPct = 100; }) },
  // malformed band MUST reject even under the PS-3 fixed-over-negotiable carve-out (Codex 2026-06-19):
  // bandCenter 100, minPct 200 → lower ≤ 0; price == bandCenter would otherwise wrongly accept.
  { name: 'ps3-malformed-band-lower-le-zero', expected: 'reject', committedAt: CA, ...mk((a) => { a.derivedFromPattern = 'fixed-price'; a.terms.price.amount = '100.00'; }, (l) => { if (l.pricing.kind === 'negotiable') l.pricing.minPct = 200; }) },
  { name: 'malformed-band-negative-pct', expected: 'reject', committedAt: CA, ...mk(() => {}, (l) => { if (l.pricing.kind === 'negotiable') l.pricing.minPct = -10; }) },
  // §7.5.1: committedAt absent → 5,6 indeterminate; with everything else passing → indeterminate
  { name: 'indeterminate-no-committedAt', expected: 'indeterminate', committedAt: undefined, ...mk() },
  // §7.5.1 precedence: committedAt absent BUT a hard failure → reject (fail beats indeterminate)
  { name: 'fail-beats-indeterminate', expected: 'reject', committedAt: undefined, ...mk((a) => { a.terms.price.currency = 'EUR'; }) },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, committedAt: c.committedAt ?? null, agreement: c.a, listing: c.l }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/agreement-listing-v0.1.json`, JSON.stringify({ set: 'agreement-listing-v0.1', spec: 'DACS §8.5.2', hash: setHash, count: vectors.length, vectors }, null, 2));

let pass = 0;
console.log('\n=== DACS §8.5.2 agreement-listing conformance vectors v0.1 ===');
for (const c of cases) {
  const v = validateAgreementAgainstListing(c.a, c.l, c.committedAt);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0;
  const fails = v.checks.filter((k) => k.ok === false).map((k) => k.id).join(',');
  const nulls = v.checks.filter((k) => k.ok === null).map((k) => k.id).join(',');
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(40)} exp=${c.expected.padEnd(13)} got=${v.decision.padEnd(13)}${fails ? ' FAIL:' + fails : ''}${nulls ? ' NULL:' + nulls : ''}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/agreement-listing-v0.1.json`);
if (pass !== cases.length) process.exit(1);
