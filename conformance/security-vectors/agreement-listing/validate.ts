/**
 * DACS §8.5.2 — Listing conformance validation (GAP vector #28 from the threat-to-test matrix).
 *
 * A verifier MUST validate an AgreementDocument against its referenced Listing, checked IN ORDER
 * (§8.5.2 checks 1..7). Reference validator + the contract the conformance vectors exercise. Pure,
 * offline, deterministic. Decimals compared EXACTLY via BigInt (CD-1 / CORE §B.2 — never floats).
 *
 * Spec fidelity (from review 2026-06-19): `pattern`/`derivedFromPattern` is the closed enum
 * `fixed-price | rfq | sealed-envelope` ("negotiable" is a PRICING kind, never a pattern). PS-3:
 * a `fixed-price`-derived agreement is permitted over a listing whose PRICING kind is `negotiable`
 * (and its price MUST equal bandCenter). Percentages may be fractional (spec: "non-negative
 * percentages") — handled exactly via scaled BigInt; negative pct → the listing is malformed.
 *
 * Decision (§7.5.1 do-not-collapse): accept (all pass) · reject (a check FAILED) · indeterminate
 * (a committedAt-relative check (5,6) cannot be evaluated because committedAt is absent AND nothing failed).
 */

export type NegotiationPattern = 'fixed-price' | 'rfq' | 'sealed-envelope';
export interface Listing {
  listingId: string;
  version: number;
  contentHash: string;
  pricing:
    | { kind: 'fixed'; currency: string; amount: string }
    | { kind: 'negotiable'; bandCenter: { currency: string; amount: string }; minPct: number; maxPct: number };
  offering: { deliverable: { deliverableType: string; hash: string; schemaUrl?: string } };
  acceptedRails: string[];
  hasPayPhase: boolean;            // PIPE-1: does the listing pipeline contain a pay-* phase?
  terms: { deadlineSecAfterCommit: number };
  validity?: { notAfter?: number };
  pattern: NegotiationPattern;     // pipeline-declared negotiation pattern
}
export interface Agreement {
  listingRef: { listingId: string; version: number; contentHash: string };
  terms: {
    price: { currency: string; amount: string };
    rail?: { railId: string };
    deliverable: { deliverableType: string; hash: string; schemaUrl?: string };
    deadline: number;
  };
  derivedFromPattern: NegotiationPattern;
}
export interface Check { id: string; rule: string; ok: boolean | null; detail: string }
export interface AgreementVerdict { decision: 'accept' | 'reject' | 'indeterminate'; checks: Check[] }

/* ── exact decimal via BigInt (CD-1) ── */
function parseDec(s: string): { neg: boolean; scaled: bigint; scale: number } {
  if (!/^-?\d+(\.\d+)?$/.test(s)) throw new Error(`non-decimal "${s}"`);
  const neg = s.startsWith('-');
  const [i, f = ''] = s.replace('-', '').split('.');
  return { neg, scaled: BigInt(i + f), scale: f.length };
}
function formatScaled(q: bigint, scale: number): string {
  const neg = q < 0n; const a = (neg ? -q : q).toString();
  let s: string;
  if (scale === 0) s = a;
  else { const p = a.padStart(scale + 1, '0'); s = `${p.slice(0, -scale)}.${p.slice(-scale)}`; }
  return (neg ? '-' : '') + s;
}
/** CD-1 minimal-digit canonical form (strip trailing fractional zeros). */
function cd1(s: string): string {
  if (!s.includes('.')) return s;
  const r = s.replace(/0+$/, '').replace(/\.$/, '');
  return r === '-0' ? '0' : r;
}
/** Compare two decimal strings exactly. -1 | 0 | 1 (scale-independent). */
function cmpDec(a: string, b: string): number {
  const A = parseDec(a), B = parseDec(b);
  const scale = Math.max(A.scale, B.scale);
  const av = (A.neg ? -1n : 1n) * A.scaled * 10n ** BigInt(scale - A.scale);
  const bv = (B.neg ? -1n : 1n) * B.scaled * 10n ** BigInt(scale - B.scale);
  return av < bv ? -1 : av > bv ? 1 : 0;
}
/** center * (100 + pctDelta) / 100, half-up to center's fractional digits, CD-1. pctDelta may be
 *  fractional and/or negative (lower bound). Exact (BigInt) — no floats. */
function bandBound(centerAmount: string, pctDelta: number): string {
  const C = parseDec(centerAmount);
  const P = parseDec(String(pctDelta));
  const factorNum = 100n * 10n ** BigInt(P.scale) + (P.neg ? -1n : 1n) * P.scaled; // (100+pctDelta)·10^P.scale
  const num = (C.neg ? -1n : 1n) * C.scaled * factorNum;                            // scale = C.scale + P.scale
  const den = 10n ** BigInt(P.scale) * 100n;                                        // divide back to C.scale
  let q = num / den; const r = num % den;
  const r2 = r < 0n ? -r : r;
  if (r2 * 2n >= den) q += num < 0n ? -1n : 1n;                                     // half-up (away from zero)
  return cd1(formatScaled(q, C.scale));
}

export function validateAgreementAgainstListing(
  agreement: Agreement,
  listing: Listing,
  committedAt?: number,
): AgreementVerdict {
  const checks: Check[] = [];
  const add = (id: string, rule: string, ok: boolean | null, detail: string) => { checks.push({ id, rule, ok, detail }); return ok; };

  // 0. listing binding — the agreement must actually reference THIS listing (the core of "mismatch").
  const lr = agreement.listingRef;
  const bound = lr.listingId === listing.listingId && lr.version === listing.version && lr.contentHash === listing.contentHash;
  add('0-listing-binding', '§8.5 listingRef pins the listing', bound,
    bound ? 'listingRef matches listing id/version/contentHash' : `listingRef ${lr.listingId}@${lr.version}/${lr.contentHash.slice(0, 10)} ≠ listing ${listing.listingId}@${listing.version}/${listing.contentHash.slice(0, 10)}`);

  const listCurrency = listing.pricing.kind === 'fixed' ? listing.pricing.currency : listing.pricing.bandCenter.currency;
  // 1. currency (BEFORE any amount comparison — §8.5.2 rule 1).
  const curOk = agreement.terms.price.currency === listCurrency;
  add('1-currency', '§8.5.2(1)', curOk, curOk ? `currency ${listCurrency}` : `agreement currency ${agreement.terms.price.currency} ≠ listing ${listCurrency}`);

  // 2. price within band / equal — only when currency matched (rule 1 ordering).
  if (!curOk) {
    add('2-price', '§8.5.2(2)', null, 'not evaluated — rule 1 rejects cross-currency BEFORE any amount comparison');
  } else if (listing.pricing.kind === 'fixed') {
    const eq = cmpDec(agreement.terms.price.amount, listing.pricing.amount) === 0;
    add('2-price', '§8.5.2(2 fixed)', eq, eq ? `price == ${listing.pricing.amount}` : `price ${agreement.terms.price.amount} ≠ fixed ${listing.pricing.amount}`);
  } else {
    const { bandCenter, minPct, maxPct } = listing.pricing;
    // Band HEALTH is validated BEFORE branching on pattern — a malformed listing (negative pct, or a
    // computed lower bound ≤ 0) MUST be rejected even for a PS-3 fixed-over-negotiable agreement, which
    // otherwise only checks price==bandCenter and would never compute the band (Codex catch 2026-06-19).
    if (!Number.isFinite(minPct) || !Number.isFinite(maxPct) || minPct < 0 || maxPct < 0) {
      add('2-price', '§8.5.2(2) band', false, `malformed listing: minPct/maxPct MUST be finite + non-negative (got ${minPct}/${maxPct})`);
    } else {
      const lower = bandBound(bandCenter.amount, -minPct), upper = bandBound(bandCenter.amount, maxPct);
      if (cmpDec(lower, '0') <= 0) {
        add('2-price', '§8.5.2(2) band', false, `computed lower bound ${lower} ≤ 0 — listing rejected`);
      } else if (agreement.derivedFromPattern === 'fixed-price') {
        const eq = cmpDec(agreement.terms.price.amount, bandCenter.amount) === 0; // PS-3: fixed-over-negotiable → equal bandCenter
        add('2-price', '§8.5.2(2 fixed-over-negotiable, PS-3)', eq, eq ? `price == bandCenter ${cd1(bandCenter.amount)} (band valid)` : `fixed-derived price ${agreement.terms.price.amount} ≠ bandCenter ${cd1(bandCenter.amount)}`);
      } else {
        const within = cmpDec(agreement.terms.price.amount, lower) >= 0 && cmpDec(agreement.terms.price.amount, upper) <= 0;
        add('2-price', '§8.5.2(2) band', within, `price ${agreement.terms.price.amount} ${within ? '∈' : '∉'} [${lower}, ${upper}]`);
      }
    }
  }

  // 3. rail — present iff pay-* phase; if present MUST be in acceptedRails; absent for zero-pay.
  const hasRail = agreement.terms.rail !== undefined;
  const railOk = listing.hasPayPhase ? (hasRail && listing.acceptedRails.includes(agreement.terms.rail!.railId)) : !hasRail;
  add('3-rail', '§8.5.2(3)', railOk,
    listing.hasPayPhase ? (hasRail ? (railOk ? `rail ${agreement.terms.rail!.railId} ∈ acceptedRails` : `rail ${agreement.terms.rail!.railId} ∉ acceptedRails`) : 'pay-* pipeline requires terms.rail (absent)') : (hasRail ? 'zero-pay pipeline forbids terms.rail (present)' : 'zero-pay: no rail (correct)'));

  // 4. deliverable — type + hash + schemaUrl (both absent, or both present and equal).
  const ld = listing.offering.deliverable, ad = agreement.terms.deliverable;
  const delOk = ad.deliverableType === ld.deliverableType && ad.hash === ld.hash && (ad.schemaUrl ?? null) === (ld.schemaUrl ?? null);
  add('4-deliverable', '§8.5.2(4)', delOk, delOk ? 'deliverable type/hash/schemaUrl conform' : `deliverable mismatch (type ${ad.deliverableType}/${ld.deliverableType}, hash ${ad.hash.slice(0, 8)}/${ld.hash.slice(0, 8)}, schemaUrl ${ad.schemaUrl ?? '∅'}/${ld.schemaUrl ?? '∅'})`);

  // 5,6. committedAt-relative — indeterminate (null) if committedAt absent (post-anchor checks, §8.5.2).
  if (committedAt === undefined) {
    add('5-deadline', '§8.5.2(5)', null, 'indeterminate — committedAt not provided (post-anchor check)');
    add('6-not-expired', '§8.5.2(6)', null, 'indeterminate — committedAt not provided (post-anchor check)');
  } else {
    const maxDeadline = committedAt + listing.terms.deadlineSecAfterCommit * 1000;
    const dlOk = agreement.terms.deadline <= maxDeadline;
    add('5-deadline', '§8.5.2(5)', dlOk, dlOk ? 'deadline ≤ committedAt + window' : `deadline ${agreement.terms.deadline} > committedAt+window ${maxDeadline}`);
    const expOk = listing.validity?.notAfter === undefined || listing.validity.notAfter >= committedAt;
    add('6-not-expired', '§8.5.2(6)', expOk, expOk ? 'listing not expired at committedAt' : `listing notAfter ${listing.validity!.notAfter} < committedAt ${committedAt}`);
  }

  // 7. pattern — derivedFromPattern matches listing pattern; PS-3 carve-out: fixed-price over negotiable PRICING.
  const patOk = agreement.derivedFromPattern === listing.pattern || (agreement.derivedFromPattern === 'fixed-price' && listing.pricing.kind === 'negotiable');
  add('7-pattern', '§8.5.2(7)', patOk, patOk ? `pattern ${agreement.derivedFromPattern}` : `derivedFromPattern ${agreement.derivedFromPattern} ≠ listing pattern ${listing.pattern}`);

  const anyFail = checks.some((c) => c.ok === false);
  const anyIndet = checks.some((c) => c.ok === null);
  // §7.5.1 precedence: any FAIL → reject (even if a committedAt check is also indeterminate); else indeterminate; else accept.
  const decision = anyFail ? 'reject' : anyIndet ? 'indeterminate' : 'accept';
  return { decision, checks };
}
