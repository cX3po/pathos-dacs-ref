/**
 * DACS §8.4.3 — sealed-envelope bid ADMISSION (commit/reveal timing + commitment binding). GAP #27 (#158).
 *
 * Is a bid admitted to the sealed-auction candidate set? The §8.4.3 rules that decide it:
 *   • SE-2 deadline gate — the authoritative time is the **SR-2 anchor timestamp**, NOT the self-reported
 *     `commitTimestamp` (which "MUST NOT be used for any deadline gate"). A commit anchored after
 *     `commitDeadline` is a late bid → excluded; a self-reported on-time `commitTimestamp` does NOT save it.
 *   • CH-3 — the commit's `bidderClaim` MUST equal the authenticated channel sender; otherwise excluded.
 *   • SE-3/SE-4 reveal window — the reveal MUST be anchored within `[commitDeadline, commitDeadline +
 *     revealWindow]`; an out-of-window (or absent) reveal → excluded.
 *   • Commitment binding — the revealed `{bid, salt}` MUST satisfy
 *     `bidHash == sha256("dacs-sealed-bid:v1:" || sha256(JCS(bid)) || salt)` (lowercase hex); mismatch → excluded.
 *
 * Decision (§7.5.1, never collapsed): pass (admitted) · fail (excluded: late / wrong-sender / out-of-window
 * / binding-mismatch / no-reveal) · indeterminate (SR-2 anchor timestamp unresolvable → cannot apply the
 * gate) · error (malformed input). Boundary instants are deliberately NOT asserted (clearly in/out only).
 *
 * Pure, offline, deterministic, dep-free. `dacs-sealed-bid:v1:` is the spec's commitment-hash domain tag (§B.7 / §8.4.3).
 */
import { createHash } from 'node:crypto';

const SEALED_BID_SEP = 'dacs-sealed-bid:v1:';
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest();
const isHex = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0 && s.length > 0;

/** Minimal injective RFC-8785-ish canonical JSON over JSON values (sorted keys); throws on non-JSON. */
export function canon(v: unknown): string {
  if (v === undefined || typeof v === 'function' || typeof v === 'symbol') throw new Error('canon: non-JSON value');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canon: non-finite number');
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) if (!(i in v)) throw new Error('canon: sparse'); return `[${v.map(canon).join(',')}]`; }
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) throw new Error('canon: non-plain object');
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`;
}

/** bidHash = sha256("dacs-sealed-bid:v1:" || sha256(JCS(bid)) || salt), lowercase hex (§8.4.3 step 2). */
export function computeBidHash(bid: unknown, saltHex: string): string {
  return sha256(Buffer.concat([Buffer.from(SEALED_BID_SEP, 'utf8'), sha256(Buffer.from(canon(bid), 'utf8')), Buffer.from(saltHex, 'hex')])).toString('hex');
}

export interface Commit { bidHash: string; bidderClaim: string; commitTimestamp?: number; anchorTimestamp: number | null }
export interface Reveal { bid: unknown; salt: string; anchorTimestamp: number | null }
export interface SealedCtx { commitDeadline: number; revealWindowSec: number; authenticatedSender: string }
export interface Check { id: string; ok: boolean | null; detail: string }
export interface SealedVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

export function checkSealedBidAdmission(commit: Commit, reveal: Reveal | null, ctx: SealedCtx): SealedVerdict {
  const checks: Check[] = [];
  const out = (d: SealedVerdict['decision']): SealedVerdict => ({ decision: d, checks });
  // [0] structural
  if (!commit || typeof commit !== 'object' || typeof commit.bidHash !== 'string' || typeof commit.bidderClaim !== 'string' ||
      !ctx || typeof ctx.commitDeadline !== 'number' || typeof ctx.revealWindowSec !== 'number' || typeof ctx.authenticatedSender !== 'string') {
    checks.push({ id: 'structural', ok: false, detail: 'malformed commit / ctx' });
    return out('error');
  }
  if (ctx.revealWindowSec < 60) { checks.push({ id: 'reveal-window-min', ok: false, detail: 'revealWindow < 60s (non-conformant listing)' }); return out('error'); }
  checks.push({ id: 'structural', ok: true, detail: 'well-formed' });
  // [0b] bidHash MUST be a lowercase 64-hex digest (§8.4.3 — the committed value is lowercase hex)
  if (!/^[0-9a-f]{64}$/.test(commit.bidHash)) {
    checks.push({ id: 'bidhash-format', ok: false, detail: 'bidHash is not a lowercase 64-hex digest (§8.4.3)' });
    return out('error');
  }

  // [1] CH-3 — bidderClaim MUST be the authenticated sender
  if (commit.bidderClaim !== ctx.authenticatedSender) {
    checks.push({ id: 'ch-3-sender', ok: false, detail: 'commit bidderClaim ≠ authenticated sender — excluded' });
    return out('fail');
  }
  // [2] SE-2 — deadline gate uses the SR-2 ANCHOR timestamp, never the self-reported commitTimestamp
  if (commit.anchorTimestamp == null) {
    checks.push({ id: 'se-2-anchor', ok: null, detail: 'commit SR-2 anchor timestamp unresolvable — cannot apply the deadline gate' });
    return out('indeterminate');
  }
  if (commit.anchorTimestamp > ctx.commitDeadline) {
    checks.push({ id: 'se-2-deadline', ok: false, detail: `commit anchored after commitDeadline (${commit.anchorTimestamp} > ${ctx.commitDeadline}) — late bid (self-reported commitTimestamp does NOT gate)` });
    return out('fail');
  }
  checks.push({ id: 'se-2-deadline', ok: true, detail: 'commit anchored on/before commitDeadline' });
  // [3] SE-4 — a committed bidder MUST reveal
  if (reveal == null || typeof reveal !== 'object') { checks.push({ id: 'se-4-reveal', ok: false, detail: 'no reveal record — excluded' }); return out('fail'); }
  // [4] SE-3 — reveal anchored WITHIN [commitDeadline, commitDeadline + revealWindow]
  if (reveal.anchorTimestamp == null) { checks.push({ id: 'se-3-anchor', ok: null, detail: 'reveal SR-2 anchor timestamp unresolvable — cannot apply the window gate' }); return out('indeterminate'); }
  const windowEnd = ctx.commitDeadline + ctx.revealWindowSec * 1000;
  if (reveal.anchorTimestamp < ctx.commitDeadline || reveal.anchorTimestamp > windowEnd) {
    checks.push({ id: 'se-3-window', ok: false, detail: `reveal anchored outside [${ctx.commitDeadline}, ${windowEnd}] — excluded` });
    return out('fail');
  }
  checks.push({ id: 'se-3-window', ok: true, detail: 'reveal anchored in-window' });
  // [5] commitment binding — revealed {bid,salt} MUST reproduce the committed bidHash
  if (!isHex(reveal.salt)) { checks.push({ id: 'binding', ok: false, detail: 'salt not hex — cannot open commitment' }); return out('error'); }
  let computed: string;
  try { computed = computeBidHash(reveal.bid, reveal.salt); }
  catch (e) { checks.push({ id: 'binding', ok: false, detail: `bid not canonicalisable: ${(e as Error).message}` }); return out('error'); }
  const bound = computed === commit.bidHash;   // both lowercase hex; exact equality (§8.4.3)
  checks.push({ id: 'binding', ok: bound, detail: bound ? 'reveal opens the committed bidHash' : 'reveal does NOT match the committed bidHash — excluded' });
  if (!bound) return out('fail');

  return out('pass');
}
