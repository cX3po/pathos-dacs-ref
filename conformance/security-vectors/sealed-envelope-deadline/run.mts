/**
 * DACS §8.4.3 sealed-envelope bid-admission conformance vectors — GAP #27 (issue #158).
 * Commit deadline gate (SR-2 anchor authoritative, self-reported commitTimestamp does NOT gate), reveal
 * window, commitment binding, CH-3 sender. Run: npx tsx run.mts → writes vectors json, exits 1 on mismatch.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkSealedBidAdmission, computeBidHash, type Commit, type Reveal, type SealedCtx } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const DEADLINE = 1_750_000_000_000;            // unix ms
const WINDOW = 300;                            // seconds (>= 60)
const SENDER = 'cci:' + 'ab'.repeat(32);
const ctx: SealedCtx = { commitDeadline: DEADLINE, revealWindowSec: WINDOW, authenticatedSender: SENDER };

const BID = { price: { amount: '100.00', currency: 'USDC' }, deliverable: { ref: 'svc-1' } };
const SALT = 'cafe'.repeat(8);                 // 32 hex chars
const BIDHASH = computeBidHash(BID, SALT);
const inWindow = DEADLINE + 60_000;            // 60s into the reveal window
const goodCommit = (over: Partial<Commit> = {}): Commit => ({ bidHash: BIDHASH, bidderClaim: SENDER, commitTimestamp: DEADLINE - 5000, anchorTimestamp: DEADLINE - 1000, ...over });
const goodReveal = (over: Partial<Reveal> = {}): Reveal => ({ bid: BID, salt: SALT, anchorTimestamp: inWindow, ...over });

type Dec = 'pass' | 'fail' | 'indeterminate' | 'error';
type Case = { name: string; expected: Dec; commit: Commit; reveal: Reveal | null; note: string };

const cases: Case[] = [
  { name: 'valid-admitted', expected: 'pass', commit: goodCommit(), reveal: goodReveal(), note: 'commit before deadline (anchor), reveal in-window, binding matches, sender matches → admitted' },
  // SE-2 deadline gate
  { name: 'late-commit-anchor', expected: 'fail', commit: goodCommit({ anchorTimestamp: DEADLINE + 1000 }), reveal: goodReveal(), note: 'commit anchored AFTER commitDeadline → late, excluded' },
  // the SE-2 headline: self-reported commitTimestamp MUST NOT gate
  { name: 'self-report-ontime-but-anchor-late', expected: 'fail', commit: goodCommit({ commitTimestamp: DEADLINE - 5000, anchorTimestamp: DEADLINE + 2000 }), reveal: goodReveal(), note: 'commitTimestamp says on-time but the SR-2 ANCHOR is late → excluded (self-report does NOT gate)' },
  { name: 'self-report-late-but-anchor-ontime', expected: 'pass', commit: goodCommit({ commitTimestamp: DEADLINE + 9999, anchorTimestamp: DEADLINE - 500 }), reveal: goodReveal(), note: 'commitTimestamp says late but the authoritative ANCHOR is on-time → admitted (anchor wins)' },
  // CH-3 sender binding
  { name: 'bidderClaim-not-sender', expected: 'fail', commit: goodCommit({ bidderClaim: 'cci:' + 'cd'.repeat(32) }), reveal: goodReveal(), note: 'CH-3: commit bidderClaim ≠ authenticated sender → excluded' },
  // SE-3/SE-4 reveal window
  { name: 'reveal-after-window', expected: 'fail', commit: goodCommit(), reveal: goodReveal({ anchorTimestamp: DEADLINE + WINDOW * 1000 + 1000 }), note: 'reveal anchored after revealWindow expiry → excluded' },
  { name: 'reveal-before-deadline', expected: 'fail', commit: goodCommit(), reveal: goodReveal({ anchorTimestamp: DEADLINE - 1000 }), note: 'reveal anchored before commitDeadline (premature, out of window) → excluded' },
  { name: 'no-reveal', expected: 'fail', commit: goodCommit(), reveal: null, note: 'SE-4: committed but never revealed → excluded' },
  // commitment binding
  { name: 'binding-wrong-bid', expected: 'fail', commit: goodCommit(), reveal: goodReveal({ bid: { price: { amount: '1.00', currency: 'USDC' } } }), note: 'revealed a DIFFERENT bid than committed → bidHash mismatch, excluded' },
  { name: 'binding-wrong-salt', expected: 'fail', commit: goodCommit(), reveal: goodReveal({ salt: 'beef'.repeat(8) }), note: 'wrong salt → bidHash mismatch, excluded' },
  // do-not-collapse: anchor unresolvable → indeterminate
  { name: 'commit-anchor-unresolvable', expected: 'indeterminate', commit: goodCommit({ anchorTimestamp: null }), reveal: goodReveal(), note: 'commit SR-2 anchor timestamp unresolvable → cannot apply the deadline gate (NOT fail, NOT pass)' },
  { name: 'reveal-anchor-unresolvable', expected: 'indeterminate', commit: goodCommit(), reveal: goodReveal({ anchorTimestamp: null }), note: 'reveal SR-2 anchor timestamp unresolvable → cannot apply the window gate' },
  // malformed → error
  { name: 'malformed-commit', expected: 'error', commit: { bidderClaim: SENDER, anchorTimestamp: DEADLINE - 1000 } as unknown as Commit, reveal: goodReveal(), note: 'missing bidHash → verifier-side parse error' },
  { name: 'salt-not-hex', expected: 'error', commit: goodCommit(), reveal: goodReveal({ salt: 'nothex!!' }), note: 'salt not hex → cannot open commitment → error' },
  { name: 'bidhash-not-lowercase-hex', expected: 'error', commit: goodCommit({ bidHash: BIDHASH.toUpperCase() }), reveal: goodReveal(), note: '§8.4.3: bidHash MUST be lowercase hex — an uppercase committed hash is non-conformant → error (not silently admitted, Codex-HIGH)' },
];

let pass = 0;
console.log('\n=== DACS §8.4.3 sealed-envelope bid-admission conformance vectors v0.1 (#158: #27) ===');
for (const c of cases) {
  const v = checkSealedBidAdmission(c.commit, c.reveal, ctx);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(36)} exp=${c.expected.padEnd(13)} got=${v.decision}`);
}
const vectorsOut = { set: 'sealed-envelope-deadline-v0.1', spec: 'DACS-3 §8.4.3 (SE-2/SE-3/SE-4 + CH-3 + commitment binding)', gaps: ['#27 sealed-envelope post-deadline'],
  decisionModel: '§7.5.1 4-value, never collapsed', ctx, count: cases.length,
  cases: cases.map((c) => ({ name: c.name, expected: c.expected, note: c.note, commit: c.commit, reveal: c.reveal })) };
const json = JSON.stringify(vectorsOut, null, 2);
writeFileSync(`${DIR}/vectors/sealed-envelope-deadline-v0.1.json`, json + '\n');
console.log(`\n${pass}/${cases.length} vectors pass → vectors/sealed-envelope-deadline-v0.1.json  (set sha256 ${sha(json).slice(0, 16)})`);
if (pass !== cases.length) process.exit(1);
