/**
 * Conformance vectors for DACS-3 sealed-envelope deadline enforcement — GAP #27 (DACS-Standard#158).
 * Chain-timestamp anchoring: a commit after / reveal outside the window is rejected. Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifySealedEnvelopeTiming, type SealedTimingInput } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const DL = 1_800_000_000_000;        // commitDeadline (unix ms)
const W = 600;                       // revealWindow (s) → window end = DL + 600_000
const END = DL + W * 1000;

type Case = { name: string; expected: 'accept' | 'reject' | 'indeterminate' | 'error'; input: SealedTimingInput };
const cases: Case[] = [
  // commit phase
  { name: 'commit-before-deadline', expected: 'accept', input: { phase: 'commit', anchoredTs: DL - 5000, commitDeadline: DL, revealWindow: W } },
  { name: 'commit-at-deadline-boundary', expected: 'accept', input: { phase: 'commit', anchoredTs: DL, commitDeadline: DL, revealWindow: W } }, // INCLUSIVE boundary — convergence note
  { name: 'commit-post-deadline-LATE', expected: 'reject', input: { phase: 'commit', anchoredTs: DL + 1, commitDeadline: DL, revealWindow: W } }, // the #27 attack
  // reveal phase
  { name: 'reveal-in-window', expected: 'accept', input: { phase: 'reveal', anchoredTs: DL + 60_000, commitDeadline: DL, revealWindow: W } },
  { name: 'reveal-before-deadline-breaks-seal', expected: 'reject', input: { phase: 'reveal', anchoredTs: DL - 1, commitDeadline: DL, revealWindow: W } },
  { name: 'reveal-post-window-LATE', expected: 'reject', input: { phase: 'reveal', anchoredTs: END + 1, commitDeadline: DL, revealWindow: W } },
  { name: 'reveal-at-window-end-boundary', expected: 'accept', input: { phase: 'reveal', anchoredTs: END, commitDeadline: DL, revealWindow: W } },
  // chain-timestamp anchoring point: NO anchored ts → indeterminate (never trust self-claimed time)
  { name: 'no-anchored-ts-indeterminate', expected: 'indeterminate', input: { phase: 'commit', anchoredTs: null, commitDeadline: DL, revealWindow: W } },
  // malformed params → error
  { name: 'revealWindow-too-short-error', expected: 'error', input: { phase: 'reveal', anchoredTs: DL + 1000, commitDeadline: DL, revealWindow: 30 } },
  { name: 'nonfinite-deadline-error', expected: 'error', input: { phase: 'commit', anchoredTs: DL, commitDeadline: NaN, revealWindow: W } },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, input: c.input }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/sealed-envelope-deadline-v0.1.json`, JSON.stringify({
  set: 'sealed-envelope-deadline-v0.1', spec: 'DACS-3 §8.4.3 sealed-envelope deadline (chain-timestamp anchoring) — GAP #27 (DACS-Standard#158)',
  note: 'Behaviour-keyed (survives v0.2 §-renumber). accept=anchored time valid for phase; reject=post-deadline commit / pre-deadline reveal / post-window reveal; indeterminate=no anchored timestamp (timing unverifiable, never assume on-time); error=malformed params. Timing rests on the CHAIN-ANCHORED ts only — never a self-claimed time (the #27 hole).',
  conventionNote: 'Boundary ts == commitDeadline (commit) and ts == windowEnd (reveal) are treated INCLUSIVE here — an open convergence question for the spec/#158: are the deadline boundaries inclusive or exclusive? Flagging rather than asserting. Asymmetry by design: ts == commitDeadline is COMMIT phase (commit accepts, reveal rejects).',
  scope: 'Validates PHASE TIMING vs a caller-supplied anchored timestamp only. Does NOT verify the commitment hash, that the reveal opens it, identity/replay/uniqueness, that anchoredTs is genuinely chain-anchored, or chain finality/confirmation-depth. Closes #27 only if callers never substitute self-claimed time and treat ONLY accept as valid (indeterminate is non-accepted). Out of scope: commitDeadline-in-past at setup, revealWindow upper bound, anchoredTs-before-commit-open.',
  hash: setHash, count: vectors.length, vectors,
}, null, 2));

let pass = 0;
console.log('\n=== DACS-3 sealed-envelope deadline conformance vectors v0.1 (GAP #27) ===');
for (const tc of cases) {
  const v = verifySealedEnvelopeTiming(tc.input);
  const ok = v.decision === tc.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${tc.name.padEnd(38)} exp=${tc.expected.padEnd(13)} got=${v.decision.padEnd(13)} :${v.checks.map((k) => k.id).join(',')}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/sealed-envelope-deadline-v0.1.json`);
if (pass !== cases.length) process.exit(1);
