/**
 * NON-NORMATIVE reference vectors for the SR-4 replay-coordinate capability hook (DACS-Standard #195).
 * Demonstrates the proposal concretely: a black-box opaque-token equality contract is enough to test
 * the nonce-reuse / channel-replay MUST-REJECT without DACS defining the crypto envelope fields.
 * Run: npx tsx run.mts → writes vectors/replay-coordinate-v0.1.json, exits 1 on mismatch.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkReplayCoordinate, type ReplayMessage, type SessionCtx } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const SID = 'sess-A';
const ctx = (admitted: string[] = [], sessionId = SID): SessionCtx => ({ sessionId, admittedCoordinates: admitted });

type Dec = 'pass' | 'fail' | 'indeterminate' | 'error';
type Case = { name: string; expected: Dec; msg: ReplayMessage; ctx: SessionCtx; note: string };

const cases: Case[] = [
  // pass — fresh coordinate
  { name: 'fresh-first-coordinate', expected: 'pass', msg: { replayCoordinate: 'k7:e3:n0001', ref: 'm1' }, ctx: ctx([]), note: 'first message of the session, no coordinate admitted yet → admit' },
  { name: 'fresh-subsequent-coordinate', expected: 'pass', msg: { replayCoordinate: 'k7:e3:n0002', ref: 'm2' }, ctx: ctx(['k7:e3:n0001']), note: 'distinct fresh coordinate after a prior admit → admit' },
  { name: 'same-token-different-session', expected: 'pass', msg: { replayCoordinate: 'k7:e3:n0001', ref: 'm1-in-B' }, ctx: ctx([], 'sess-B'), note: 'session-scoped: a token admitted in session A is fresh in session B (no global ledger) → admit' },
  { name: 'near-duplicate-different-bytes', expected: 'pass', msg: { replayCoordinate: 'K7:E3:N0001', ref: 'upper' }, ctx: ctx(['k7:e3:n0001']), note: 'exact-equality contract: a different-byte token is a different coordinate → admit (canonical emission is the substrate’s responsibility, like the crypto envelope)' },
  // fail — the MUST-REJECT headline
  { name: 'duplicate-coordinate', expected: 'fail', msg: { replayCoordinate: 'k7:e3:n0001', ref: 'replay' }, ctx: ctx(['k7:e3:n0001']), note: 'coordinate already admitted in this session → duplicate/replay, MUST reject' },
  { name: 'duplicate-after-many', expected: 'fail', msg: { replayCoordinate: 'k7:e3:n0002', ref: 'replay-2' }, ctx: ctx(['k7:e3:n0001', 'k7:e3:n0002', 'k7:e3:n0003']), note: 'replay of a non-most-recent admitted coordinate → MUST reject' },
  { name: 'nonce-reuse-same-key-epoch', expected: 'fail', msg: { replayCoordinate: 'key=ab12|epoch=5|nonce=00ff', ref: 'l2ps-reuse' }, ctx: ctx(['key=ab12|epoch=5|nonce=00ff']), note: 'the L2PS case made black-box: same (key,epoch,nonce) folded into one token, re-presented → MUST reject' },
  // indeterminate — hook unobservable
  { name: 'no-coordinate-emitted', expected: 'indeterminate', msg: { ref: 'no-token' }, ctx: ctx(['k7:e3:n0001']), note: 'substrate emits no replay coordinate → capability unobservable, cannot decide (NOT a fail)' },
  { name: 'null-coordinate', expected: 'indeterminate', msg: { replayCoordinate: null, ref: 'null-token' }, ctx: ctx([]), note: 'explicit null coordinate → unobservable → indeterminate' },
  // error — malformed
  { name: 'empty-string-coordinate', expected: 'error', msg: { replayCoordinate: '', ref: 'empty' }, ctx: ctx([]), note: 'coordinate present but empty → not a well-formed opaque token → error' },
  { name: 'non-string-coordinate', expected: 'error', msg: { replayCoordinate: 1234 as unknown as string, ref: 'numeric' }, ctx: ctx([]), note: 'coordinate present but not a string token → malformed → error' },
  { name: 'malformed-ctx-admitted-not-array', expected: 'error', msg: { replayCoordinate: 'k7:e3:n0001' }, ctx: { sessionId: SID, admittedCoordinates: 'k7:e3:n0001' as unknown as string[] }, note: 'session ctx admittedCoordinates not an array → malformed ctx → error' },
  { name: 'malformed-ctx-bad-element', expected: 'error', msg: { replayCoordinate: 'k7:e3:n0001' }, ctx: { sessionId: SID, admittedCoordinates: ['', 99 as unknown as string] }, note: 'admittedCoordinates contains non-token elements → malformed ctx → error' },
  { name: 'malformed-ctx-empty-sessionId', expected: 'error', msg: { replayCoordinate: 'k7:e3:n0001' }, ctx: { sessionId: '', admittedCoordinates: [] }, note: 'empty sessionId → malformed ctx → error' },
];

let pass = 0, total = 0;
console.log('\n=== NON-NORMATIVE SR-4 replay-coordinate hook reference vectors v0.1 (DACS #195 proposal) ===');
for (const c of cases) {
  const v = checkReplayCoordinate(c.msg, c.ctx);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0; total += 1;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(34)} exp=${c.expected.padEnd(13)} got=${v.decision}`);
}
// robustness: a SPARSE admittedCoordinates (holes) cannot round-trip through JSON, so assert inline.
// Codex binding review: .every skips holes — a sparse ctx must be rejected as malformed (error), not accepted.
{
  const sparse: string[] = ['k7:e3:n0001']; sparse[3] = 'k7:e3:n0004';   // indices 1,2 are holes
  const v = checkReplayCoordinate({ replayCoordinate: 'k7:e3:n0009' }, { sessionId: SID, admittedCoordinates: sparse });
  const ok = v.decision === 'error';
  pass += ok ? 1 : 0; total += 1;
  console.log(`  [${ok ? '✓' : '✗'}] ${'(robust) sparse-admitted-array'.padEnd(34)} exp=${'error'.padEnd(13)} got=${v.decision}`);
}
const vectorsOut = {
  set: 'replay-coordinate-v0.1',
  normative: false,
  spec: 'NON-NORMATIVE reference impl of the SR-4 abstract replay-coordinate hook proposed on DACS-Standard #195',
  contract: 'Within one session, two admitted messages MUST NOT share a replay coordinate; a re-presented coordinate MUST be rejected. The coordinate is an opaque substrate-emitted equality token; DACS would define only this observable, never the crypto envelope fields.',
  decisionModel: '§7.5.1 4-value, never collapsed',
  count: cases.length,
  cases: cases.map((c) => ({ name: c.name, expected: c.expected, note: c.note, message: c.msg, ctx: c.ctx })),
};
const json = JSON.stringify(vectorsOut, null, 2);
writeFileSync(`${DIR}/vectors/replay-coordinate-v0.1.json`, json + '\n');
console.log(`\n${pass}/${total} checks pass (${cases.length} persisted vectors + ${total - cases.length} robustness) → vectors/replay-coordinate-v0.1.json  (set sha256 ${sha(json).slice(0, 16)})`);
if (pass !== total) process.exit(1);
