/**
 * DACS §8.3.3 / CH-6 channel-message replay conformance vectors (matrix #14).
 * Per-session channelId uniqueness (CH-6), channel binding, signature, monotonic per-channel sequence.
 * Run: npx tsx run.mts → writes vectors/channel-message-replay-v0.1.json, exits 1 on any mismatch.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkChannelMessage, channelSignedBytes, pubRawFromSeed, edSign, type ChannelMessage, type ChannelCtx } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const seed = (n: number) => Buffer.alloc(32, n).toString('hex');

const SENDER_SEED = seed(0xc1), ATTACKER_SEED = seed(0xc2);
const SENDER = `cci:${pubRawFromSeed(SENDER_SEED)}`;
const CHAN = 'chan-session-7';
const PRIOR = ['chan-session-1', 'chan-session-2'];

/** build a properly-signed message (sign over the §8.3.3 signed scope with the sender's key). */
function msg(over: Partial<ChannelMessage> = {}, signSeed = SENDER_SEED): ChannelMessage {
  const base: ChannelMessage = { channelId: CHAN, sequence: 1, sender: SENDER, sentAt: 1_750_000_000_000, type: 'offer', body: { price: '10' }, signature: '' };
  const m = { ...base, ...over };
  m.signature = edSign(channelSignedBytes(m), signSeed);
  return m;
}
const ctx = (over: Partial<ChannelCtx> = {}): ChannelCtx => ({ sessionChannelId: CHAN, lastSequence: 0, priorChannelIds: PRIOR, ...over });

type Dec = 'pass' | 'fail' | 'indeterminate' | 'error';
type Case = { name: string; expected: Dec; msg: ChannelMessage; ctx: ChannelCtx; note: string };

// a genuine message that was anchored in a PRIOR session (signed over channelId chan-session-1, seq 1)
const priorSessionMsg = msg({ channelId: 'chan-session-1', sequence: 1 });
// the attacker re-channels it to the current session WITHOUT re-signing (signature still over the old channelId)
const reChannelled: ChannelMessage = { ...priorSessionMsg, channelId: CHAN };

const cases: Case[] = [
  { name: 'valid-first-message', expected: 'pass', msg: msg({ sequence: 1 }), ctx: ctx({ lastSequence: 0 }), note: 'seq 1, correct channel, valid sig, no prior reuse → admit' },
  { name: 'valid-next-message', expected: 'pass', msg: msg({ sequence: 2 }), ctx: ctx({ lastSequence: 1 }), note: 'strictly-increasing sequence → admit' },
  { name: 'valid-sequence-gap', expected: 'pass', msg: msg({ sequence: 5 }), ctx: ctx({ lastSequence: 2 }), note: 'monotonic allows a gap (5 > 2) — replay defence cares about duplicates/decreases, not gaps → admit' },
  // sequence replay
  { name: 'replay-duplicate-sequence', expected: 'fail', msg: msg({ sequence: 3 }), ctx: ctx({ lastSequence: 3 }), note: 'sequence == last-seen → duplicate/replay, excluded' },
  { name: 'replay-decreasing-sequence', expected: 'fail', msg: msg({ sequence: 2 }), ctx: ctx({ lastSequence: 5 }), note: 'sequence < last-seen → out-of-order/replay, excluded' },
  // cross-session replay — both mechanisms
  { name: 'foreign-channel-message', expected: 'fail', msg: priorSessionMsg, ctx: ctx({ lastSequence: 0 }), note: 'a session-1 message presented in session-7: channelId ≠ session → excluded' },
  { name: 'rechannelled-message-sig-breaks', expected: 'fail', msg: reChannelled, ctx: ctx({ lastSequence: 0 }), note: 'attacker rewrites channelId to the new session — signature (over the old channelId) no longer verifies → excluded' },
  // CH-6 — session reuses a prior channelId
  { name: 'ch6-channelId-reused', expected: 'fail', msg: msg({ sequence: 1 }), ctx: ctx({ sessionChannelId: 'chan-session-1', lastSequence: 0 }), note: 'CH-6: this session reuses a prior session\'s channelId → session rejected' },
  // signature
  { name: 'tampered-signature', expected: 'fail', msg: { ...msg({ sequence: 1 }), signature: 'aa'.repeat(64) }, ctx: ctx({ lastSequence: 0 }), note: 'signature does not verify → excluded' },
  { name: 'tampered-body-after-signing', expected: 'fail', msg: { ...msg({ sequence: 1 }), body: { price: '999' } }, ctx: ctx({ lastSequence: 0 }), note: 'body changed after signing → envelope hash differs → signature invalid' },
  // do-not-collapse: sender key unresolvable → indeterminate
  { name: 'sender-not-cci', expected: 'indeterminate', msg: msg({ sequence: 1, sender: 'did:demos:placeholder' }), ctx: ctx({ lastSequence: 0 }), note: 'sender claim not a resolvable cci key → cannot verify signature → undecidable' },
  // malformed → error
  { name: 'malformed-missing-channelId', expected: 'error', msg: { sequence: 1, sender: SENDER, sentAt: 1, type: 'offer', body: {}, signature: 'x' } as unknown as ChannelMessage, ctx: ctx(), note: 'missing channelId → verifier-side parse error' },
  { name: 'sequence-below-one', expected: 'error', msg: msg({ sequence: 0 }), ctx: ctx({ lastSequence: 0 }), note: 'sequence < 1 violates §8.3.3 (starts at 1) → error' },
  // malformed ctx → error (Codex: bad lastSequence/priorChannelIds must not bypass the monotonicity gate)
  { name: 'ctx-fractional-lastSequence', expected: 'error', msg: msg({ sequence: 2 }), ctx: { sessionChannelId: CHAN, lastSequence: 1.5, priorChannelIds: PRIOR }, note: 'ctx.lastSequence non-integer → would make `seq <= 1.5` unreliable; rejected as malformed ctx (not silently admitted)' },
  { name: 'ctx-priorChannelIds-bad-element', expected: 'error', msg: msg({ sequence: 1 }), ctx: { sessionChannelId: CHAN, lastSequence: 0, priorChannelIds: [123 as unknown as string] }, note: 'priorChannelIds contains a non-string → cannot evaluate CH-6 reliably → malformed ctx' },
];

// Robustness assertions for malformed inputs that CANNOT round-trip through a cross-impl JSON vector file
// (undefined / circular / BigInt body; NaN / Infinity lastSequence). These verify the checker returns `error`
// rather than collapsing to `fail`/`pass`; they are NOT persisted as language-neutral vectors. (Codex round-2.)
function assertErr(name: string, m: ChannelMessage, c: ChannelCtx): void {
  const v = checkChannelMessage(m, c);
  const ok = v.decision === 'error';
  pass += ok ? 1 : 0; total += 1;
  console.log(`  [${ok ? '✓' : '✗'}] ${('(robust) ' + name).padEnd(34)} exp=${'error'.padEnd(13)} got=${v.decision}`);
}
const circular: Record<string, unknown> = {}; circular.self = circular;

let pass = 0, total = 0;
console.log('\n=== DACS §8.3.3 / CH-6 channel-message replay conformance vectors v0.1 (matrix #14) ===');
for (const c of cases) {
  const v = checkChannelMessage(c.msg, c.ctx);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0; total += 1;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(34)} exp=${c.expected.padEnd(13)} got=${v.decision}`);
}
// non-serializable robustness checks (counted in the run total, excluded from the persisted vector file)
assertErr('body-undefined', { ...msg({ sequence: 1 }), body: undefined }, ctx({ lastSequence: 0 }));
assertErr('body-circular', { ...msg({ sequence: 1 }), body: circular }, ctx({ lastSequence: 0 }));
assertErr('body-bigint', { ...msg({ sequence: 1 }), body: { n: 1n as unknown as number } }, ctx({ lastSequence: 0 }));
assertErr('lastSequence-NaN', msg({ sequence: 2 }), { sessionChannelId: CHAN, lastSequence: NaN, priorChannelIds: PRIOR });
assertErr('lastSequence-Infinity', msg({ sequence: 2 }), { sessionChannelId: CHAN, lastSequence: Infinity, priorChannelIds: PRIOR });

const vectorsOut = { set: 'channel-message-replay-v0.1', spec: 'DACS-3 §8.3.3 + CH-6 (+ §8.12 replay analysis)', gaps: ['#14 cross-session offer replay / channelId reuse'],
  decisionModel: '§7.5.1 4-value, never collapsed', count: cases.length,
  cases: cases.map((c) => ({ name: c.name, expected: c.expected, note: c.note, message: c.msg, ctx: c.ctx })) };
const json = JSON.stringify(vectorsOut, null, 2);
writeFileSync(`${DIR}/vectors/channel-message-replay-v0.1.json`, json + '\n');
console.log(`\n${pass}/${total} checks pass (${cases.length} persisted vectors + ${total - cases.length} robustness) → vectors/channel-message-replay-v0.1.json  (set sha256 ${sha(json).slice(0, 16)})`);
if (pass !== total) process.exit(1);
