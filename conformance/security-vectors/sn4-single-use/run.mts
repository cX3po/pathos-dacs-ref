/**
 * Conformance vectors for CORE §B.8 SN-4 single-use (consume/reject-reuse branch).
 * Per RB on DACS-Standard#143 — covers the per-jobId consumed-marker branch. Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifySN4SingleUse, type SN4Input } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const N = 'a3f1c8e9d2b40576a1c3e5f7091b2d4e6080a2c4e6f80911223344556677889900';  // a well-formed issued nonce
const J = 'job-7f3a';

type Case = { name: string; expected: 'accept' | 'reject' | 'indeterminate' | 'error'; input: SN4Input };
const cases: Case[] = [
  // first valid use → accept (verifier then marks it consumed)
  { name: 'first-use', expected: 'accept', input: { jobId: J, nonce: N, consumedBefore: [] } },
  // the SN-4 attack: same nonce re-presented for the same jobId after consumption → reject
  { name: 'reuse-same-job-rejected', expected: 'reject', input: { jobId: J, nonce: N, consumedBefore: [[J, N]] } },
  // per-jobId scoping: a nonce consumed for a DIFFERENT job doesn't block this job's first use → accept
  { name: 'same-nonce-different-job-ok', expected: 'accept', input: { jobId: J, nonce: N, consumedBefore: [['job-OTHER', N]] } },
  // a different nonce for this job (an earlier one consumed) → accept (this one is fresh)
  { name: 'different-nonce-same-job-ok', expected: 'accept', input: { jobId: J, nonce: N, consumedBefore: [[J, 'b' + N.slice(1)]] } },
  // consumed-ledger unreadable → indeterminate (never assume fresh)
  { name: 'unreadable-ledger-indeterminate', expected: 'indeterminate', input: { jobId: J, nonce: N, ledgerReadable: false } },
  // malformed → error
  { name: 'missing-nonce-error', expected: 'error', input: { jobId: J, consumedBefore: [] } },
  { name: 'empty-jobid-error', expected: 'error', input: { jobId: '', nonce: N, consumedBefore: [] } },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, input: c.input }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/sn4-single-use-v0.1.json`, JSON.stringify({
  set: 'sn4-single-use-v0.1', spec: 'CORE §B.8 SN-4 single-use (consume/reject-reuse) — DACS-Standard#143 / §14.6',
  note: 'Covers the SN-4 branch the stateless vp-replay set (PR #18) does NOT: per-jobId consume-on-attempt + reject-reuse. Behaviour-keyed. accept=first use (then mark consumed); reject=already-consumed (replay); indeterminate=ledger unreadable (never assume fresh); error=malformed. Single-use scoped to (jobId,nonce) — a nonce consumed for one job does not block another (each session issued its own nonce per SN-1/SN-3).',
  hash: setHash, count: vectors.length, vectors,
}, null, 2));

let pass = 0;
console.log('\n=== CORE §B.8 SN-4 single-use conformance vectors v0.1 (consume/reject-reuse) ===');
for (const tc of cases) {
  const v = verifySN4SingleUse(tc.input);
  const ok = v.decision === tc.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${tc.name.padEnd(34)} exp=${tc.expected.padEnd(13)} got=${v.decision.padEnd(13)} :${v.checks.map((k) => k.id).join(',')}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/sn4-single-use-v0.1.json`);
if (pass !== cases.length) process.exit(1);
