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
const ISSUED_AT = 1_000;
const LIFETIME = 5_000;

const liveChallenge = (overrides: Partial<SN4Input> = {}): SN4Input => ({
  jobId: J,
  nonce: N,
  issuedForJobId: J,
  issuedNonce: N,
  issuedAtMs: ISSUED_AT,
  observedAtMs: ISSUED_AT + 1_000,
  challengeLifetimeMs: LIFETIME,
  presentationOtherwiseValid: true,
  consumedBefore: [],
  recordReadable: true,
  ...overrides,
});

type Case = {
  name: string;
  expected: 'accept' | 'reject' | 'indeterminate' | 'error';
  expectedConsumedOnAttempt: boolean;
  input: SN4Input;
};
const cases: Case[] = [
  // first valid use → accept (verifier then marks it consumed)
  { name: 'first-use', expected: 'accept', expectedConsumedOnAttempt: true, input: liveChallenge() },
  // the SN-4 attack: same nonce re-presented for the same jobId after consumption → reject
  { name: 'reuse-same-job-rejected', expected: 'reject', expectedConsumedOnAttempt: false, input: liveChallenge({ consumedBefore: [[J, N]] }) },
  // Per-job consumption scoping is safe only because this record independently proves issuance for J.
  { name: 'separately-issued-for-current-job-not-blocked-by-other-job-consumption', expected: 'accept', expectedConsumedOnAttempt: true, input: liveChallenge({ consumedBefore: [['job-OTHER', N]] }) },
  // The same nonce bytes issued only for another job never validate for this job.
  { name: 'nonce-issued-for-different-job-rejected', expected: 'reject', expectedConsumedOnAttempt: false, input: liveChallenge({ issuedForJobId: 'job-OTHER' }) },
  // a different nonce for this job (an earlier one consumed) → accept (this one is fresh)
  { name: 'different-nonce-same-job-ok', expected: 'accept', expectedConsumedOnAttempt: true, input: liveChallenge({ consumedBefore: [[J, 'b' + N.slice(1)]] }) },
  // Exact lifetime boundary is still live; one millisecond later is expired.
  { name: 'challenge-at-lifetime-boundary-accepted', expected: 'accept', expectedConsumedOnAttempt: true, input: liveChallenge({ observedAtMs: ISSUED_AT + LIFETIME }) },
  { name: 'challenge-past-lifetime-rejected', expected: 'reject', expectedConsumedOnAttempt: true, input: liveChallenge({ observedAtMs: ISSUED_AT + LIFETIME + 1 }) },
  // A later validation failure still burns the correctly issued nonce on this attempt.
  { name: 'later-presentation-failure-still-consumes', expected: 'reject', expectedConsumedOnAttempt: true, input: liveChallenge({ presentationOtherwiseValid: false }) },
  // Challenge record unreadable before terminal state → indeterminate (never assume fresh).
  { name: 'unreadable-record-indeterminate', expected: 'indeterminate', expectedConsumedOnAttempt: false, input: liveChallenge({ recordReadable: false }) },
  // malformed → error
  { name: 'missing-nonce-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ nonce: undefined }) },
  { name: 'empty-jobid-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ jobId: '' }) },
  { name: 'non-positive-lifetime-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ challengeLifetimeMs: 0 }) },
  { name: 'record-readable-nonboolean-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ recordReadable: 'false' }) },
  { name: 'consumed-ledger-object-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ consumedBefore: {} }) },
  { name: 'consumed-ledger-malformed-tuple-error', expected: 'error', expectedConsumedOnAttempt: false, input: liveChallenge({ consumedBefore: [[J]] }) },
];

const vectors = cases.map((c) => ({
  name: c.name,
  expected: c.expected,
  expectedConsumedOnAttempt: c.expectedConsumedOnAttempt,
  input: c.input,
}));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/sn4-single-use-v0.1.json`, JSON.stringify({
  set: 'sn4-single-use-v0.1', spec: 'CORE §B.8 SN-4 single-use (consume/reject-reuse) — DACS-Standard#143 / §14.6',
  note: 'Covers SN-4 consume-on-attempt/reject-reuse and bounded lifetime with explicit SN-3 issuance binding. Behaviour-keyed. accept=issued for this job, unexpired first use; reject=wrong-job issuance, expired challenge, replay, or later presentation failure; indeterminate=issued/consumed record unreadable; error=malformed. Every matching issued-nonce attempt records whether it newly consumed the challenge. Consumption is scoped to (jobId,nonce), but the same bytes under another job never authorize this presentation. Durable retention until terminal state and atomic persistence remain unproven implementation/harness obligations.',
  hash: setHash, count: vectors.length, vectors,
}, null, 2));

let pass = 0;
console.log('\n=== CORE §B.8 SN-4 single-use conformance vectors v0.1 (consume/reject-reuse) ===');
for (const tc of cases) {
  const v = verifySN4SingleUse(tc.input);
  const ok = v.decision === tc.expected && v.consumedOnAttempt === tc.expectedConsumedOnAttempt;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${tc.name.padEnd(34)} exp=${tc.expected.padEnd(13)} got=${v.decision.padEnd(13)} consumed=${String(v.consumedOnAttempt).padEnd(5)} :${v.checks.map((k) => k.id).join(',')}`);
}

// Stateful proof: a presentation that fails after nonce match still burns the
// challenge, and replaying from the returned state is rejected.
const failedAttempt = verifySN4SingleUse(liveChallenge({ presentationOtherwiseValid: false }));
const retry = verifySN4SingleUse(liveChallenge({ consumedBefore: failedAttempt.consumedAfter }));
const sequenceOk = failedAttempt.decision === 'reject' &&
  failedAttempt.consumedOnAttempt &&
  retry.decision === 'reject' &&
  !retry.consumedOnAttempt;
console.log(`  [${sequenceOk ? '✓' : '✗'}] failed-attempt-state-transition    first=${failedAttempt.decision}/consumed:${failedAttempt.consumedOnAttempt} retry=${retry.decision}`);
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/sn4-single-use-v0.1.json`);
if (pass !== cases.length || !sequenceOk) process.exit(1);
