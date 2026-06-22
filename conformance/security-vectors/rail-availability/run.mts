/**
 * Conformance vectors for DACS-4 rail-availability PINNING — GAP #13 (DACS-Standard#158).
 * Read-before-pin: a post-pin change to the §9.5 rail-availability is poisoning. Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifyRailAvailabilityPin } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

type Case = { name: string; expected: 'accept' | 'reject' | 'indeterminate' | 'error'; presented: unknown; pinned: unknown };
const cases: Case[] = [
  { name: 'pin-holds-live', expected: 'accept', presented: 'live', pinned: 'live' },
  { name: 'pin-holds-failed', expected: 'accept', presented: 'failed', pinned: 'failed' },          // honest failed settlement, consistent
  // THE core #13 attack: synthetic/test evidence dressed up as real on-chain settlement
  { name: 'poison-upgrade-mocked-to-live', expected: 'reject', presented: 'live', pinned: 'mocked' },
  { name: 'poison-upgrade-failed-to-live', expected: 'reject', presented: 'live', pinned: 'failed' },
  { name: 'poison-upgrade-disabled-to-operator_gated', expected: 'reject', presented: 'operator_gated', pinned: 'disabled' },
  // a downgrade is still a post-pin change (inconsistency) → reject
  { name: 'change-downgrade-live-to-failed', expected: 'reject', presented: 'failed', pinned: 'live' },
  // absent presented → cannot confirm the pin held → indeterminate, NEVER assume live
  { name: 'absent-presented-indeterminate', expected: 'indeterminate', presented: undefined, pinned: 'live' },
  // unrecognized presented value → error (verifier-side, never reject)
  { name: 'unknown-presented-error', expected: 'error', presented: 'super-live', pinned: 'live' },
  // case/whitespace variant MUST NOT be coerced to a known value → error (no silent normalization)
  { name: 'case-variant-not-coerced', expected: 'error', presented: 'Live', pinned: 'live' },
  // unrecognized PINNED baseline → error (verifier misconfig; no trusted baseline)
  { name: 'unknown-pinned-error', expected: 'error', presented: 'live', pinned: 'totally-live' },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, presented: c.presented ?? null, pinned: c.pinned }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/rail-availability-v0.1.json`, JSON.stringify({
  set: 'rail-availability-v0.1', spec: 'DACS-4 rail-availability §9.5 pinning (read-before-pin) — GAP #13 (DACS-Standard#158)',
  note: 'Behaviour-keyed (survives the v0.2 §-renumber). accept=pin held; reject=post-pin change (UPGRADE = the dangerous poisoning direction); indeterminate=presented absent (never assume live); error=unrecognized value / no trusted pinned baseline. Mirrors the §7.4.5 recipe-availability preflight, adding the read-before-pin comparison.',
  scope: 'Validates PIN-CONSISTENCY of the rail availability FIELD only — NOT that the rail settled on-chain, nor finality/receipt/registry-signature/version. Verdict is pure exact-match; the favorability rank is diagnostic-only (labels poison direction, no verdict effect). indeterminate is non-success; absent availability is never defaulted to live. No case/whitespace coercion (a variant is unrecognized → error).',
  hash: setHash, count: vectors.length, vectors,
}, null, 2));

let pass = 0;
console.log('\n=== DACS-4 rail-availability pinning conformance vectors v0.1 (GAP #13) ===');
for (const tc of cases) {
  const v = verifyRailAvailabilityPin(tc.presented, tc.pinned);
  const ok = v.decision === tc.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${tc.name.padEnd(40)} exp=${tc.expected.padEnd(13)} got=${v.decision.padEnd(13)} :${v.checks.map((k) => k.id).join(',')}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/rail-availability-v0.1.json`);
if (pass !== cases.length) process.exit(1);
