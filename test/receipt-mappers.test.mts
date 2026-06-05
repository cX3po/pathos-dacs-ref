/**
 * Unit tests for the receipt mappers (pure, no network). Run: npx tsx test/receipt-mappers.test.mts
 */
import { fromVerifyVerdict, fromArtifact } from '../src/demos/receipt-mappers.js';
import type { VerifyVerdict } from '../src/types/bundle.js';

let failed = 0;
function check(name: string, cond: boolean) {
  console.log(`  ${cond ? '✓' : '✗'} ${name}`);
  if (!cond) failed++;
}

// 1. fromVerifyVerdict reuses the verdict's own hash + decision (no re-hashing)
const verdict: VerifyVerdict = {
  decision: 'pass',
  jobId: 'job-123',
  steps: [],
  canonicalBundleHash: 'a'.repeat(64),
  signersVerified: ['pk1', 'pk2'],
  attestationsVerified: 3,
  attestationsFailed: 0,
};
const r1 = fromVerifyVerdict(verdict, '2026-06-05T20:00:00Z');
check('verdict→kind dacs5-verdict', r1.kind === 'dacs5-verdict');
check('verdict→ref is jobId', r1.ref === 'job-123');
check('verdict→contentHash reuses canonicalBundleHash', r1.contentHash === 'a'.repeat(64));
check('verdict→outcome is decision', r1.outcome === 'pass');
check('verdict→at injectable', r1.at === '2026-06-05T20:00:00Z');
check('verdict→detail counts', (r1.detail as any).signersVerified === 2 && (r1.detail as any).attestationsVerified === 3);

// 2. fromArtifact is deterministic + JCS key-order independent
const a = fromArtifact('gate-verdict', 'gate-1', { b: 2, a: 1 }, { at: 't' });
const b = fromArtifact('gate-verdict', 'gate-1', { a: 1, b: 2 }, { at: 't' });
check('artifact hash deterministic + key-order independent', a.contentHash === b.contentHash);
check('artifact contentHash is 64 hex', /^[0-9a-f]{64}$/.test(a.contentHash));
check('artifact different content → different hash', fromArtifact('k', 'r', { a: 1 }).contentHash !== fromArtifact('k', 'r', { a: 2 }).contentHash);

// 3. fromArtifact carries outcome/detail
const c = fromArtifact('capture-milestone', 'm-1', { note: 'x' }, { outcome: 'APPROVED', at: 't', detail: { n: 1 } });
check('artifact carries outcome', c.outcome === 'APPROVED');
check('artifact carries detail', (c.detail as any).n === 1);

console.log(`\n${failed === 0 ? 'ALL PASS' : failed + ' FAILED'}`);
process.exit(failed === 0 ? 0 : 1);
