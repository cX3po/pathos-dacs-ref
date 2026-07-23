// Independent re-verification of an exported DACS receipt set (GATEWAY_DUMP_ARTIFACTS output).
// Reads the dump file ALONE — no gateway, no chain — builds a fetch resolver from the dump's own
// byte-faithful `raw` strings, and re-runs the full verifier with signatures ENFORCED and two-sided
// reconciliation ON. If this passes, the receipts stand entirely on their own.
import { readFileSync } from 'node:fs';
import { verifyBundleV1Full, computeAnchorPairV1 } from '../src/lib/verify-bundle-v1.js';

const path = process.argv[2];
if (!path) { console.error('usage: reverify-dump.mts <dump.json>'); process.exit(2); }
const dump = JSON.parse(readFileSync(path, 'utf8'));
if (dump.dumpFormat !== 'dacs-receipt-dump:v1') {
  console.error(`unsupported dump format: ${dump.dumpFormat ?? '(none)'} — expected dacs-receipt-dump:v1`);
  process.exit(2);
}

// locator -> raw anchored string, straight from the exported receipts.
const byLocator = new Map<string, string>();
for (const a of Object.values(dump.artifacts) as Array<{ locator: string; raw: string }>) {
  byLocator.set(a.locator, a.raw);
}

// Two-sided reconciliation (§10.4.3) fetches the buyer/seller bundle copies at addresses DERIVED
// from the jobId, not the dump's storage locators — register both copies under those derived
// addresses so the offline resolver can serve them.
for (const [k, a] of Object.entries(dump.artifacts) as Array<[string, { raw: string }]>) {
  const m = /^dacs5:bundle:(.+):(buyer|seller)$/.exec(k);
  if (!m) continue;
  const pair = computeAnchorPairV1(m[1]!);
  byLocator.set(m[2] === 'buyer' ? pair.buyer : pair.seller, a.raw);
}

// Offline resolver: serves the exact anchored bytes from the dump, never touches the network.
const fetchFromDump = async (_rpc: string, storageAddress: string) => {
  const raw = byLocator.get(storageAddress);
  if (raw === undefined) return null;
  return { storageAddress, owner: '', data: raw, sizeBytes: raw.length, createdByTx: '', createdAt: 0 };
};

const bundleKey = Object.keys(dump.artifacts).find((k) => k.startsWith('dacs5:bundle:') && k.endsWith(':buyer'))
  ?? Object.keys(dump.artifacts).find((k) => k.startsWith('dacs5:bundle:'));
if (!bundleKey) { console.error('no dacs5:bundle in dump'); process.exit(1); }

const bundle = (dump.artifacts[bundleKey] as { content: unknown }).content;
const verdict = await verifyBundleV1Full(bundle as never, {
  requireSignatures: true,
  fetchAnchoredImpl: fetchFromDump as never,
});

console.log(`source file: ${path}`);
console.log(`bundle:      ${bundleKey}`);
console.log(`rollup:      ${verdict.rollup.toUpperCase()}`);
console.log(`two-sided:   ${verdict.twoSided.outcome}`);
console.log(`attestations: ${verdict.attestationsVerified} verified, ${verdict.attestationsFailed} failed`);
console.log(`structural:  ${verdict.structurallyValid ? 'valid' : 'INVALID'}`);
process.exit(verdict.rollup === 'pass' ? 0 : 1);
