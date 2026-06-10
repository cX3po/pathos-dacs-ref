/**
 * Generate canonical-form-vectors.json from the shared cases (oracle: src/jcs.ts).
 * Run: npx tsx vectors/canonical-form/generate.mts
 * The committed JSON is guarded by test/vectors/canonical-form.test.ts (re-derives every hash).
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { jcsHashHex } from '../../src/jcs.js';
import { acceptCases, rejectCases } from './cases.js';

const acceptVectors = acceptCases.map((c) => ({
  id: c.id,
  description: c.description,
  input: c.build(),
  expectedSha256: jcsHashHex(c.build()),
  ...(c.sameHashAs ? { sameHashAs: c.sameHashAs } : {}),
}));

const rejectVectors = rejectCases.map((c) => ({ id: c.id, description: c.description, reason: c.reason }));

const out = {
  generatedBy: 'pathos-dacs-ref vectors/canonical-form/generate.mts',
  oracle: 'src/jcs.ts (RFC 8785 JCS + DACS section B.2 pre-pass: NFC values+keys, safe-int, surrogate-reject, key-collision-reject)',
  note: 'Accept vectors: sha256 of the JCS canonical form of input MUST equal expectedSha256. Reject vectors are not JSON-representable (BigInt / lone surrogate / over-2^53 / NFC key-collision) - construct per cases.ts builders; a conforming canonicaliser MUST reject each.',
  acceptVectors,
  rejectVectors,
};

const dir = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(dir, 'canonical-form-vectors.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${acceptVectors.length} accept + ${rejectVectors.length} reject vectors`);
