/**
 * Generate os-string-vectors.json from cases.ts. Run: npx tsx vectors/os-string/generate.mts
 * Guarded by test/vectors/os-string.test.ts (re-derives every accept round-trip + reject + laxity).
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { STRICT_OS, acceptCases, rejectCases } from './cases.js';

const acceptVectors = acceptCases.map((c) => ({
  id: c.id,
  s: c.s,
  description: c.description,
  // round-trip proof: the canonical reader/writer pair must satisfy BigInt(s).toString() === s
  roundTrips: BigInt(c.s).toString() === c.s,
}));

const rejectVectors = rejectCases.map((c) => ({
  id: c.id, s: c.s, reason: c.reason,
  bareBigIntAccepts: c.bareBigIntAccepts,
}));

const out = {
  generatedBy: 'pathos-dacs-ref vectors/os-string/generate.mts',
  grammar: STRICT_OS.source, // ^(0|[1-9][0-9]*)$
  note: 'Demos OS amounts are non-negative decimal strings on the wire; the canonical writer is '
      + 'toOsString(os)=os.toString(). A conforming READER MUST accept exactly the writer\'s image and '
      + 'REJECT every other string (a permissive reader makes re-serialize non-idempotent → hash drift). '
      + '`bareBigIntAccepts` flags reject cases that bare BigInt() — @kynesyslabs/demosdk v4.0.8 parseOsString '
      + '(src/denomination/conversion.ts) — admits outside the canonical grammar.',
  acceptVectors,
  rejectVectors,
};

const dir = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(dir, 'os-string-vectors.json'), JSON.stringify(out, null, 2) + '\n');
const lax = rejectVectors.filter((r) => r.bareBigIntAccepts).length;
console.log(`wrote ${acceptVectors.length} accept + ${rejectVectors.length} reject (${lax} wrongly accepted by bare BigInt)`);
