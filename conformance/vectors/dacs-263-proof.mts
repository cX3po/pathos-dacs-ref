/**
 * Proof harness for the DACS-Standard#263 signature-value encoding vector.
 * Runs the vector through our SHIPPED decoder (imported, not copied) and asserts
 * accept(canonical base64) / accept(canonical base64url) / reject(non-canonical).
 *   npx tsx conformance/vectors/dacs-263-proof.mts
 */
import { decodeEd25519Sig } from '../../src/lib/verify-bundle-v1.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const vec = JSON.parse(readFileSync(join(here, 'dacs-263-sig-value-encoding-v1.json'), 'utf8'));
let allPass = true;
for (const [name, e] of Object.entries<any>(vec.encodings)) {
  const verdict = decodeEd25519Sig(e.value) === null ? 'REJECT' : 'ACCEPT';
  const ok = verdict === e.expect;
  allPass &&= ok;
  console.log(`  ${ok ? 'PASS' : 'FAIL'} ${name}: expected ${e.expect}, got ${verdict}`);
}
console.log(allPass ? 'VECTOR PROOF: PASS' : 'VECTOR PROOF: FAIL');
process.exit(allPass ? 0 : 1);
