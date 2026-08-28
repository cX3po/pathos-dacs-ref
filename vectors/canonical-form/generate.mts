/**
 * Generate canonical-form-vectors.json from the shared cases (oracle: src/jcs.ts).
 * Run: npx tsx vectors/canonical-form/generate.mts
 * The committed JSON is guarded by test/vectors/canonical-form.test.ts (re-derives every hash).
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import { acceptCases, rejectCases } from './cases.js';

const toHex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');

const acceptVectors = acceptCases.map((c) => ({
  id: c.id,
  description: c.description,
  input: c.build(),
  // canonicalUtf8Hex is the PORTABLE ground truth: the exact UTF-8 bytes of the JCS canonical form,
  // hex-encoded. It is editor-proof (no NFC/NFD flattening can corrupt hex), so a consumer can verify
  // sha256(unhex(canonicalUtf8Hex)) === expectedSha256 AND that their canonicaliser reproduces these
  // bytes — WITHOUT trusting how their editor saved the literal-Unicode `input` field.
  canonicalUtf8Hex: toHex(jcsCanonical(c.build())),
  expectedSha256: jcsHashHex(c.build()),
  ...(c.sameHashAs ? { sameHashAs: c.sameHashAs } : {}),
}));

const rejectVectors = rejectCases.map((c) => ({ id: c.id, description: c.description, reason: c.reason }));

const out = {
  generatedBy: 'pathos-dacs-ref vectors/canonical-form/generate.mts',
  oracle: 'src/jcs.ts (RFC 8785 JCS + DACS section B.2 pre-pass: NFC on string VALUES only — member names are preserved as received and UTF-16 sorted per RFC 8785 — plus safe-int and surrogate-reject)',
  note: 'Accept vectors: sha256(JCS canonical form of `input`) MUST equal expectedSha256; canonicalUtf8Hex carries the exact canonical bytes (editor-proof portable form). Reject vectors carry no `input` (BigInt / lone surrogate / over-safe-int are not always faithfully JSON-serialisable) — construct via the cases.ts builders; a conforming canonicaliser MUST reject each for the stated reason.',
  acceptVectors,
  rejectVectors,
};

const dir = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(dir, 'canonical-form-vectors.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${acceptVectors.length} accept + ${rejectVectors.length} reject vectors`);
