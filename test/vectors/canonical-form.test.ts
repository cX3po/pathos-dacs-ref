/**
 * Guards vectors/canonical-form/canonical-form-vectors.json:
 *  - every accept vector re-derives to its committed expectedSha256 (no drift),
 *  - sameHashAs equivalence holds (NFC=NFD value, key-order, NFC=NFD key),
 *  - every reject vector is rejected by the canonicaliser.
 * If this fails, regenerate: npx tsx vectors/canonical-form/generate.mts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { jcsHashHex, jcsCanonical } from '../../src/jcs.js';
import { acceptCases, rejectCases } from '../../vectors/canonical-form/cases.js';

type AcceptVector = { id: string; expectedSha256: string; sameHashAs?: string };
const dir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(dir, '../../vectors/canonical-form/canonical-form-vectors.json'), 'utf8'),
) as { acceptVectors: AcceptVector[]; rejectVectors: { id: string }[] };
const byId = new Map<string, AcceptVector>(vectors.acceptVectors.map((v) => [v.id, v]));

test('accept vectors re-derive to the committed expectedSha256 (no drift)', () => {
  for (const c of acceptCases) {
    const v = byId.get(c.id);
    assert.ok(v, `committed vector missing for ${c.id} - regenerate`);
    const h = jcsHashHex(c.build());
    assert.match(h, /^[0-9a-f]{64}$/, `${c.id}: not a sha256 hex`);
    assert.equal(h, v!.expectedSha256, `${c.id}: hash drift vs committed vector`);
  }
});

test('sameHashAs cases hash identically (NFC=NFD value, key-order, NFC=NFD key)', () => {
  for (const c of acceptCases) {
    if (!c.sameHashAs) continue;
    const ref = acceptCases.find((x) => x.id === c.sameHashAs);
    assert.ok(ref, `sameHashAs ref missing: ${c.sameHashAs}`);
    assert.equal(jcsHashHex(c.build()), jcsHashHex(ref!.build()), `${c.id} must hash == ${c.sameHashAs}`);
  }
});

test('reject vectors are rejected by the canonicaliser', () => {
  for (const c of rejectCases) {
    assert.throws(() => jcsCanonical(c.build()), `${c.id} (${c.reason}) MUST be rejected`);
  }
});
