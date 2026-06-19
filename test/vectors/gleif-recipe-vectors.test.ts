/**
 * GLEIF vet recipe (gleif-cbp) conformance vectors — the deterministic cross-impl convergence set.
 *
 * Asserts this impl's pure classifiers (classifyFetchStatus + classifyRegistrationStatus) reproduce
 * every case in conformance/vet-drift/recipe-vectors.json. That file is the contract a second impl
 * (DNO, the SDK) checks ITS recipe against — same #146 pattern as the bundle/settlement drift checks,
 * but for the DACS-2 GLEIF public-authority verification recipe. If the impl and the vectors ever
 * disagree, one of them is wrong and this test fails loudly.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { classifyFetchStatus, classifyRegistrationStatus } from '../../src/lib/gleif-classify.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(path.join(HERE, '../../conformance/vet-drift/recipe-vectors.json'), 'utf8'),
) as {
  fetchCases: { id: string; responseStatus: number; hasErrors: boolean; expected: { decision: string | null } }[];
  statusCases: { id: string; registrationStatus: string | null; expected: { decision: string } }[];
};

test('gleif-cbp — fetch-level cases reproduce the conformance vectors', () => {
  for (const c of vectors.fetchCases) {
    const v = classifyFetchStatus(c.responseStatus, c.hasErrors);
    if (c.expected.decision === null) {
      assert.equal(v, null, `${c.id}: expected no fetch-level verdict (proceed)`);
    } else {
      assert.equal(v?.decision, c.expected.decision, `${c.id}: fetch decision`);
    }
  }
});

test('gleif-cbp — registration-status cases reproduce the conformance vectors (locked Mode-A, #146)', () => {
  for (const c of vectors.statusCases) {
    const v = classifyRegistrationStatus(c.registrationStatus ?? undefined);
    assert.equal(v.decision, c.expected.decision, `${c.id}: status decision`);
  }
});
