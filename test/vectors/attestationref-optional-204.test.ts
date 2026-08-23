/**
 * DACS-Standard #204 regression guard — phaseSummary[].attestationRef is OPTIONAL.
 *
 * Steward ruling (randomblocker, 2026-07-01, spec/DACS-5-VERIFY.md §10.4.3, next@68d70df):
 *   "A validator MUST NOT reject a bundle solely because a phaseSummary entry omits
 *    attestationRef." The top-level vetRecords[] / settlementEvidence[] are the
 *    authoritative attestation set; the per-phase ref is an optional back-pointer that
 *    SHOULD be carried when a phase produced a durable anchored attestation.
 *
 * pathos-dacs-ref already conforms (type is `attestationRef?`, the structural validator
 * never inspects it, and the ref-walk validates only when present). This test LOCKS that
 * in: strip the per-phase attestationRef from a known-good bundle and assert the verifier
 * does not reject on that basis. If a future change made the field required, this fails.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { verifyBundleV1 } from '../../src/lib/verify-bundle-v1.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const load = () =>
  JSON.parse(
    readFileSync(path.join(HERE, 'dacs-x-fixtures', 'attestation-bundle-0004.json'), 'utf8'),
  ) as AttestationBundleV1;

test('#204 baseline — a bundle carrying per-phase attestationRef is accepted', () => {
  const b = load();
  const hadRef = (b.phaseSummary ?? []).some((p) => (p as { attestationRef?: unknown }).attestationRef);
  assert.equal(hadRef, true, 'fixture sanity: baseline carries at least one phase attestationRef');
  const v = verifyBundleV1(b, { requireSignatures: false });
  assert.equal(v.decision, 'accept');
});

test('#204 — MUST NOT reject solely for omitting phaseSummary[].attestationRef (steward ruling)', () => {
  const b = load();
  for (const p of (b.phaseSummary ?? []) as Array<{ attestationRef?: unknown }>) {
    delete p.attestationRef;
  }
  const v = verifyBundleV1(b, { requireSignatures: false });
  assert.notEqual(v.decision, 'reject', 'omitting per-phase attestationRef must not cause rejection (#204)');
  assert.equal(v.decision, 'accept', 'an otherwise-valid bundle still accepts without the optional per-phase ref');
});
