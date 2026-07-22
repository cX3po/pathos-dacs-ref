/**
 * PUBLISHED conformance-vector test for the "unsigned-field / loosely-typed member laundering"
 * DEFECT CLASS (DACS-5 §10.4). This is the static, published, cross-runnable counterpart of the
 * anchoredByRole laundering regression suite (bundle-binding-anchoredbyrole-laundering.test.ts) and
 * the stateful fuzzer's ALTER_UNSIGNED transition (bb-stateful-fuzzer.mts) — generalised across the
 * WHOLE class (anchoredByRole + boolean-for-int + container-for-scalar) as a drop-in vector set.
 *
 * THE CLASS: a receipt/bundle member a resolution decision depends on is either OUTSIDE the signed
 * hash scope, or too LOOSELY TYPED, so a mutation that keeps the signature valid (or confuses the
 * type) changes the verdict — laundering a fail/indeterminate into a present (or hiding a divergence).
 *
 * This suite:
 *   1. runs every REACHABLE vector through OUR resolver and asserts it AGREEs with the published
 *      expected disposition (pristine + mutated-safe + control);
 *   2. asserts the invariant directly — no MUTATED vector resolves present (fail-closed);
 *   3. MUTATION-PINS the container-for-scalar guard: reverting the phaseSummaryDiverges canonical-key
 *      normalisation (simulated by feeding raw-reference-keyed comparison) makes the mutated container
 *      vector wrongly resolve present -> the pin has teeth (guard-delete => RED).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import {
  resolveBundleBinding,
  resolveFaultBundlePair,
  resolveMixedVersionPair,
  resolveFaultBundlePointer,
  type BundleBindingRequest,
  type BundleBindingResolution,
  type BundleBindingRole,
} from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...m));

type Json = Record<string, any>;
type Corpus = { set: string; publicKeys: Record<string, string>; vectors: Json[]; hash: string; count: number };

const corpus = JSON.parse(readFileSync(
  new URL('../../conformance/cross-run-corpus/dacs248/unsigned-field-laundering-v0.1.json', import.meta.url),
  'utf8',
)) as Corpus;

function resolveVector(vector: Json): BundleBindingResolution {
  switch (vector.family) {
    case 'pair':
      return resolveFaultBundlePair({ publicKeys: corpus.publicKeys, copies: vector.copies });
    case 'mixed':
      return resolveMixedVersionPair({ publicKeys: corpus.publicKeys, copies: vector.copies });
    case 'pointer':
      return resolveFaultBundlePointer({
        publicKeys: corpus.publicKeys, pointer: vector.pointer, dereferenced: vector.dereferenced, binding: vector.binding,
      });
    case 'direct': {
      const anchored = vector.anchored ?? {};
      const request: BundleBindingRequest = { ...vector.request, publicKeys: corpus.publicKeys, budget: vector.budget };
      return resolveBundleBinding(request, vector.bindings ?? [], (na: string) => anchored[na]);
    }
    default:
      throw new Error(`unknown family ${vector.family}`);
  }
}

const reachable = corpus.vectors.filter((v) => v.reachable);

test('set integrity: hash == sha256(jcs(vectors)) and count matches', async () => {
  const { sha256 } = await import('@noble/hashes/sha2');
  const { jcsCanonical } = await import('../../src/jcs.js');
  const recomputed = Buffer.from(sha256(jcsCanonical(corpus.vectors))).toString('hex');
  assert.equal(recomputed, corpus.hash, 'set hash must equal sha256(jcsCanonical(vectors))');
  assert.equal(corpus.count, corpus.vectors.length, 'count must equal vector length');
});

test('every REACHABLE vector AGREEs with its published expected disposition', () => {
  assert.ok(reachable.length >= 12, `expected >=12 reachable vectors, got ${reachable.length}`);
  for (const v of reachable) {
    const res = resolveVector(v);
    assert.equal(
      res.disposition, v.expected,
      `DIVERGE on ${v.name} (${v.field}/${v.triple}): expected ${v.expected}, our resolver ${res.disposition} — ${res.detail}`,
    );
  }
});

test('INVARIANT: no MUTATED (laundering-attempt) vector resolves present', () => {
  const mutated = reachable.filter((v) => v.triple === 'mutated');
  assert.ok(mutated.length >= 4, `expected >=4 reachable mutated vectors, got ${mutated.length}`);
  for (const v of mutated) {
    const res = resolveVector(v);
    assert.notEqual(
      res.disposition, 'present',
      `LAUNDERING: mutated vector ${v.name} (${v.field}) resolved present — an unsigned/loose-type mutation swung the verdict (${res.detail})`,
    );
  }
});

test('CONTROL vectors prove non-tautology: each control moves the disposition as designed', () => {
  const controls = reachable.filter((v) => v.triple === 'control');
  assert.ok(controls.length >= 3, `expected >=3 control vectors, got ${controls.length}`);
  for (const v of controls) {
    const res = resolveVector(v);
    assert.equal(res.disposition, v.expected, `control ${v.name} did not resolve ${v.expected}: ${res.detail}`);
  }
  // At least one control legitimately resolves present and at least one legitimately fails/indeterminate,
  // proving the set is not "everything fails" or "everything passes".
  const dispositions = new Set(controls.map((v) => v.expected));
  assert.ok(dispositions.has('present'), 'at least one control must legitimately resolve present');
  assert.ok(dispositions.size >= 2, 'controls must span more than one disposition (non-tautology)');
});

// -------------------------------------------------------------------------------------------------
// MUTATION-PIN with TEETH: the container-for-scalar guard is phaseSummaryDiverges' canonical-key
// normalisation. We cannot delete a private function from here, so we reproduce the PRE-FIX behaviour
// (a Map keyed by the RAW index value, reference-compared for containers) and prove that under the
// reverted guard the mutated container vector's phase divergence goes UNDETECTED -> it would resolve
// present. This demonstrates the guard is load-bearing: revert it -> RED.
// -------------------------------------------------------------------------------------------------
/** PRE-FIX phaseSummaryDiverges: raw-value Map key (container indices compare by reference). */
function phaseSummaryDivergesRawKey(a: Json, b: Json): boolean {
  const pa = Array.isArray(a.phaseSummary) ? a.phaseSummary : [];
  const pb = Array.isArray(b.phaseSummary) ? b.phaseSummary : [];
  const byIndex = new Map<unknown, Json>();
  for (const p of pa) if (p && typeof p === 'object') byIndex.set(p.index, p);
  for (const p of pb) {
    if (!p || typeof p !== 'object') continue;
    const other = byIndex.get(p.index);
    if (other && (other.kind !== p.kind || other.outcome !== p.outcome)) return true;
  }
  return false;
}
/** FIXED phaseSummaryDiverges: canonical string key (container indices compare by value). */
function phaseSummaryDivergesCanonicalKey(a: Json, b: Json): boolean {
  const key = (index: unknown): string => {
    try {
      return 'j:' + Buffer.from(JSON.stringify(index)).toString('base64'); // JSON.stringify is a stand-in for JCS on plain arrays/scalars
    } catch {
      return 's:' + String(index);
    }
  };
  const pa = Array.isArray(a.phaseSummary) ? a.phaseSummary : [];
  const pb = Array.isArray(b.phaseSummary) ? b.phaseSummary : [];
  const byIndex = new Map<string, Json>();
  for (const p of pa) if (p && typeof p === 'object') byIndex.set(key(p.index), p);
  for (const p of pb) {
    if (!p || typeof p !== 'object') continue;
    const other = byIndex.get(key(p.index));
    if (other && (other.kind !== p.kind || other.outcome !== p.outcome)) return true;
  }
  return false;
}

test('MUTATION-PIN (teeth): reverting the container-index canonical-key guard fails to detect the container divergence', () => {
  const v = corpus.vectors.find((c) => c.name === 'phaseIndex-container-mutated-launder-attempt');
  assert.ok(v, 'missing phaseIndex-container-mutated-launder-attempt vector');
  const a = v!.copies.seller;
  const b = v!.copies.buyer;
  // Sanity: the two copies carry a CONTAINER index and a genuine phase-outcome divergence at it.
  assert.deepEqual(a.phaseSummary[0].index, [0], 'copy a index must be the container [0]');
  assert.deepEqual(b.phaseSummary[0].index, [0], 'copy b index must be the container [0]');
  assert.notEqual(a.phaseSummary[0].outcome, b.phaseSummary[0].outcome, 'the phase outcomes must genuinely diverge');

  // PRE-FIX (guard reverted): raw-value Map key -> reference compare -> divergence NOT detected (RED
  // condition: the resolver would wrongly converge -> present).
  assert.equal(
    phaseSummaryDivergesRawKey(a, b), false,
    'PRE-FIX guard must FAIL to detect the container-index divergence (this is the vulnerability the pin guards)',
  );
  // POST-FIX (guard present): canonical key -> by-value compare -> divergence DETECTED (fail-closed).
  assert.equal(
    phaseSummaryDivergesCanonicalKey(a, b), true,
    'POST-FIX guard must DETECT the container-index divergence',
  );

  // End-to-end proof the LIVE resolver has the fix: the vector resolves fail (not the laundered present).
  const live = resolveVector(v!);
  assert.equal(
    live.disposition, 'fail',
    `the live resolver must reject the container-index laundering (fail), got ${live.disposition}: ${live.detail}`,
  );
});
