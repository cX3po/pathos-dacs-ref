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

// Regression (Codex 2026-07-22): the CROSS-RUN's resolveVector default branch must THROW on an
// unknown/misspelled family, so the cross-run scores it ERROR (fails --strict) rather than laundering
// a silent 'fail' disposition into an AGREE against a vector whose expected==='fail'. Guards the exact
// fail-open Codex reproduced with `family:"diretc", expected:"fail"`.
test('TOOLING GUARD: unknown vector family THROWS (no silent fail → no --strict AGREE laundering)', async () => {
  // NodeNext maps the `.mjs` specifier to the `.mts` source (same convention as the `.js`-for-`.ts`
  // imports above); a bare `.mts` specifier is a tsc error (TS5097).
  const mod = await import('../../conformance/cross-run-corpus/unsigned-field-cross-run.mjs');
  const bogus = { name: 'typo-family', family: 'diretc', field: 'x', triple: 'mutated', expected: 'fail', reachable: true };
  const emptyCorpus = { set: corpus.set, publicKeys: corpus.publicKeys, vectors: [] };
  assert.throws(
    () => mod.resolveVector(emptyCorpus, bogus),
    /unknown vector family/,
    'an unknown family must throw so the cross-run scores it ERROR (fails --strict), never a silent fail scored AGREE',
  );
});

// Regression (Codex 2026-07-22, finding D): malformed scoring METADATA must not silently drop a vector
// out of strict scoring. A typo'd `reachble: true` reads as reachable===undefined (falsy) → REF-ONLY →
// ignored by --strict, so a valid-family vector resolving WRONG could still pass. metaError() flags it →
// the cross-run scores it ERROR → --strict fails. Also assert the committed set is all-valid.
test('TOOLING GUARD: malformed vector metadata is rejected (no silent drop from --strict scoring)', async () => {
  const mod = await import('../../conformance/cross-run-corpus/unsigned-field-cross-run.mjs');
  // every committed vector must be metadata-valid (else the set itself would carry a silent-drop hole)
  for (const v of corpus.vectors) {
    assert.equal(mod.metaError(v), null, `committed vector ${v.name} must have valid metadata`);
  }
  // a misspelled `reachable` key (the exact finding-D shape) must be flagged, not silently REF-ONLY'd
  const typoReachable = { name: 'typo-reachable', family: 'direct', field: 'x', triple: 'mutated', expected: 'fail', reachble: true };
  assert.match(mod.metaError(typoReachable) ?? '', /unknown key "reachble"/, 'a misspelled reachable must be flagged as ERROR (unknown-key guard)');
  // and an OMITTED reachable (no typo, just absent) is caught by the boolean check
  assert.match(mod.metaError({ name: 'no-reachable', family: 'direct', field: 'x', triple: 'mutated', expected: 'fail' }) ?? '', /"reachable" must be boolean/, 'an absent reachable must be flagged');
  // other malformed enums are flagged too (family / expected / triple / baseline)
  assert.match(mod.metaError({ name: 'bad-fam', family: 'diretc', reachable: true, expected: 'fail' }) ?? '', /family/, 'bad family flagged');
  assert.match(mod.metaError({ name: 'bad-exp', family: 'direct', reachable: true, expected: 'presnt' }) ?? '', /expected/, 'bad expected flagged');
  // finding-D RESIDUAL (Codex): a reference-only vector whose pathosBaseline is MISSPELLED (unknown key)
  // or MISSING must not silently drop from strict scoring — both are flagged.
  assert.match(
    mod.metaError({ name: 'typo-baseline', family: 'direct', field: 'x', triple: 'mutated', expected: 'fail', reachable: false, pathosBasline: 'indeterminate' }) ?? '',
    /unknown key "pathosBasline"/, 'a misspelled pathosBaseline (unknown key) must be flagged');
  assert.match(
    mod.metaError({ name: 'missing-baseline', family: 'direct', field: 'x', triple: 'mutated', expected: 'fail', reachable: false }) ?? '',
    /reference-only vector requires a valid "pathosBaseline"/, 'a ref-only vector with no baseline must be flagged');
  // and the unknown-key guard closes the whole misspelling class (e.g. a typo'd field key)
  assert.match(
    mod.metaError({ name: 'typo-field', family: 'direct', reachable: true, expected: 'fail', feild: 'x' }) ?? '',
    /unknown key "feild"/, 'any unknown/misspelled key is flagged');
});
