/**
 * #248 authority-laundering regression suite (Codex adversarial review, 2026-07).
 *
 * VULNERABILITY CLASS: `anchoredByRole` is EXCLUDED from the signed scope of a
 * FaultAttestationBundle / legacy AttestationBundle copy (see bundle-binding-v1.ts
 * `bundleScope` — it strips `signatures` AND `anchoredByRole`; R5-1 exclusion, also
 * documented in bundle-signed-scope-v1.ts). Yet `impliedFaultSet` derives a legacy
 * copy's implied absolute-fault SET from (outcome, anchoredByRole), and
 * `faultedPartyPermitted` validates a FAB's permissible set against anchoredByRole.
 * An attacker can therefore flip `anchoredByRole` WITHOUT invalidating the signature
 * and launder a `fail` (contradiction) into a `present` (agreement).
 *
 * INVARIANT ENFORCED BY THE FIX: no mutation of the unsigned `anchoredByRole` field
 * may turn a `fail` disposition into `present`, in ANY of the 3 new #248 families.
 * The fix re-anchors the unsigned field to a TRUSTED signal — the role-keyed anchor
 * address the copy was published under (the map key). This mirrors the §10.4.2/§248
 * anchor-address ↔ anchoredByRole cross-check already enforced in verifyV1TwoSided
 * (verify-bundle-v1.ts FIX 1): the copy fetched from role X's address MUST declare
 * anchoredByRole === X. A copy whose anchoredByRole disagrees with its anchor-address
 * key is forged/mislabeled → fail-closed.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  resolveMixedVersionPair,
  resolveFaultBundlePair,
} from '../../src/lib/bundle-binding-v1.js';

type JsonObject = Record<string, any>;

function loadCorpus(file: string): JsonObject {
  return JSON.parse(readFileSync(
    new URL(`../../conformance/cross-run-corpus/dacs248/${file}`, import.meta.url),
    'utf8',
  ));
}

function vector(corpus: JsonObject, name: string): JsonObject {
  const v = corpus.vectors.find((c: JsonObject) => c.name === name);
  assert.ok(v, `missing corpus vector ${name}`);
  return structuredClone(v);
}

const mixed = loadCorpus('mixed-version-reconciliation-v0.3.json');
const pair = loadCorpus('fault-bundle-perspective-pair-v0.3.json');

const ROLES = ['buyer', 'seller', 'orchestrator'] as const;
function otherRoles(role: string): string[] {
  return ROLES.filter((r) => r !== role);
}

/**
 * PRIMARY EXPLOIT — the published `mixed-implied-fault-contradiction` vector, mutated.
 *
 * FAB(seller) faultedParty=seller → set {seller}; legacy(buyer) aborted-by-self,
 * anchoredByRole=buyer → set {buyer}. {buyer} ∩ {seller} = ∅ → correct `fail`.
 * MUTATION: flip ONLY the legacy copy's anchoredByRole buyer→seller (signature is
 * UNTOUCHED and stays valid because anchoredByRole is unsigned). Pre-fix the resolver
 * derives {seller}, {seller} ∩ {seller} ≠ ∅ → WRONGLY `present` (authority laundering).
 * Post-fix: the legacy copy's anchoredByRole (seller) no longer matches its anchor key
 * (buyer) → fail-closed.
 */
test('EXPLOIT: flipping unsigned anchoredByRole on the legacy copy must not launder fail→present', () => {
  const v = vector(mixed, 'mixed-implied-fault-contradiction');

  // Sanity: the pristine vector resolves fail (the contradiction stands).
  const pristine = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: v.copies });
  assert.equal(pristine.disposition, 'fail', 'pristine contradiction vector must resolve fail');

  // MUTATION: flip ONLY the legacy buyer copy's anchoredByRole. Signature untouched.
  const mutated = structuredClone(v);
  assert.equal(mutated.copies.buyer.anchoredByRole, 'buyer');
  assert.ok(!('faultBundleVersion' in mutated.copies.buyer), 'buyer copy is the legacy one');
  mutated.copies.buyer.anchoredByRole = 'seller';

  const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: mutated.copies });

  // The invariant: an unsigned-field flip may NEVER turn fail into present.
  assert.notEqual(
    result.disposition, 'present',
    `AUTHORITY LAUNDERING: flipping unsigned anchoredByRole laundered fail→present (${result.detail})`,
  );
  assert.ok(
    result.disposition === 'fail' || result.disposition === 'indeterminate',
    `expected fail/indeterminate after anchoredByRole flip, got ${result.disposition}`,
  );
});

/**
 * SIBLING CLASS 1 — mixed-version family: every `fail` vector that carries a legacy
 * copy, mutate its anchoredByRole to every other role. No flip may produce `present`.
 */
test('SIBLING: no anchoredByRole flip on any legacy copy launders fail→present (mixed-version family)', () => {
  for (const v of mixed.vectors as JsonObject[]) {
    if (v.expected !== 'fail') continue;
    for (const [role, copy] of Object.entries(v.copies as JsonObject) as [string, JsonObject][]) {
      // Mutate BOTH legacy and FAB copies — anchoredByRole is unsigned on both.
      for (const flipped of otherRoles(copy.anchoredByRole ?? role)) {
        const mutated = structuredClone(v);
        mutated.copies[role].anchoredByRole = flipped;
        const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: mutated.copies });
        assert.notEqual(
          result.disposition, 'present',
          `LAUNDERING in ${v.name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
        );
      }
    }
  }
});

/**
 * SIBLING CLASS 2 — perspective-pair family: same mutation on every FAB copy of every
 * `fail` vector. No flip may produce `present`.
 */
test('SIBLING: no anchoredByRole flip on any copy launders fail→present (perspective-pair family)', () => {
  for (const v of pair.vectors as JsonObject[]) {
    if (v.expected !== 'fail') continue;
    for (const [role, copy] of Object.entries(v.copies as JsonObject) as [string, JsonObject][]) {
      for (const flipped of otherRoles(copy.anchoredByRole ?? role)) {
        const mutated = structuredClone(v);
        mutated.copies[role].anchoredByRole = flipped;
        const result = resolveFaultBundlePair({ publicKeys: pair.publicKeys, copies: mutated.copies });
        assert.notEqual(
          result.disposition, 'present',
          `LAUNDERING in ${v.name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
        );
      }
    }
  }
});

/**
 * SIBLING CLASS 3 — the perspective-flip control and the orchestrator legacy family:
 * flip anchoredByRole on the legacy-legacy genuine-divergence vector and the mixed
 * orchestrator-divergent vector individually. Belt-and-suspenders over the sweeps above.
 */
test('SIBLING: legacy-legacy divergence + orchestrator divergence resist anchoredByRole laundering', () => {
  const targets: Array<[JsonObject, string, string]> = [
    [mixed, 'legacy-legacy-genuine-divergence', 'buyer'],
    [mixed, 'legacy-legacy-genuine-divergence', 'seller'],
    [mixed, 'mixed-orchestrator-divergent', 'buyer'],
    [mixed, 'mixed-orchestrator-divergent', 'seller'],
  ];
  for (const [corpus, name, role] of targets) {
    const v = vector(corpus, name);
    for (const flipped of otherRoles(v.copies[role].anchoredByRole ?? role)) {
      const mutated = structuredClone(v);
      mutated.copies[role].anchoredByRole = flipped;
      const result = resolveMixedVersionPair({ publicKeys: corpus.publicKeys, copies: mutated.copies });
      assert.notEqual(
        result.disposition, 'present',
        `LAUNDERING in ${name}: flipping ${role}.anchoredByRole → ${flipped} turned fail→present (${result.detail})`,
      );
    }
  }
});

/**
 * REGRESSION — the fix must NOT break legitimate vectors: every published `pass`
 * vector (whose anchoredByRole equals its anchor-address key) must still resolve
 * present with the anchor-key binding enforced.
 */
test('REGRESSION: legitimate pass vectors still resolve present with anchor-key binding enforced', () => {
  for (const v of mixed.vectors as JsonObject[]) {
    if (v.expected !== 'pass') continue;
    const result = resolveMixedVersionPair({ publicKeys: mixed.publicKeys, copies: v.copies });
    assert.equal(result.disposition, 'present', `${v.name} regressed: ${result.detail}`);
  }
  for (const v of pair.vectors as JsonObject[]) {
    if (v.expected !== 'pass') continue;
    const result = resolveFaultBundlePair({ publicKeys: pair.publicKeys, copies: v.copies });
    assert.equal(result.disposition, 'present', `${v.name} regressed: ${result.detail}`);
  }
});
