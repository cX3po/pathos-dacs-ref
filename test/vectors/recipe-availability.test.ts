/**
 * DACS-2 §7.4.5 recipe.availability preflight (RAV) test vectors
 *
 * Locks in:
 *   - 'available' | 'mocked' | 'degraded' → proceed (no error decision)
 *   - 'disabled' | 'failed'               → MUST refuse (proceed=false, decision='error')
 *   - ABSENT availability                 → fail-safe to 'mocked', proceed=true
 *   - unrecognized value                  → fail-safe to refusal (proceed=false, decision='error')
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  RecipeAvailability,
  preflightRecipe,
  type RecipeAvailabilityDescriptor,
} from '../../src/lib/recipe-availability.js';

test('available → proceeds, no error decision', () => {
  const r = preflightRecipe({ recipe: 'evm-rpc@0.1', availability: RecipeAvailability.Available });
  assert.equal(r.proceed, true);
  assert.equal(r.decision, undefined);
  assert.equal(r.effectiveAvailability, RecipeAvailability.Available);
});

test('mocked → proceeds (runnable but not authoritative)', () => {
  const r = preflightRecipe({ recipe: 'gleif@0.1', availability: RecipeAvailability.Mocked });
  assert.equal(r.proceed, true);
  assert.equal(r.decision, undefined);
  assert.equal(r.effectiveAvailability, RecipeAvailability.Mocked);
});

test('degraded → proceeds (caller should downgrade confidence)', () => {
  const r = preflightRecipe({ recipe: 'evm-rpc@0.1', availability: RecipeAvailability.Degraded });
  assert.equal(r.proceed, true);
  assert.equal(r.decision, undefined);
  assert.equal(r.effectiveAvailability, RecipeAvailability.Degraded);
});

test('disabled → MUST refuse with decision=error', () => {
  const r = preflightRecipe({ recipe: 'evm-rpc@0.1', availability: RecipeAvailability.Disabled });
  assert.equal(r.proceed, false);
  assert.equal(r.decision, 'error');
  assert.equal(r.effectiveAvailability, RecipeAvailability.Disabled);
  assert.match(r.reason, /MUST refuse/);
});

test('failed → MUST refuse with decision=error', () => {
  const r = preflightRecipe({ recipe: 'gleif@0.1', availability: RecipeAvailability.Failed });
  assert.equal(r.proceed, false);
  assert.equal(r.decision, 'error');
  assert.equal(r.effectiveAvailability, RecipeAvailability.Failed);
  assert.match(r.reason, /MUST refuse/);
});

test('absent availability → fail-safe to mocked, proceeds', () => {
  // No availability field at all (the now-normative §7.4.5 field omitted).
  const r = preflightRecipe({ recipe: 'legacy-recipe@0.1' });
  assert.equal(r.proceed, true);
  assert.equal(r.decision, undefined);
  // Fail-safe: absent is resolved to 'mocked', NOT 'available'.
  assert.equal(r.effectiveAvailability, RecipeAvailability.Mocked);
  assert.match(r.reason, /absent/);
  assert.match(r.reason, /fail-safe/);
});

test('unrecognized availability → fail-safe to refusal (decision=error)', () => {
  // A value outside the §7.4.5 enum must NOT be silently assumed safe.
  const r = preflightRecipe({
    recipe: 'future-recipe@0.1',
    // Cast through the descriptor type to exercise the runtime guard for an
    // unknown wire value (e.g. a recipe authored against a newer spec rev).
    availability: 'experimental' as unknown as RecipeAvailabilityDescriptor['availability'],
  });
  assert.equal(r.proceed, false);
  assert.equal(r.decision, 'error');
  assert.match(r.reason, /unrecognized availability/);
});
