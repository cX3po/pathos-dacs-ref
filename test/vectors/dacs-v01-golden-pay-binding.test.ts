import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  checkPayBindings,
  listingFromVector,
} from '../../conformance/reproducers/dacs-v01-golden-pay-binding/pay-bindings.js';

const GOLDEN_SHA256 = '19e5ce5c93917204ac76c1e3337e6e995000f9df2d87622a62217af16a6831e4';
const vectorPath = fileURLToPath(new URL(
  '../../conformance/reproducers/dacs-v01-golden-pay-binding/vectors/dacs-v0.1-happy-path.json',
  import.meta.url,
));

test('DACS v0.1 happy-path golden Listing fails the directory payBindingsOk predicate', () => {
  const bytes = readFileSync(vectorPath);
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    GOLDEN_SHA256,
    'the pinned upstream golden vector changed',
  );

  const vector: unknown = JSON.parse(bytes.toString('utf8'));
  const listing = listingFromVector(vector);
  const result = checkPayBindings(listing);

  assert.equal(listing.listingId, 'lst-regen-0001');
  assert.deepEqual(result.acceptedRailIds, ['evm-erc20:8453:USDC']);
  assert.equal(result.payStepCount, 1, 'fixture must continue to exercise a pay-* step');
  assert.equal(
    result.ok,
    false,
    'golden Listing now binds every pay step; retire or update finding #243',
  );
  assert.deepEqual(result.unboundPaySteps, [{
    index: 3,
    step: { kind: 'pay-evm-erc20' },
    rail: null,
  }]);

  // Positive control: the mirrored predicate is not hard-coded to reject this
  // fixture. Binding the same step to the accepted rail makes it pass.
  const boundListing = structuredClone(listing);
  const pipeline = boundListing.pipeline as Record<string, unknown>[];
  pipeline[3] = {
    ...pipeline[3],
    parameters: { rail: 'evm-erc20:8453:USDC' },
  };
  const boundResult = checkPayBindings(boundListing);
  assert.equal(boundResult.ok, true);
  assert.deepEqual(boundResult.unboundPaySteps, []);
});
