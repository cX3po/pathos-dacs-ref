import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { checkPayBindings, listingFromVector } from './pay-bindings.js';

const vectorPath = fileURLToPath(
  new URL('./vectors/dacs-v0.1-happy-path.json', import.meta.url),
);
const vector: unknown = JSON.parse(readFileSync(vectorPath, 'utf8'));
const listing = listingFromVector(vector);
const result = checkPayBindings(listing);

assert.equal(listing.listingId, 'lst-regen-0001', 'unexpected Listing fixture');
assert.ok(result.payStepCount > 0, 'fixture must exercise at least one pay-* step');
assert.equal(
  result.ok,
  false,
  'the golden Listing now satisfies payBindingsOk; this reproducer must be reviewed',
);
assert.ok(result.unboundPaySteps.length > 0, 'expected an unbound pay-* step');

console.log('DACS directory payBindingsOk: FAIL (expected by this reproducer)');
console.log(`Listing: ${String(listing.listingId)}`);
console.log(`Accepted rail IDs: ${JSON.stringify(result.acceptedRailIds)}`);
for (const unbound of result.unboundPaySteps) {
  console.log(`Unbound pay step at pipeline[${unbound.index}]:`);
  console.log(JSON.stringify(unbound.step, null, 2));
}
