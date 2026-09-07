import test from 'node:test';
import assert from 'node:assert/strict';
import { isLogicalLocator, isNativeLocator, ownerAddressOfClaim, sdkProgramName } from '../../src/lib/locator-form.js';

test('locator forms: native vs logical, SDK-form names, owner behind a claim', () => {
  assert.equal(isNativeLocator('stor-' + 'a'.repeat(40)), true);
  assert.equal(isNativeLocator('stor-' + 'a'.repeat(64)), true);
  assert.equal(isNativeLocator('dacs4:payment:job:pay-dem:2'), false);
  assert.equal(isLogicalLocator('dacs4:payment:job:pay-dem:2'), true);
  assert.equal(isLogicalLocator('pathos:identity-bundle:job:buyer'), true);
  assert.equal(isLogicalLocator('stor-' + 'a'.repeat(40)), false);
  assert.equal(isNativeLocator(undefined), false);
  assert.equal(isNativeLocator(''), false);
  assert.equal(sdkProgramName('dacs4:payment:job:pay-dem:2'), 'dacs4%3Apayment%3Ajob%3Apay-dem%3A2');
  assert.equal(sdkProgramName('dacs4%3Adeliverable%3Ajob'), 'dacs4%3Adeliverable%3Ajob');
  assert.equal(sdkProgramName('stor-' + 'a'.repeat(40)), 'stor-' + 'a'.repeat(40));
  const hex = 'f'.repeat(64);
  assert.equal(ownerAddressOfClaim(`did:demos:agent:${hex}`), `0x${hex}`);
  assert.equal(ownerAddressOfClaim(`cci:${hex.toUpperCase()}`), `0x${hex}`);
  assert.equal(ownerAddressOfClaim(`cci:0x${hex}`), `0x${hex}`);
  assert.equal(ownerAddressOfClaim('did:web:example.org'), null);
  assert.equal(ownerAddressOfClaim({ scheme: 'cci', identifier: hex }), null);
});
