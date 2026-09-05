/**
 * commerce/ artifacts — the purchasing and delivery contract for the four PATH-OS services.
 * Pins: SKU ids agree across offers, manifest and openapi; every amountOs equals demToOs(amountDem);
 * rehearsal mode with mainnet disabled everywhere; the verify SKU price equals the endpoint default;
 * JCS hashes are pinned so a price or term change is a deliberate diff.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { demToOs } from '../../src/adapters/dacs/pay-dem.js';
import { jcsHashHex } from '../../src/jcs.js';
import { readConfig } from '../../src/live/verify-endpoint.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', 'commerce');
const load = (name: string) => JSON.parse(readFileSync(join(root, name), 'utf8'));
const offers = load('offers.json');
const manifest = load('service-manifest.json');
const openapi = load('openapi.json');
const listing = load('discovery-registration.json');

const SKUS = ['verify-bundle', 'interop-run', 'verifier-package', 'pr-review'];

test('sku ids agree across offers, manifest and openapi, exactly once each', () => {
  assert.deepEqual(offers.skus.map((s: { id: string }) => s.id), SKUS);
  assert.deepEqual(manifest.services.map((s: { id: string }) => s.id), SKUS);
  assert.deepEqual(Object.keys(openapi['x-skus']), SKUS);
  for (const [i, id] of SKUS.entries()) {
    assert.equal(openapi['x-skus'][id].pricing, `commerce/offers.json#/skus/${i}`);
    assert.ok(manifest.proofOfDelivery[id], `proof of delivery for ${id}`);
  }
});

test('every amountOs is demToOs(amountDem), an integer string greater than zero', () => {
  for (const sku of offers.skus) {
    const os = demToOs(sku.price.amountDem);
    assert.equal(sku.price.amountOs, os.toString(), sku.id);
    assert.match(sku.price.amountOs, /^[1-9][0-9]*$/);
    assert.ok(os > 0n);
  }
  assert.equal(offers.currency.fractionalDigits, 9);
  assert.equal(demToOs('1').toString(), '1000000000');
});

test('rehearsal on testnet, mainnet disabled, nothing signed', () => {
  assert.equal(offers.network.id, 'demos:testnet');
  assert.equal(offers.network.mode, 'rehearsal');
  assert.equal(offers.network.mainnet.enabled, false);
  assert.equal(manifest.network.mode, 'rehearsal');
  assert.equal(manifest.network.mainnet.enabled, false);
  for (const service of manifest.services) {
    if (service.kind !== 'http') assert.match(service.order, /manualOrders/);
  }
  assert.deepEqual(offers.manualOrders.applies, ['interop-run', 'verifier-package', 'pr-review']);
  assert.equal(openapi['x-network'].mode, 'rehearsal');
  assert.equal(openapi['x-network'].mainnet.enabled, false);
  assert.equal(listing['x-pathos'].availability['demos:testnet'], true);
  assert.equal(listing['x-pathos'].availability['demos:mainnet'], false);
  assert.equal(listing.signature, 'unsigned-draft');
  assert.equal(offers.provider.identity.identifier, 'unset-until-deploy');
  assert.equal(manifest.provider.signingKey.identifier, 'unset-until-deploy');
  for (const service of manifest.services) {
    if (service.kind === 'http') assert.equal(service.endpoint.baseUrl, 'unset-until-deploy');
  }
});

test('the verify SKU price equals the verify endpoint default and the listing price', () => {
  const verify = offers.skus.find((s: { id: string }) => s.id === 'verify-bundle');
  const config = readConfig({ VERIFY_RECIPIENT: '0x' + 'a'.repeat(64) });
  assert.ok('priceDem' in config, JSON.stringify(config));
  assert.equal(verify.price.amountDem, (config as { priceDem: string }).priceDem);
  assert.equal(verify.price.amountOs, (config as { amountOs: string }).amountOs);
  assert.equal(listing.price.amount, verify.price.amountDem);
  assert.equal(listing.price.currency, 'DEM');
  assert.equal(verify.limits.maxBodyBytes, 1048576);
});

test('openapi surface matches the endpoint contract', () => {
  assert.equal(openapi.openapi, '3.1.0');
  assert.deepEqual(Object.keys(openapi.paths).sort(), ['/healthz', '/schemas/verify-request.json', '/schemas/verify-verdict.json', '/verify']);
  const verify = openapi.paths['/verify'].post;
  assert.deepEqual(Object.keys(verify.responses).sort(), ['200', '400', '402', '413', '503']);
  assert.deepEqual(openapi.components.schemas.PaymentRequirement.properties.reason.enum,
    ['missing-proof', 'malformed-proof', 'unverifiable', 'mismatch', 'replayed']);
  assert.deepEqual(openapi.components.schemas.Receipt.required, ['txHash', 'from', 'amountOs', 'resourceId']);
  assert.deepEqual(openapi.components.schemas.VerifyResponse.required, ['apiVersion', 'bundleKind', 'exitCode', 'verdict', 'receipt']);
  assert.match(verify.requestBody.content['application/json'].schema.$ref, /^https:\/\/raw\.githubusercontent\.com\//);
});

test('artifact hashes are pinned (a price or term change is a deliberate diff)', () => {
  const pinned: Record<string, string> = {
    'offers.json': 'edf4f40c05863a056fa2f087041b4654d77e71af164a502c24c3cf2b717f2e3b',
    'service-manifest.json': 'bf0ea1b0cd479e9ccd5493ad9c638c4fbea0d8f834a8be69a1bc3d7a9361a347',
    'openapi.json': 'e161f7988ddd678455e418439bea82c4589fbf2ba6e71275337ca8006f207fab',
    'discovery-registration.json': 'd619fcd796729fa925d688460a9df60e6218e24a3385e5315ceb360c762e8e6d',
  };
  for (const [name, hash] of Object.entries(pinned)) {
    assert.equal(jcsHashHex(load(name)), hash, name);
  }
});
