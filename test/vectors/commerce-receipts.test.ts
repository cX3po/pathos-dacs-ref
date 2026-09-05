/**
 * Delivery receipts — one signed shape for the four SKUs (commerce/receipt.schema.json, src/lib/delivery-receipt.ts).
 * Pins: every example verifies; the checked-in examples equal a fresh deterministic generation; a one-byte tamper
 * anywhere fails; each required field is enforced; the verify-bundle example carries the endpoint receipt fields;
 * the idempotent-retry guarantee is cited from the endpoint tests, not re-run on chain.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PATHOS_EXTENSION_SEPARATORS } from '../../src/domain-sep.js';
import {
  DELIVERY_SKUS,
  checkReceiptShape,
  isRfc3339DateTime,
  receiptCommitmentHex,
  verifyDeliveryReceipt,
  type DeliveryReceipt,
} from '../../src/lib/delivery-receipt.js';
import { EXAMPLE_SELLER_PUBKEY_HEX, exampleReceipts } from '../../commerce/examples/generate-receipts.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const examplesDir = join(here, '..', '..', 'commerce', 'examples');
const schema = JSON.parse(readFileSync(join(here, '..', '..', 'commerce', 'receipt.schema.json'), 'utf8'));
const loadExample = (sku: string): DeliveryReceipt =>
  JSON.parse(readFileSync(join(examplesDir, `${sku}.receipt.json`), 'utf8'));

test('separator is registered and the schema names the same required fields the verifier enforces', () => {
  assert.equal(PATHOS_EXTENSION_SEPARATORS.DELIVERY_RECEIPT, 'pathos-delivery-receipt:v1:');
  assert.deepEqual(schema.required, ['v', 'sku', 'quoteRef', 'buyer', 'seller', 'network', 'payment', 'idempotencyKey', 'inputHash', 'implementationVersion', 'resultHash', 'issuedAt', 'retrieval', 'signature']);
  assert.deepEqual(schema.properties.sku.enum, [...DELIVERY_SKUS]);
});

test('the four checked-in examples verify and equal a fresh deterministic generation', () => {
  const fresh = exampleReceipts();
  assert.equal(fresh.length, 4);
  for (const receipt of fresh) {
    const file = join(examplesDir, `${receipt.sku}.receipt.json`);
    assert.ok(existsSync(file), `${file} is checked in (run commerce/examples/generate-receipts.mts)`);
    const stored = loadExample(receipt.sku);
    assert.deepEqual(stored, receipt, `${receipt.sku} example matches its generator`);
    const check = verifyDeliveryReceipt(stored);
    assert.ok(check.ok, `${receipt.sku}: ${check.ok ? '' : check.reason}`);
    assert.equal(stored.seller.pubKeyHex, EXAMPLE_SELLER_PUBKEY_HEX);
    assert.equal(stored.network.mode, 'rehearsal');
  }
  const key = JSON.parse(readFileSync(join(examplesDir, 'example-seller-key.json'), 'utf8'));
  assert.equal(key.pubKeyHex, EXAMPLE_SELLER_PUBKEY_HEX);
  assert.match(key.note, /never a merchant key/);
});

test('any tamper fails: a changed field, a changed signature byte, a foreign key', () => {
  const good = loadExample('interop-run');
  const withAmount = { ...good, payment: { ...good.payment, amountOs: '5000000001' } };
  assert.equal(verifyDeliveryReceipt(withAmount).ok, false);
  const withResult = { ...good, resultHash: good.resultHash.replace(/^./, (c) => (c === '0' ? '1' : '0')) };
  assert.equal(verifyDeliveryReceipt(withResult).ok, false);
  const flipped = good.signature.hex.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  assert.equal(verifyDeliveryReceipt({ ...good, signature: { ...good.signature, hex: flipped } }).ok, false);
  const foreignKey = { ...good, seller: { ...good.seller, pubKeyHex: 'ab'.repeat(32) } };
  assert.equal(verifyDeliveryReceipt(foreignKey).ok, false);
  // A forger holding its own key can sign a receipt naming that key; the trusted-key argument closes it.
  assert.ok(verifyDeliveryReceipt(good, EXAMPLE_SELLER_PUBKEY_HEX).ok);
  assert.equal(verifyDeliveryReceipt(good, 'cd'.repeat(32)).ok, false);
  assert.notEqual(receiptCommitmentHex(withAmount), receiptCommitmentHex(good));
});

test('every required field is enforced by shape checks, and nothing throws on garbage', () => {
  const good = loadExample('pr-review');
  for (const key of schema.required as string[]) {
    const broken: Record<string, unknown> = { ...good };
    delete broken[key];
    assert.ok(checkReceiptShape(broken), `${key} missing must be a defect`);
    assert.equal(verifyDeliveryReceipt(broken).ok, false);
  }
  for (const garbage of [null, undefined, 1, 'x', [], {}, { v: 'other' }]) {
    assert.equal(verifyDeliveryReceipt(garbage).ok, false);
  }
  assert.equal(verifyDeliveryReceipt({ ...good, network: { ...good.network, mode: 'LIVE' } }).ok, false);
  assert.equal(verifyDeliveryReceipt({ ...good, payment: { ...good.payment, amountOs: '0' } }).ok, false);
  assert.equal(verifyDeliveryReceipt({ ...good, inputHash: good.inputHash.toUpperCase() }).ok, false);
  assert.equal(verifyDeliveryReceipt({ ...good, issuedAt: '2026-09-05' }).ok, false);
  for (const bad of ['2026-02-30T14:00:00Z', '2026-09-05T24:00:00Z', '2026-13-01T00:00:00Z', '2026-09-05T14:00:60Z', '2026-09-05T14:00:00+25:00']) {
    assert.equal(isRfc3339DateTime(bad), false, bad);
    assert.equal(verifyDeliveryReceipt({ ...good, issuedAt: bad }).ok, false, bad);
  }
  assert.ok(isRfc3339DateTime('2028-02-29T23:59:59.5+05:30'));
  assert.equal(verifyDeliveryReceipt({ ...good, endpoint: { resourceId: 'verify:' + 'a'.repeat(64) } }).ok, false, 'endpoint block on a manual SKU');
  // Unpaired surrogate: not canonicalisable, must not throw.
  assert.equal(verifyDeliveryReceipt({ ...good, buyer: 'bad\ud800' }).ok, false);
});

test('the verify-bundle example mirrors the endpoint receipt and the offers price', () => {
  const receipt = loadExample('verify-bundle');
  const offers = JSON.parse(readFileSync(join(here, '..', '..', 'commerce', 'offers.json'), 'utf8'));
  const sku = offers.skus.find((s: { id: string }) => s.id === 'verify-bundle');
  assert.equal(receipt.payment.amountOs, sku.price.amountOs);
  assert.ok(receipt.endpoint);
  assert.equal(receipt.endpoint!.resourceId, receipt.quoteRef);
  assert.equal(receipt.endpoint!.resourceId, receipt.idempotencyKey);
  assert.match(receipt.endpoint!.resourceId, /^verify:[0-9a-f]{64}$/);
  assert.equal(receipt.endpoint!.resourceId.slice(7), receipt.inputHash);
  assert.equal(verifyDeliveryReceipt({ ...receipt, quoteRef: 'verify:' + 'f'.repeat(64) }).ok, false, 'resourceId must equal quoteRef');
  assert.equal(verifyDeliveryReceipt({ ...receipt, endpoint: { ...receipt.endpoint, redelivered: 'yes' } }).ok, false);
  assert.equal(verifyDeliveryReceipt({ ...receipt, endpoint: { ...receipt.endpoint, extra: 1 } }).ok, false);
  // Endpoint receipt fields {txHash, from, amountOs, resourceId} all have a home in the delivery receipt.
  for (const field of ['txHash', 'from', 'amountOs'] as const) assert.ok(receipt.payment[field]);
  // A non-verify receipt must not be forced to carry the endpoint block.
  const manual = loadExample('interop-run');
  assert.equal(manual.endpoint, undefined);
  assert.ok(verifyDeliveryReceipt(manual).ok);
  // The verify SKU's own idempotency (same proof, same bytes, redelivered, never billed twice) is pinned by the
  // endpoint tests in test/vectors/verify-endpoint.test.ts; this file does not re-run a payment.
  const endpointTests = readFileSync(join(here, 'verify-endpoint.test.ts'), 'utf8');
  assert.match(endpointTests, /redelivered/);
});
