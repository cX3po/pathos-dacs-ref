import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { DELIVERY_RECEIPT_VERSION, signDeliveryReceipt, type DeliveryReceiptBody } from '../../src/lib/delivery-receipt.js';
import { sellerFromMnemonicEnv } from '../../src/live/verify-endpoint.mjs';

ed25519.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...m));
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function signedRecord(sellerSeed: Uint8Array): string {
  const pubHex = hexOf(ed25519.getPublicKey(sellerSeed));
  const input = createHash('sha256').update('{"bundle":{}}').digest('hex');
  const resourceId = `verify:${input.slice(0, 16)}`;
  const body: DeliveryReceiptBody = {
    v: DELIVERY_RECEIPT_VERSION, sku: 'verify-bundle' as DeliveryReceiptBody['sku'], quoteRef: resourceId, buyer: '0x' + '55'.repeat(32),
    seller: { name: 'PATH-OS', pubKeyHex: pubHex }, network: { id: 'demos:testnet', mode: 'rehearsal' },
    payment: { txHash: 'ab'.repeat(32), from: '0x' + '55'.repeat(32), amountOs: '100000000' }, idempotencyKey: resourceId,
    inputHash: input, implementationVersion: 'test', resultHash: createHash('sha256').update('{}').digest('hex'), issuedAt: '2026-09-07T17:00:00Z',
    retrieval: { kind: 'http-response', ref: 'POST /verify' }, endpoint: { resourceId },
  };
  const receipt = signDeliveryReceipt(body, sellerSeed);
  const dir = mkdtempSync(join(tmpdir(), 'recheck-'));
  const file = join(dir, 'verify-pilot-test.json');
  writeFileSync(file, JSON.stringify({ buyer: { deliveryReceipt: receipt }, deliveryReceipt: receipt }));
  return file;
}

function recheck(args: string[]): { status: number | null; out: string } {
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/receipt-recheck.mts', ...args], { cwd: process.cwd(), encoding: 'utf8', timeout: 120_000 });
  return { status: run.status, out: (run.stdout + run.stderr).trim() };
}

test('receipt-recheck: verifies only under the independently supplied seller key; a missing or malformed key is a usage error, a foreign key fails', () => {
  const seed = new Uint8Array(32).fill(0x21); const pubHex = hexOf(ed25519.getPublicKey(seed));
  const file = signedRecord(seed);
  const ok = recheck(['--file', file, '--seller-pubkey', pubHex]);
  assert.equal(ok.status, 0, ok.out); assert.match(ok.out, /"ok":true/);
  const foreign = recheck(['--file', file, '--seller-pubkey', hexOf(ed25519.getPublicKey(new Uint8Array(32).fill(0x22)))]);
  assert.equal(foreign.status, 1, foreign.out); assert.match(foreign.out, /"ok":false/);
  assert.equal(recheck(['--file', file]).status, 2);
  assert.equal(recheck(['--file', file, '--seller-pubkey', 'not-hex']).status, 2);
});

test('seller wallet from mnemonic env: a wallet-unlock failure is reported with a fixed message that never echoes the SDK error or the secret', async () => {
  const sentinel = 'SENTINEL-' + 'zebra '.repeat(11) + 'zebra';
  const dir = mkdtempSync(join(tmpdir(), 'dotenv-'));
  const envFile = join(dir, '.env');
  writeFileSync(envFile, `PILOT_TEST_SELLER_MNEMONIC="${sentinel}"\n`);
  const result = await sellerFromMnemonicEnv({ VERIFY_SELLER_MNEMONIC_ENV: 'PILOT_TEST_SELLER_MNEMONIC', DACS_ENV_PATH: envFile } as NodeJS.ProcessEnv,
    async () => { throw new Error(`unlock exploded with ${sentinel}`); });
  assert.ok(result && 'error' in result);
  assert.equal(result.error, 'seller wallet could not be unlocked');
  assert.doesNotMatch(JSON.stringify(result), /zebra|SENTINEL/);
  const badName = await sellerFromMnemonicEnv({ VERIFY_SELLER_MNEMONIC_ENV: 'lower case' } as NodeJS.ProcessEnv);
  assert.ok(badName && 'error' in badName);
  assert.equal(await sellerFromMnemonicEnv({} as NodeJS.ProcessEnv), null);
});
