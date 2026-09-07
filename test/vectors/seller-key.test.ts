import test from 'node:test';
import assert from 'node:assert/strict';
import * as ed25519 from '@noble/ed25519';
import { sellerKeyFromWallet } from '../../src/live/seller-key.js';

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

test('seller key: the wallet seed signs for the wallet address; a foreign seed, a wrong address, or a malformed key is refused', () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = ed25519.getPublicKey(seed);
  const libsodium = new Uint8Array(64); libsodium.set(seed, 0); libsodium.set(pub, 32);
  const key = sellerKeyFromWallet({ publicKey: pub, privateKey: libsodium }, `0x${hexOf(pub)}`);
  assert.equal(key.pubKeyHex, hexOf(pub)); assert.deepEqual(Array.from(key.privKey), Array.from(seed));
  assert.equal(sellerKeyFromWallet({ publicKey: pub, privateKey: seed }, `0X${hexOf(pub).toUpperCase()}`).pubKeyHex, hexOf(pub));
  const other = ed25519.getPublicKey(new Uint8Array(32).fill(9));
  assert.throws(() => sellerKeyFromWallet({ publicKey: pub, privateKey: libsodium }, `0x${hexOf(other)}`), /does not derive the wallet address/);
  assert.throws(() => sellerKeyFromWallet({ publicKey: other, privateKey: libsodium }, `0x${hexOf(pub)}`), /public key does not equal/);
  assert.throws(() => sellerKeyFromWallet({ publicKey: pub, privateKey: new Uint8Array(31) }, `0x${hexOf(pub)}`), /31 bytes/);
  assert.throws(() => sellerKeyFromWallet({ publicKey: pub, privateKey: libsodium }, 'not-an-address'), /0x \+ 64 hex/);
});
