/**
 * seller-key.ts — the delivery-receipt signing key of a seller, taken from the seller's own Demos wallet.
 *
 * A Demos wallet's ed25519 keypair (demosdk `Demos.keypair`) carries the 64-byte libsodium private key
 * `seed(32) || publicKey(32)`; the receipt signer (`@noble/ed25519`) takes the 32-byte seed. The seed is
 * accepted only when its public key equals the wallet's address, so a receipt signed with it verifies under the
 * seller's DACS identity (`did:demos:agent:<address hex>`), the key the buyer binds the listing to.
 */
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

ed25519.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...messages));

export interface WalletKeypair {
  publicKey: ArrayLike<number>;
  privateKey: ArrayLike<number>;
}

export interface SellerSigningKey {
  privKey: Uint8Array;
  pubKeyHex: string;
}

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** The 32-byte seed behind a wallet keypair, checked against the wallet's 0x address; throws on any mismatch. */
export function sellerKeyFromWallet(keypair: WalletKeypair, address: string): SellerSigningKey {
  const priv = Uint8Array.from(keypair.privateKey);
  const pub = Uint8Array.from(keypair.publicKey);
  if (priv.length !== 64 && priv.length !== 32) throw new Error(`wallet private key has ${priv.length} bytes; expected 64 (seed || public key) or 32 (seed)`);
  const seed = priv.subarray(0, 32);
  const derived = ed25519.getPublicKey(seed);
  const addressHex = address.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(addressHex)) throw new Error('wallet address is not 0x + 64 hex characters');
  if (hexOf(derived) !== addressHex) throw new Error('wallet seed does not derive the wallet address');
  if (pub.length === 32 && hexOf(pub) !== addressHex) throw new Error('wallet public key does not equal the wallet address');
  return { privKey: new Uint8Array(seed), pubKeyHex: addressHex };
}
