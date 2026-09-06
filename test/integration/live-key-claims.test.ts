import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { cciClaimForAddress, keyClaimForAddress, keyClaimForPubkeyClaim, demosClaimForPubkeyClaim, verifyDomainHashAgentSignature, claimRefFor } from '../../src/adapters/demos/identity.js';
import { resolvePrimaryClaimPubkey } from '../../src/lib/verify-bundle.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { listingLogicalAddress, assertRegisteredClaimReference } from '../../src/dacs1/addressing.js';

(ed as unknown as { etc: { sha512Sync: (...m: Uint8Array[]) => Uint8Array } }).etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
const priv = ed.utils.randomPrivateKey();
const pubHex = Buffer.from(ed.getPublicKey(priv)).toString('hex');
const address = `0x${pubHex}`;

test('a Demos wallet address is its ed25519 public key: cci: for parties and verifiers, key: for the registered listing address', () => {
  const cciClaim = cciClaimForAddress(address);
  assert.equal(cciClaim, `cci:${pubHex}`);
  assert.equal(keyClaimForAddress(address), `key:${pubHex}`);
  // DACS-1 v0.1 registers key: but neither cci: nor demos:, so the listing address takes the key: form of the same key.
  assert.doesNotThrow(() => assertRegisteredClaimReference(`key:${pubHex}`));
  assert.throws(() => assertRegisteredClaimReference(cciClaim), /not registered/);
  assert.throws(() => assertRegisteredClaimReference(String(claimRefFor(address))), /not registered/);
  assert.equal(keyClaimForPubkeyClaim(cciClaim), `key:${pubHex}`);
  assert.equal(keyClaimForPubkeyClaim(`demos:0x${pubHex}`), `key:${pubHex}`);
  assert.throws(() => keyClaimForPubkeyClaim(`lei:${pubHex}`), /64-hex/);
  assert.equal(demosClaimForPubkeyClaim(cciClaim), `demos:0x${pubHex}`);
  assert.equal(demosClaimForPubkeyClaim(`key:${pubHex}`), `demos:0x${pubHex}`);
  assert.equal(demosClaimForPubkeyClaim(`demos:0x${pubHex}`), `demos:0x${pubHex}`);
  assert.throws(() => cciClaimForAddress('0xabc'), /64-hex/);
  assert.throws(() => cciClaimForAddress(`0x${pubHex.toUpperCase()}`), /64-hex/);
  assert.throws(() => demosClaimForPubkeyClaim('cci:zz'), /64-hex/);
  assert.throws(() => demosClaimForPubkeyClaim(`lei:${pubHex}`), /64-hex/);
  // The repository's cold verifier resolves the public key from a cci: party claim (it does not from key: or demos:).
  const resolved = resolvePrimaryClaimPubkey({ party: { primary: { scheme: 'cci', identifier: pubHex } } } as never);
  assert.equal(Buffer.from(resolved!.pubkey).toString('hex'), pubHex);
  assert.equal(resolvePrimaryClaimPubkey({ party: { primary: { scheme: 'key', identifier: pubHex } } } as never), null);
});

test('the listing logical address takes the key: form derived from the party claim', () => {
  const logical = listingLogicalAddress(String(keyClaimForPubkeyClaim(cciClaimForAddress(address))), 'job-1-listing', 1);
  assert.ok(logical.startsWith('dacs1:'));
});

test('a signature made by the wallet key verifies under the cci:, key: and demos: forms and fails under another key', () => {
  const hash = 'ab'.repeat(32);
  // The wallet signs `domain || UTF8(hash)`; reproduce the bytes the CCI boundary signs.
  const domain = DOMAIN_SEPARATORS.AGREEMENT;
  const bytes = Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from(hash, 'utf8')]);
  const sig = ed.sign(bytes, priv);
  assert.equal(verifyDomainHashAgentSignature(`cci:${pubHex}`, domain, hash, sig), true);
  assert.equal(verifyDomainHashAgentSignature(`key:${pubHex}`, domain, hash, sig), true);
  assert.equal(verifyDomainHashAgentSignature(`demos:0x${pubHex}`, domain, hash, sig), true);
  // Uppercase hex is not the canonical form: the mapping refuses rather than normalising (the callers catch and treat as false).
  assert.throws(() => verifyDomainHashAgentSignature(`cci:${pubHex.toUpperCase()}`, domain, hash, sig), /64-hex/);
  const other = Buffer.from(ed.getPublicKey(ed.utils.randomPrivateKey())).toString('hex');
  assert.equal(verifyDomainHashAgentSignature(`key:${other}`, domain, hash, sig), false);
  assert.equal(verifyDomainHashAgentSignature(`key:${pubHex}`, domain, 'cd'.repeat(32), sig), false);
});
