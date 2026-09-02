# Candidate encryption-suite profile for the DACS-3 encrypted transcript anchor (input to #351)

Status: candidate input to the steward's hard gate on DACS-Standard#351. Not normative text. Every SDK-derived value below is pinned to `@kynesyslabs/demosdk` 4.0.16 (`build/encryption/unifiedCrypto.js`, `build/encryption/PQC/enigma.js`, `build/abstraction/Identities.js`, and `build/l2ps/anchor/anchor.js`) and `@noble/post-quantum` 0.4.1 as shipped in that package.

## 1. Suite identifier

`suiteId = "dacs-transcript-mlkem768-a256gcm/1"`. The trailing `/1` is the profile version; because no version was published, the corrections in this candidate keep `/1`. After publication, a change to any parameter in sections 2–8 requires a new suite id, never an in-place edit.

## 2. Recipient key source, binding, and byte format

- Recipient key: an ML-KEM-768 encapsulation public key, 1184 bytes (FIPS 203 `ek`). The SDK derives the 64-byte key-generation seed as pinned in section 3 and passes it to `ml_kem768.keygen(seed)` in `generate_ml_kem_encryption_keypair` (`enigma.js:201-205`).
- `keySig` (the member's DACS `ComponentSignature` over `UTF8('dacs-transcript-kem-key:v1:') || sha256(JCS({claim, kem, publicKey})))`) binds the key to the claim; it is specified here and listed as out of scope for this harness (§10), which binds the advertised keys only through `memberKeysHash`.
- The SDK's on-chain `pqc` identity binding is `bindPqcIdentity` (`Identities.js:455`). Its supported PQC algorithms are exactly `["falcon", "ml-dsa"]` (`unifiedCrypto.js:341`), so ML-KEM public keys are not published by that path today. A production roster therefore supplies `{ claim, kem: "ml-kem-768", publicKey: base64url(ek), keySig }`. The harness vectors omit `keySig` and skip verification step 2.
- Claims in this profile are already CF-2 canonical `ClaimReference`s; the order is `Buffer.compare` over their UTF-8 bytes. CF-2 canonicalisation before this point is a precondition and is not performed by this profile or harness.

If the substrate later publishes ML-KEM keys under the `pqc` identity, a roster entry may cite that record instead; the `ek` byte format is unchanged.

## 3. Key agreement, KDF, and content key

- Per recipient: `(ct_i, ss_i) = ML-KEM-768.Encaps(ek_i, m_i)` with `ct_i` 1088 bytes and `ss_i` 32 bytes. `m_i` is the 32-byte encapsulation randomness. The SDK calls `ml_kem768.encapsulate(peerPublicKey)` (`enigma.js:118`); the noble API's explicit randomness argument makes these vectors deterministic.
- **SDK ek/dk derivation (not used by these vectors):** `okm = HKDF-SHA-256(ikm = wallet masterSeed, salt = UTF8('master seed'), info = UTF8('ml-kem-aes'), L = 64)` (`unifiedCrypto.js:139-140`); `(ek, dk) = ML-KEM-768.KeyGen(okm)` (`enigma.js:201-205`). The two source literals are exactly `"master seed"` and `"ml-kem-aes"`. **Wrap KDF:** none — `ss` (32 bytes) is the AES-256-GCM key. **Vector path:** raw `ml_kem768.keygen(64-byte seed)`, not the HKDF above.
- The direct use of `sharedSecret` as the AES-256-GCM key is pinned at `enigma.js:120-121`.
- Content encryption key `cek`: 32 random bytes, generated once per envelope and never reused across envelopes.

## 4. Multi-recipient wrapping

For each member `i` in roster order:

`wrap_i = SDK.encrypt_ml_kem_aes(cek, ek_i) = { kemCiphertext: base64url(ct_i), wrapped: base64url(iv_i || AES-256-GCM(ss_i, iv_i, cek) || tag_i) }`.

`iv_i` is 12 random bytes and `tag_i` is 16 bytes. The SDK uses a 12-byte IV and `sharedSecret` directly as the key (`enigma.js:118,120-121`), frames `Buffer.concat([iv, encryptedMessage, authTag])` (`enigma.js:130-133`), and decrypts with `slice(0, 12)`, `slice(12, -16)`, and `slice(-16)` (`enigma.js:145-160`). Wrap AEAD has no AAD (SDK primitive). A wrap of a different `cek` fails at step 6. A `cek` holder can reseal new content under the same wraps; that is prevented only by envelope/transcript signatures (out of this harness), not by wrap AEAD.

## 5. Content encryption, AAD, and public commitment

- `memberSetHash = sha256(JCS(orderedClaims))` hex, using the steward's definition.
- `memberKeysHash = sha256(JCS(memberKeys.map(({claim, kem, publicKey}) => ({claim, kem, publicKey}))))` hex.
- `plaintextHash = sha256(JCS(AuthenticatedChannelTranscript))` hex.
- `header = { suiteId, transcriptVersion: "1", channelId, memberSetHash, memberKeysHash, plaintextHash }`.
- `aad = UTF8(JCS(header))`: the RFC 8785 canonical form of `header`, with no trailing newline.
- `ciphertext = AES-256-GCM(cek, iv, plaintext = UTF8(JCS(AuthenticatedChannelTranscript)), aad)`, with a 12-byte random `iv` and a 16-byte `tag`; `iv`, `ciphertext`, and `tag` are separate base64url fields.
- `contentHash = sha256(UTF8(JCS(header)) || iv || ciphertext || tag)` hex.

`contentHash` binds the header (and through it `memberSetHash`, `memberKeysHash`, and `plaintextHash`) to the content bytes, so header tampering is a public step-4 failure. The SDK anchor helper (`anchor.js:67,123`) hashes only the L2PS ciphertext under the subnet key; it is a different object and is not this profile.

## 6. Envelope

```
EncryptedChannelTranscript = {
  envelopeVersion: "1", suiteId, channelId,
  memberSetHash, memberKeysHash, plaintextHash,
  memberKeys: [{ claim, kem, publicKey }...],
  wraps: [{ claim, kemCiphertext, wrapped }...],
  iv, ciphertext, tag, contentHash
}
```

The harness form above omits production `keySig` as described in sections 2 and 10. Claims are already CF-2 canonical `ClaimReference`s and arrays use `Buffer.compare` over claim UTF-8 bytes; no CF-2 canonicalisation is performed here. All binary fields are base64url without padding (SIG-6 value encoding), hashes are lowercase hex, and the envelope is JCS-canonical when hashed or signed. Signatures over the envelope use the steward's `TranscriptSignature` with the existing `ComponentSignature` algorithm set.

## 7. Nonce and randomness

`iv` and every `iv_i` are 12 bytes from a CSPRNG (`crypto.randomBytes(12)`, `enigma.js:120`); `cek` and every `m_i` are 32 bytes from a CSPRNG. Because `cek` is single-use and each wrap has its own `ss_i`, nonce uniqueness is per key and holds with random nonces at these sizes. Vector files carry `cek`, each `m_i`, `iv`, and each `iv_i` so a verifier regenerates the exact bytes.

## 8. Rotation and revocation

Admission verifies every `memberKeys[i].keySig` against the member's current DACS signing key at substrate time. A revoked signing key invalidates that roster entry. A member's ML-KEM key change changes `memberKeysHash` (while `memberSetHash` remains unchanged if the ordered claims are unchanged), and therefore requires a new envelope and anchor. A membership change changes both the ordered roster commitment and, normally, the advertised-key commitment. There is no re-wrap without re-anchoring.

## 9. Verification order

1. Check envelope shape and encodings.
2. Verify production `memberKeys` signatures (specified, skipped by this harness).
3. Recompute and compare both `memberSetHash` from the ordered claims and `memberKeysHash` from the advertised `{claim, kem, publicKey}` entries.
4. Recompute and compare `contentHash = sha256(UTF8(JCS(header)) || iv || ciphertext || tag)`.
5. For the verifier's claim, locate its wrap, compute `ss = Decaps(ct, dk)`, and authenticate/decrypt the wrapped `cek`.
6. Open the content with `aad = UTF8(JCS(header))`.
7. Check `sha256(JCS(plaintext)) == plaintextHash`.
8. Check that the plaintext's `channelId` and ordered roster equal the header/envelope values.

Steps 1–4 need no secret keys. The verifier returns the first failure; in particular, an unrehashed header or ciphertext edit stops at step 4.

## 10. Deterministic vectors and scope

- `success`: both roster members open the deterministic envelope.
- `tamper-ciphertext`: one ciphertext bit is flipped without rehashing; public integrity and every recipient stop at step 4.
- `tamper-ciphertext-rehashed`: the bit is flipped and `contentHash` recomputed; public integrity succeeds and both members fail content authentication or JSON decoding at step 6.
- `wrong-claim`: an absent claim has no wrap and stops at step 5 with `recipient wrap not found`; it never decapsulates.
- `wrong-dk`: member A's in-roster claim is opened with the outsider's `dk`; ML-KEM implicit rejection produces a different shared secret and the wrap tag fails at step 5 with `recipient wrap authentication failed`.
- `aad-mismatch`: `channelId` is edited without rehashing; public integrity and every recipient stop at step 4.
- `aad-mismatch-rehashed`: `channelId` is edited and `contentHash` recomputed; steps 1–4 pass and both members fail AAD authentication at step 6.
- `member-set-mismatch`: `memberSetHash` is replaced; public integrity and every recipient stop at step 3.
- `member-key-swap`: member B's `publicKey` bytes are replaced while the wraps and `memberKeysHash` are retained; public integrity and every recipient stop at step 3 with `memberKeysHash mismatch`.
- `stale-key`: specified, not in this harness (needs the DACS signer); a production verifier rejects it at step 2.

The vectors use raw `ml_kem768.keygen` with stated 64-byte seeds. Explicitly out of scope are `keySig` creation/verification and `stale-key`, the SDK HKDF recipient-key path, L2PS transport, anchoring, and envelope/transcript signatures.

## 11. What this profile does not claim

It does not claim the SDK's `anchorEncryptedTranscript` helper implements this profile; that helper encrypts with the L2PS subnet key and has no per-recipient wrap. It does not provide forward secrecy. It does not define L2PS transport or anchoring.

## Harness

The harness consists of `conformance/transcript-envelope/envelope.mts`, `conformance/transcript-envelope/generate-vectors.mts`, and `test/vectors/transcript-envelope.test.ts`. Generate vectors with `npx tsx conformance/transcript-envelope/generate-vectors.mts`, verify checked-in bytes with `npx tsx conformance/transcript-envelope/generate-vectors.mts --check`, and run its test with `npx tsx --test test/vectors/transcript-envelope.test.ts`.

Its vectors are: `success` (two valid opens), `tamper-ciphertext` (public content-byte commitment), `tamper-ciphertext-rehashed` (content AEAD), `wrong-claim` (lookup failure without decapsulation), `wrong-dk` (ML-KEM implicit rejection followed by wrap-tag failure), `aad-mismatch` (public header commitment), `aad-mismatch-rehashed` (content AAD), `member-set-mismatch` (claim-roster commitment), and `member-key-swap` (advertised-key commitment). Every recorded expectation is executed, and the checked-in vector file is required to regenerate byte-identically.

The explicit exclusions are `keySig` and `stale-key` (they need the DACS signer), the SDK HKDF key path, L2PS transport, anchoring, and envelope/transcript signatures.
