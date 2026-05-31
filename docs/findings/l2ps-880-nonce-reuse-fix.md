# Fix proposal — L2PS AES-GCM nonce reuse (KyneSys issue #880)

> Contributed by [pathos-dacs-ref](../../README.md). A concrete fix for the open P0
> in `@kynesyslabs/demosdk` `src/l2ps/l2ps.ts` (verified against v4.0.5 source).
> Offered as a proposal/PR-when-ready, not a unilateral patch.

## The bug (verified at source)
`L2PS` holds a **single `private readonly iv`** set once in the constructor
(`l2ps.ts:99-105`). Every encryption reuses it:

```ts
// l2ps.ts:200-203  (encryptTx)
const cipher = forge.cipher.createCipher('AES-GCM', this.privateKey)
cipher.start({ iv: this.iv })          // <-- same (key, iv) for EVERY tx in the subnet
```

So all transactions a subnet encrypts share one (key, nonce) pair.

## Why this is a P0 (not a polish item)
AES-GCM with a reused (key, nonce) is a **total** break — both properties fail:
1. **Confidentiality.** GCM is CTR-mode: same key+nonce → same keystream `K`. For two
   ciphertexts, `C₁ ⊕ C₂ = P₁ ⊕ P₂` — plaintext XOR leaks directly; any known/guessable
   plaintext (these are structured transactions) unravels the rest.
2. **Authentication.** Nonce reuse enables the GCM **"forbidden attack"** (Joux): from
   two (or a few) known/chosen messages encrypted under the *reused* (key, nonce), an
   adversary solves for the GHASH subkey `H`, then **forges valid auth tags for chosen
   ciphertexts under that key** — so integrity, not just confidentiality, is lost. (The
   recovery/forgery is scoped to the reused key+nonce, but here that's *every* tx in the
   subnet, so it's effectively total.)

For a *privacy* subnet whose entire purpose is confidential transactions, this voids the
guarantee. It must be fixed before any L2PS data is treated as private.

## The fix: per-message nonce (random 96-bit), carried in the payload
Generate a fresh IV **per encryption**, store it alongside the ciphertext+tag, and read
it back on decrypt. This is exactly what the SDK's own `encryption/PQC/enigma.ts:176`
already does (`crypto.randomBytes(12)`), and what `instant_messaging/l2ps_types.ts:209`
already anticipates (a per-message `nonce` field). The core L2PS just needs to match.

### 1. Add `iv` to the encrypted payload type (keep all existing fields)
```ts
// l2ps.ts — L2PSEncryptedPayload (existing fields preserved; only `iv` is new)
interface L2PSEncryptedPayload {
  l2ps_uid: string
  encrypted_data: string   // base64
  tag: string              // base64
  original_hash: string    // KEEP — still validated against originalTx.hash on decrypt (l2ps.ts:301)
  iv: string               // base64  <-- NEW: the per-message 96-bit nonce
}
```

### 2. Fresh IV per encryption
```ts
async encryptTx(tx: Transaction, senderIdentity?: any): Promise<L2PSTransaction> {
  const iv = forge.random.getBytesSync(12)               // 96-bit, FRESH per tx
  const cipher = forge.cipher.createCipher('AES-GCM', this.privateKey)
  cipher.start({ iv })                                   // not this.iv
  cipher.update(txBuffer)
  if (!cipher.finish()) { /* … */ }
  return {
    l2ps_uid:       this.id,
    encrypted_data: forge.util.encode64(cipher.output.getBytes()),
    tag:            forge.util.encode64(cipher.mode.tag.getBytes()),
    original_hash:  tx.hash,                             // KEEP — unchanged, still validated on decrypt
    iv:             forge.util.encode64(iv),             // travel the nonce with the ciphertext
  }
}
```

### 3. Decrypt from the payload's IV (not `this.iv`)
```ts
async decryptTx(encryptedTx: L2PSTransaction): Promise<Transaction> {
  const iv = forge.util.createBuffer(forge.util.decode64(encryptedPayload.iv))
  const decipher = forge.cipher.createDecipher('AES-GCM', this.privateKey)
  decipher.start({ iv, tag })                            // iv from payload
  /* … */
}
```

### 4. Drop the constructor `iv` from the crypto path
`create(privateKey?, iv?)` and the `private readonly iv` exist only to feed encryption;
once the nonce is per-message, the instance IV should be removed (or, for back-compat,
kept but never used to encrypt — and a deprecation note added) so it can't be
reintroduced as a reuse source.

## Migration / compat
- **Wire-breaking** for in-flight subnets (payload gains a required `iv`; old payloads
  lack it). Since L2PS is pre-mainnet PoC, a clean break is cheapest. If any persisted
  ciphertext must remain readable, gate on `payload.iv` presence and fall back to the
  legacy `this.iv` path for old records only (read-only), never for new writes.
- A test vector: encrypt the *same* plaintext twice in one subnet → assert the two
  ciphertexts (and IVs) differ, and both decrypt correctly. (Today they'd be identical —
  the regression that proves the bug.)

## Nonce-volume note (for high-throughput subnets)
Random 96-bit IVs are safe to ~2³² messages per key (birthday bound on collision).
A busy subnet could approach that; two stronger options if volume warrants:
- **Deterministic counter nonce** (per-key monotone) — zero collision risk, needs
  per-instance counter persistence.
- **XChaCha20-Poly1305** (192-bit nonce) — random nonces are collision-safe at any
  realistic volume; a clean swap if AES-GCM isn't a hard requirement.
Random-96 per-message is the minimal correct fix; the above are hardening for scale.
