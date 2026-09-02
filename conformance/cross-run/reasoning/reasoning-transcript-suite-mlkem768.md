# Transcript encryption suite — independent implementation reasoning

Implementation: `impl/eval_transcript_suite_mlkem768.py`

Source consulted: only the supplied candidate profile sections 1–9 and its
pinned golden fixture. The upstream TypeScript implementation was not read,
fetched, or reconstructed. The evaluator is a pure function of vector data;
it does not read answer fields or vector names.

## Profile mapping

- §1 fixes the exact suite ID/version and envelope version. Unsupported
  selectors are malformed at verifier step 1.
- §2 defines unsigned binding shape, the Ed25519 signature preimage, validity
  window, and authenticated status outcomes. Binding signatures and authority
  decisions execute at step 2 before public-hash checks.
- §3 supplies bytewise UTF-8 member ordering, uniqueness, positional
  binding/wrap coordinates, `memberSetHash`, and `recipientBindingsHash`.
- §4 supplies deterministic ML-KEM encapsulation, direct shared-secret AES
  wrap keys, empty wrap AAD, and the 12+32+16-byte `wrapped` framing.
- §5 supplies values-only-NFC JCS plaintext, header construction, exact header
  JCS bytes as content AAD, and separate IV/ciphertext/tag fields.
- §6 supplies the public `contentHash` preimage. Binary content fields are
  strictly decoded before hashing.
- §7 supplies the envelope's exact member set and canonical wire encodings.
- §8 supplies the ordered eight-step verifier and the four outcomes. Evaluation
  stops at the first applicable step.
- §9 supplies the deterministic golden inputs and negative-test conditions.

The repository's standard JCS adapter is a process adapter over an external
DACS-Standard checkout, not an importable canonicalisation module. The evaluator
therefore contains one RFC 8785 function for the value subset used here: strings,
safe integers, booleans, null, arrays, and objects. It applies CORE CF-1 NFC only
to string values and sorts unmodified object names by UTF-16 code units.

## Library mapping

- ML-KEM-768: `kyber_py.ml_kem.ML_KEM_768` from kyber-py 1.2.0.
  `KeyGen_internal(d,z)` is `_keygen_internal(seed[:32], seed[32:])`, returning
  the 1,184-byte encapsulation key and 2,400-byte decapsulation key. Both derived
  public keys equal the fixture. `_encaps_internal(ek,m)` was checked in the
  installed library to return `(shared_secret, ciphertext)` with lengths 32 and
  1,088 bytes. Decapsulation is `decaps(dk,ct)`.
- Ed25519: cryptography `Ed25519PrivateKey.from_private_bytes(seed32)`. Member
  claims are `cci:` plus lowercase public-key hex. The signed bytes are the
  profile domain tag followed by ASCII lowercase SHA-256 hex of unsigned-binding
  JCS.
- AES-256-GCM: cryptography `AESGCM`. The raw ML-KEM shared secret is the wrap
  key with empty AAD. The CEK is the content key with exact header-JCS AAD.
- Base64URL decoding rejects padding, non-alphabet characters, remainder-one
  lengths, wrong decoded sizes, and non-canonical trailing bits by re-encoding.

## Boundaries and one observable limitation

No authenticated key-status registry was implemented. Tests inject its already
authenticated decision through `authority.keyStatus`; `unavailable` models a
resolver exception and yields `indeterminate` at step 2. A missing signing key
does likewise.

CF-2 claim canonicalisation is limited to the fixture's
`cci:<64 lowercase hex>` form. General ClaimReference canonicalisation is not
implemented.

When one binding and its wrap are removed and all three affected public hashes
are recomputed, the envelope alone contains no external copy of the fixed roster.
The pure verifier therefore discovers the absent requested coordinate at step 5.
It does not infer a roster from vector names or from unrelated authority keys.

## Reproduction

The pinned fixture SHA-256 is
`e9c8c0a60da017c7d5f33e6c47c811ef77b30c4127258b3ecc78efc3ba5ec95d`.
Reproduction reported `EQUAL` for all seven top-level compared fields, both
bindings' public keys and signatures, and both wraps' ML-KEM ciphertext and
wrapped CEK fields: 15/15 rows, `TOTAL ALL EQUAL`.
