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
The `missing-recipient-binding` vector removes a member's binding and wrap and
recomputes the public hashes. Because the member roster lives inside the
ciphertext, the envelope is self-consistent at step 1; the omission is first
observable at step 5 when opening as the removed member, or at step 8 as a roster
mismatch when opening as the retained member. This is how the harness reads
profile §3 versus §8, and is noted so a reader does not expect a step-1 failure.

## Blind-vector step coverage

Every vector is derived by `scripts/build_transcript_suite_blind_set.py` from the
pinned fixture inputs. For mutations that must pass content authentication, the
generator uses the profile seal helpers and pinned deterministic CEK/IV to re-seal
the altered header or transcript. `--check` compares both generated files byte for
byte with their committed forms.

| Vector | Outcome | Step | Code | Coverage |
|---|---:|---:|---|---|
| `seal-golden-inputs` | pass | 8 | `SEALED` | Reproduces six pinned seal outputs and opens for both members. |
| `exact-open-member-a` | pass | 8 | `OPENED` | Complete open as member A. |
| `exact-open-member-b` | pass | 8 | `OPENED` | Complete open as member B. |
| `wrong-recipient-coordinate` | fail | 5 | `RECIPIENT_NOT_FOUND` | Exact coordinate lookup. |
| `wrong-mlkem-secret` | fail | 5 | `CEK_WRAP_AUTHENTICATION_FAILED` | ML-KEM implicit rejection and wrap authentication. |
| `ciphertext-tamper-stale-content-hash` | fail | 4 | `CONTENT_HASH_MISMATCH` | Public commitment detects ciphertext mutation. |
| `ciphertext-tamper-recomputed-content-hash` | fail | 6 | `CONTENT_AUTHENTICATION_FAILED` | Content AEAD detects mutation after rehashing. |
| `wrap-tamper-stale-content-hash` | fail | 4 | `CONTENT_HASH_MISMATCH` | Public commitment detects wrap mutation. |
| `wrap-tamper-recomputed-content-hash` | fail | 5 | `CEK_WRAP_AUTHENTICATION_FAILED` | Wrap AEAD detects mutation after rehashing. |
| `channel-id-change-recomputed-content-hash` | fail | 6 | `CONTENT_AUTHENTICATION_FAILED` | Exact header AAD binds channel ID. |
| `modified-key-signature` | fail | 2 | `BAD_KEY_SIGNATURE` | Binding authorization signature. |
| `revoked-key` | fail | 2 | `KEY_REVOKED` | Authenticated revocation decision. |
| `unavailable-key-status` | indeterminate | 2 | `KEY_STATUS_UNAVAILABLE` | Four-value authority behavior. |
| `expired-key` | fail | 2 | `KEY_OUTSIDE_VALIDITY_WINDOW` | Exclusive expiry boundary. |
| `unsupported-suite-id` | error | 1 | `MALFORMED_ENVELOPE` | Closed suite ID. |
| `unsupported-suite-version` | error | 1 | `MALFORMED_ENVELOPE` | Closed suite version. |
| `suite-version-boolean-true` | error | 1 | `MALFORMED_ENVELOPE` | Boolean is not the exact numeric suite version. |
| `suite-version-float-one` | error | 1 | `MALFORMED_ENVELOPE` | Floating-point 1.0 is not the exact integer suite version. |
| `binding-valid-from-boolean` | error | 1 | `MALFORMED_ENVELOPE` | Boolean validity bound is not a safe integer. |
| `missing-recipient-binding` | fail | 5 | `RECIPIENT_NOT_FOUND` | Absent opener after self-consistent roster removal. |
| `duplicate-recipient` | error | 1 | `MALFORMED_ENVELOPE` | Duplicate-free roster. |
| `reordered-bindings` | error | 1 | `MALFORMED_ENVELOPE` | Canonical member-byte order. |
| `noncanonical-base64url-tag` | error | 1 | `MALFORMED_ENVELOPE` | Canonical unpadded Base64URL. |
| `wrap-binding-coordinate-mismatch` | error | 1 | `MALFORMED_ENVELOPE` | Positional binding/wrap bijection. |
| `stale-member-set-hash-resealed-content` | fail | 3 | `MEMBER_SET_HASH_MISMATCH` | Isolated member-set commitment check. |
| `stale-recipient-bindings-hash-resealed-content` | fail | 3 | `RECIPIENT_BINDINGS_HASH_MISMATCH` | Isolated signed-binding commitment check. |
| `member-b-revoked-open-member-a` | fail | 2 | `KEY_REVOKED` | All bindings authorized, not only opener. |
| `member-b-bad-key-signature-open-member-a` | fail | 2 | `BAD_KEY_SIGNATURE` | All binding signatures verified, with later bytes consistent. |
| `wrong-plaintext-hash-resealed-content` | fail | 7 | `PLAINTEXT_HASH_MISMATCH` | Content authenticates before isolated plaintext hash failure. |
| `transcript-member-order-mismatch-resealed-content` | fail | 8 | `TRANSCRIPT_ROSTER_MISMATCH` | Correct plaintext hash precedes roster-order comparison. |
| `malformed-plus-revoked-key` | error | 1 | `MALFORMED_ENVELOPE` | Step 1 precedes step 2. |
| `bad-key-signature-plus-stale-content-hash` | fail | 2 | `BAD_KEY_SIGNATURE` | Step 2 precedes step 4. |
| `stale-member-set-hash-plus-stale-content-hash` | fail | 3 | `MEMBER_SET_HASH_MISMATCH` | Step 3 precedes step 4. |

The table covers every verifier step: malformed shape at 1; all-binding
authorization at 2; both roster hashes at 3; the public commitment at 4;
recipient unwrap at 5; content authentication at 6; plaintext hashing at 7;
and transcript/envelope roster equality at 8.

## Reproduction

The pinned fixture SHA-256 is
`e9c8c0a60da017c7d5f33e6c47c811ef77b30c4127258b3ecc78efc3ba5ec95d`.
Reproduction reported `EQUAL` for all seven top-level compared fields, both
bindings' public keys and signatures, and both wraps' ML-KEM ciphertext and
wrapped CEK fields: 15/15 rows, `TOTAL ALL EQUAL`.
