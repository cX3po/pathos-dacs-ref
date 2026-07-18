/**
 * conformance/shared-suite/reference-adapter.mjs — the "pathos-dacs-ref" adapter, WIRED.
 *
 * Implements the DacsAdapter shape declared in `adapter-contract.mjs` / `ADAPTER.md` by
 * calling straight through to the self-contained `../partner-kit/{jcs,drift,sign,domain-sep}.mjs`
 * primitives. This file adds NO new cryptography or canonicalization logic of its own except
 * the ~15-line SIG-6 signature-value canonical-form guard (F3), which has no partner-kit
 * counterpart yet and is ported verbatim (same regex/decode/re-encode rule) from
 * `src/lib/verify-bundle-v1.ts::decodeEd25519Sig`.
 *
 * Self-contained on the run path: Node ≥ 18, zero npm dependencies, no network, no imports
 * outside `conformance/` (partner-kit + shared-suite) — same discipline as partner-kit.
 *
 * F4 (`verifyBundle`) is INTENTIONALLY NOT EXPORTED here. DACS-5 §10.4 single-bundle
 * acceptance (structural validation + required-signer rule + signature verification +
 * referenced-artifact signer-authorization) is a ~700-line verifier
 * (`src/lib/verify-bundle-v1.ts`) that pulls in the full repo src tree and its dev
 * dependencies (dacs-sdk#38's fix included) — it is NOT reproducible zero-dep on this run
 * path. Per ADAPTER.md's own semantics, an adapter that has no function for a family
 * ABSTAINS from it; that is the honest, non-faked answer for F4 in this reference adapter.
 * A full-verifier adapter (calling `verifyBundleV1` directly) is a legitimate REPO-SIDE
 * variant of this adapter — it would need `npx tsx` and the src tree, so it does not belong
 * on the zero-dep `conformance/` run path. If/when that variant is built, it should live
 * outside `conformance/shared-suite/` (e.g. a repo-side script) and register itself as a
 * SEPARATE adapter (e.g. "pathos-dacs-ref-full-verifier") rather than being folded into this
 * one, so the zero-dep guarantee of this file never regresses.
 */
import { jcsCanonical } from '../partner-kit/jcs.mjs';
import { evaluateArtifact } from '../partner-kit/drift.mjs';
import { sign, verify } from '../partner-kit/sign.mjs';

const ED25519_SIG_BYTES = 64;

/**
 * CORE SIG-6 canonical-form decode. Port of `src/lib/verify-bundle-v1.ts::decodeEd25519Sig`
 * (same rule, same ~15 lines): accept only unpadded Base64URL or canonical standard Base64
 * (migration window), with a decode/re-encode canonical-form check — the final base64 char
 * of a 64-byte payload carries 4 unused bits; a permissive decoder folds a non-zero setting
 * of those bits to the same 64 bytes, but a canonical verifier MUST reject the non-canonical
 * spelling (re-encode != input). Returns the decoded 64 bytes, or null if the value is not a
 * canonical ed25519 signature-value spelling.
 */
function decodeSigValueCanonical(v) {
  if (typeof v !== 'string') return null;
  if (!/^[A-Za-z0-9+/]{86}==$/.test(v) && !/^[A-Za-z0-9_-]{86}$/.test(v)) return null;
  let out;
  try {
    const b64 = v.replace(/-/g, '+').replace(/_/g, '/');
    out = new Uint8Array(Buffer.from(b64.endsWith('==') ? b64 : b64 + '==', 'base64'));
  } catch {
    return null;
  }
  if (out.length !== ED25519_SIG_BYTES) return null;
  const canonB64 = Buffer.from(out).toString('base64'); // 88 chars, "==" padded
  const canonB64url = canonB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // 86, no pad
  return v === canonB64 || v === canonB64url ? out : null;
}

/**
 * The reference adapter (pathos-dacs-ref) — the FIRST adapter because it seeds the corpus,
 * NOT because it defines conformance (see ADAPTER.md "Governance & neutrality").
 * @returns {import('./adapter-contract.mjs').DacsAdapter}
 */
export function referenceAdapter() {
  return {
    name: 'pathos-dacs-ref',

    // F1 — RFC 8785 (JCS) canonical bytes, hex-encoded. Throws (fail-closed) on
    // non-canonicalizable input (BigInt, unsafe-range numbers, lone surrogates, NFC key
    // collisions) — that throw IS the "reject" verdict for canonical-reject vectors.
    canonicalize(value) {
      return { hex: Buffer.from(jcsCanonical(value)).toString('hex') };
    },

    // F2 — sha256 over the artifact's canonical signed scope (bundleHash / evidenceHash).
    // Delegates to partner-kit's evaluateArtifact() dispatcher (bundle vs settlement
    // detection + the exact signed-scope stripping rules already ported there) and lifts
    // out just the computed hash. Throws if the artifact isn't a recognisable DACS artifact
    // (no bundleVersion/evidenceVersion) — there is no signed-scope hash to report.
    signedScopeHash(artifact) {
      const row = evaluateArtifact(artifact, 'shared-suite-vector', null);
      if (!row.ourHash) {
        throw new Error(
          `signedScopeHash: not a hashable DACS artifact (no bundleVersion/evidenceVersion) — ${row.notes || 'unrecognised kind'}`
        );
      }
      return { hex: row.ourHash };
    },

    // F3 — CORE SIG-6 signature-value verdict.
    signatureValueVerdict(value) {
      return decodeSigValueCanonical(value) === null ? 'REJECT' : 'ACCEPT';
    },

    // F5 — domain-separated sign/verify round-trip. Argument order (msg, sep, key, ...)
    // matches the DacsAdapter typedef in adapter-contract.mjs; partner-kit's sign()/verify()
    // take (separator, body, key, ...), so this is a thin reorder, not new logic.
    domainSepSign(msg, separator, privKey, intermediateHash) {
      return { hex: Buffer.from(sign(separator, msg, privKey, intermediateHash)).toString('hex') };
    },
    domainSepVerify(msg, separator, sig, pubKey, intermediateHash) {
      return verify(separator, sig, msg, pubKey, intermediateHash);
    },

    // F4 — verifyBundle: deliberately absent. See file header. ABSTAIN, not faked.
  };
}
