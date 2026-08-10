/**
 * Cross-implementation confirmation vector for DACS-Standard #278:
 * a SIGNED artifact whose contentHash is the §B.2 canonical form.
 *
 * The finding in #278 is that no published vector exercises the §B.2 hash of a SIGNED
 * artifact, because `validate_conformance_vectors.py` hashes the signature-INCLUDED object
 * with `json.dumps`. So an implementer can be §B.2-correct and fail, or §B.2-wrong and pass.
 * A property the suite never exercises is one it cannot discriminate on (#270).
 *
 * This emits one signed AttestationBundleV1 from the reference impl and pins BOTH values
 * side by side, so the divergence is executable rather than asserted:
 *
 *   b2ContentHash        sha256(JCS(artifact minus the per-kind excluded fields))   <- §B.2
 *   publishedStyleHash   sha256(json.dumps(whole artifact, incl. signatures))       <- current validator
 *
 * WHY AttestationBundleV1 and not a simpler artifact: its signed scope omits `signatures`
 * AND `anchoredByRole` (§10.4.1 R5-1). That makes it the useful case rather than the easy
 * one — it shows a single global "omit the signature field" rule is insufficient and a
 * per-kind excluded-field table is required, which is exactly item 1 of the #278 PR plan.
 * A vector built on an artifact with no carve-out would not have surfaced that.
 *
 * Determinism: keys are fixed fill-bytes and timestamps are constants (same convention as
 * conformance/regen-lifecycle.mts), so the output is byte-stable and independently
 * reproducible by a third party — the chain keeps its provenance.
 *
 *   npx tsx conformance/signed-artifact-b2-vector.mts           # emit + self-verify
 *   npx tsx conformance/signed-artifact-b2-vector.mts --check   # re-emit, assert byte-identical
 */
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import { emitAttestationBundleV1 } from '../src/lib/emit-bundle-v1.js';
import { verifyBundleV1 } from '../src/lib/verify-bundle-v1.js';
import { jcsHashHex } from '../src/jcs.js';
import { bundleSignedScopeHashV1 } from '../src/lib/bundle-signed-scope-v1.js';
import { DOMAIN_SEPARATORS } from '../src/domain-sep.js';
import type { AttestationBundleV1 } from '../src/types/bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, 'regen', 'signed-artifact-b2.vector.json');

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const mk = (f: number) => { const priv = new Uint8Array(32).fill(f); return { priv, pubHex: hex(ed25519.getPublicKey(priv)) }; };

/** The published validator's method, reproduced exactly: json.dumps(sort_keys, compact) over the WHOLE object. */
function publishedStyleHash(artifact: unknown): string {
  const canonicalLikePython = JSON.stringify(sortDeep(artifact));
  return createHash('sha256').update(Buffer.from(canonicalLikePython, 'utf8')).digest('hex');
}
/** Mirrors python json.dumps(sort_keys=True, separators=(',',':')) key ordering. */
function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) out[k] = sortDeep((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

const buyer = mk(0x11);
const seller = mk(0x22);
const JOB = 'job-b2-278';
const T = '2026-01-01T00:00:00.000Z';
const Tn = Date.parse(T); // epoch-ms — finalisedAt is a non-negative integer, derived from T so they cannot drift apart

const buyerClaim = `cci:${buyer.pubHex}`;
const sellerClaim = `cci:${seller.pubHex}`;
const partyHash = (role: string, claim: string) => jcsHashHex({ jobId: JOB, role, primaryClaim: claim });

const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
  bundleVersion: '1', jobId: JOB, outcome: 'completed', anchoredByRole: 'buyer',
  listingRef: { listingId: 'lst-b2-278', version: 1, contentHash: jcsHashHex({ listingId: 'lst-b2-278', version: 1 }) },
  parties: [
    { role: 'buyer', bundleHash: partyHash('buyer', buyerClaim), primaryClaim: buyerClaim },
    { role: 'seller', bundleHash: partyHash('seller', sellerClaim), primaryClaim: sellerClaim },
  ],
  phaseSummary: [
    { index: 0, kind: 'vet-credentials', outcome: 'ok' },
    { index: 1, kind: 'settle', outcome: 'ok' },
  ],
  vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: Tn,
};

// Signed by the reference impl's own emitter — not a duplicated signing path.
const bundle: AttestationBundleV1 = emitAttestationBundleV1(unsigned, [
  { party: buyerClaim, privKey: buyer.priv },
  { party: sellerClaim, privKey: seller.priv },
]);

// ── the two hashes, side by side ─────────────────────────────────────────────
// §B.2 / §10.4.1: canonical form with the per-kind excluded fields omitted.
const { signatures: _sigs, anchoredByRole: _anchor, ...b2Scope } = bundle as Record<string, unknown> as any;
const b2ContentHash = jcsHashHex(b2Scope);
const publishedStyle = publishedStyleHash(bundle);

// ── self-verify: the claims this vector makes must hold at emit time ─────────
const v = verifyBundleV1(bundle);
const signaturesVerify = v.decision === 'accept' && v.signatureChecks.every((c) => c.decision === 'pass');
const hashesDiverge = b2ContentHash !== publishedStyle;

// Our independently-computed §B.2 scope must equal the emitter's own signed-scope hash.
// If these ever differ, this file is measuring something other than what gets signed.
const scopeMatchesImpl = b2ContentHash === bundleSignedScopeHashV1(unsigned);

// THE DISCRIMINATING CHECK, executed rather than asserted: the ed25519 signatures must verify
// over the §B.2 value and must NOT verify over the published-style value. This is the claim
// `signaturesCommitTo` makes, and it is the substance of the #278 finding — the vectors were
// signed correctly; only the stored contentHash and the validator disagree with them.
const enc = new TextEncoder();
const signedBytes = (h: string) => {
  const sep = enc.encode(DOMAIN_SEPARATORS.BUNDLE);
  const body = enc.encode(h);
  const out = new Uint8Array(sep.length + body.length);
  out.set(sep, 0); out.set(body, sep.length);
  return out;
};
const partyKey: Record<string, string> = { [buyerClaim]: buyer.pubHex, [sellerClaim]: seller.pubHex };
const verifyAll = (h: string) => bundle.signatures.every((s) => {
  const pub = partyKey[String(s.party)];
  if (!pub) return false;
  return ed25519.verify(Buffer.from(s.value, 'base64'), signedBytes(h), Buffer.from(pub, 'hex'));
});
const signaturesVerifyOverB2 = verifyAll(b2ContentHash);
const signaturesVerifyOverPublishedStyle = verifyAll(publishedStyle);
// The whole point of #278: the signatures commit to the §B.2 scope, NOT to the published value.
// If these ever coincided, the vector would no longer discriminate and must not be published.
if (!signaturesVerify) throw new Error('signed-artifact-b2: emitted bundle does not self-verify');
if (!hashesDiverge) throw new Error('signed-artifact-b2: hashes coincide — vector cannot discriminate, refusing to emit');
if (!scopeMatchesImpl) throw new Error('signed-artifact-b2: computed B.2 scope != emitter signed scope — refusing to emit');
if (!signaturesVerifyOverB2) throw new Error('signed-artifact-b2: signatures do NOT verify over the B.2 value — the core claim is false, refusing to emit');
if (signaturesVerifyOverPublishedStyle) throw new Error('signed-artifact-b2: signatures ALSO verify over the published-style value — no discrimination, refusing to emit');

const vector = {
  vectorId: 'signed-artifact-b2-contenthash',
  title: 'Signed artifact whose contentHash is the §B.2 canonical form (cross-impl confirmation for #278)',
  dacsVersion: '0.1',
  purpose:
    'Exercises the §B.2 canonical-form hash of a SIGNED artifact — the property #278 identifies as '
    + 'unexercised by any published vector. A conforming reader MUST reproduce b2ContentHash from the '
    + 'artifact with the per-kind excluded fields omitted; publishedStyleHash is recorded only to make '
    + 'the divergence explicit and is NOT a conformance target.',
  artifactKind: 'AttestationBundleV1',
  excludedFields: ['signatures', 'anchoredByRole'],
  excludedFieldsBasis: 'CORE §B.2 (signature omitted) + DACS-5 §10.4.1 R5-1 (anchoredByRole excluded)',
  b2ContentHash,
  publishedStyleHash: publishedStyle,
  divergesOnTwoAxes: [
    'signature-bearing fields are included in the published-style value and omitted from the §B.2 value',
    'json.dumps(sort_keys) is not RFC 8785 JCS (they coincide only on ASCII, signature-less content)',
  ],
  signaturesCommitTo: 'b2ContentHash',
  selfVerified: {
    signaturesVerify,
    hashesDiverge,
    scopeMatchesImplementation: scopeMatchesImpl,
    signaturesVerifyOverB2,                       // MUST be true
    signaturesVerifyOverPublishedStyle,           // MUST be false — this is what discriminates
  },
  provenance: {
    generator: 'pathos-dacs-ref conformance/signed-artifact-b2-vector.mts',
    command: 'npx tsx conformance/signed-artifact-b2-vector.mts',
    checkCommand: 'npx tsx conformance/signed-artifact-b2-vector.mts --check',
    deterministic: 'fixed ed25519 fill-byte keys + fixed timestamps; byte-stable across runs',
  },
  artifact: bundle,
};

const serialized = JSON.stringify(vector, null, 2) + '\n';

if (process.argv.includes('--check')) {
  if (!existsSync(OUT)) { console.error(`missing ${OUT} — run without --check first`); process.exit(1); }
  const onDisk = readFileSync(OUT, 'utf8');
  if (onDisk !== serialized) { console.error('DRIFT: re-emit is not byte-identical to the committed vector'); process.exit(1); }
  console.log('byte-identical ✓  b2=%s  published-style=%s', b2ContentHash, publishedStyle);
  process.exit(0);
}

writeFileSync(OUT, serialized);
console.log('wrote %s', OUT);
console.log('  §B.2 contentHash    : %s', b2ContentHash);
console.log('  published-style hash: %s', publishedStyle);
console.log('  signatures verify   : %s', signaturesVerify);
console.log('  hashes diverge      : %s', hashesDiverge);
