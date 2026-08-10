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
 * side by side, so the divergence is executable rather than asserted. The divergence this
 * vector exercises is SCOPE (which fields are hashed) — not encoder behaviour. This artifact
 * contains no serialization feature (non-ASCII, exotic numbers) that would distinguish JCS
 * from Python's json.dumps, so it deliberately does NOT claim an encoder-level divergence:
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
 * conformance/regen-lifecycle.mts), so no input varies per run by construction. That is a
 * statement about INPUTS, not a guarantee of identical output bytes elsewhere: the runner and
 * transformer (tsx/esbuild), the python3 binary and the runtime closure are not attested.
 * Independent reproduction is DEMONSTRATED, not assumed, by running `--check` in your own
 * environment — it re-emits and byte-compares, so a divergence shows up rather than hiding.
 *
 *   npx tsx conformance/signed-artifact-b2-vector.mts           # emit + self-verify
 *   npx tsx conformance/signed-artifact-b2-vector.mts --check   # re-emit, assert byte-identical
 */
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
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

/**
 * Compute the published validator's value with REAL python3, not a JS reproduction.
 * The upstream validator is Python (`validate_conformance_vectors.py` canonical_json), so a
 * JS lookalike is a claim about Python, not a measurement of it. We compute both and refuse
 * to emit unless they agree — that turns "this is the validator's method" into a checked fact.
 */
function pythonPublishedStyleHash(artifact: unknown): string {
  const src = 'import sys,json,hashlib;'
    + 'v=json.load(sys.stdin);'
    + 's=json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False);'
    + 'print(hashlib.sha256(s.encode("utf-8")).hexdigest())';
  return execFileSync('python3', ['-c', src], { input: JSON.stringify(artifact), encoding: 'utf8' }).trim();
}

/**
 * Pin what a third party needs to reproduce these exact bytes.
 *
 * This is the sha256 of THIS GENERATOR'S OWN SOURCE, not a git commit. A commit SHA cannot work
 * here: the commit containing this output does not exist when the output is produced, so pinning
 * live HEAD names a tree that does not contain the generator that ran — false provenance. It also
 * forced --check to normalize the field, which made --check blind to tampering in it.
 * Source hashes have neither problem: they are stable across commits, they change when any
 * source that can alter these bytes changes, and a third party can verify they hold the same
 * inputs with sha256sum. The set must cover the implementation modules too — pinning only the
 * generator would leave emit/verify/sign/jcs changes able to move the output silently. sign.ts
 * matters most: it produces the signature bytes themselves.
 */
function sha256File(rel: string): string {
  return createHash('sha256').update(readFileSync(path.join(HERE, rel))).digest('hex');
}
/**
 * Every source whose bytes can change this output: the generator itself PLUS the
 * implementation modules it emits and hashes through. Pinning only the generator would
 * overclaim — a change in emit-bundle-v1 or jcs alters the emitted bytes while leaving the
 * generator's own hash untouched.
 */
const SOURCE_FILES: Record<string, string> = {
  'conformance/signed-artifact-b2-vector.mts': 'signed-artifact-b2-vector.mts',
  'src/lib/emit-bundle-v1.ts': '../src/lib/emit-bundle-v1.ts',
  'src/lib/verify-bundle-v1.ts': '../src/lib/verify-bundle-v1.ts',
  'src/lib/bundle-signed-scope-v1.ts': '../src/lib/bundle-signed-scope-v1.ts',
  'src/lib/sign.ts': '../src/lib/sign.ts',          // produces the emitted signature BYTES
  'src/jcs.ts': '../src/jcs.ts',
  'src/domain-sep.ts': '../src/domain-sep.ts',
};
function sourceHashes(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [label, rel] of Object.entries(SOURCE_FILES)) {
    // Fail CLOSED. Recording "unreadable" would emit a vector whose provenance cannot be
    // verified while still looking complete — the failure mode this whole block exists to stop.
    out[label] = sha256File(rel);
  }
  return out;
}
function depVersion(pkg: string): string {
  // Fail CLOSED, matching sourceHashes(): emitting "unknown" would claim complete provenance
  // while recording none.
  const pj = JSON.parse(readFileSync(path.join(HERE, '..', 'node_modules', pkg, 'package.json'), 'utf8'));
  const v = pj.version;
  if (typeof v !== 'string' || !v) throw new Error(`depVersion: no version for ${pkg}`);
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
const pyHash = pythonPublishedStyleHash(bundle);   // executed, then asserted equal below
// Executes the encoder-agreement statement instead of asserting it: real RFC 8785 JCS over the
// WHOLE artifact vs real python json.dumps over the same input. Equal here means the two encoders
// agree on THIS artifact (ASCII, no distinguishing forms) — which is precisely why this vector
// claims a scope divergence and not an encoder divergence.
const jcsWholeArtifactHash = jcsHashHex(bundle);
const encodersAgreeOnThisArtifact = jcsWholeArtifactHash === pyHash;

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

// EXECUTE the per-kind-exclusion claim rather than leaving it to be inferred: omitting only
// `signatures` (the naive global rule) is NOT the §B.2 scope for this kind. If these ever
// coincided, this artifact would not demonstrate the need for a per-kind excluded-field table.
const { signatures: _s2, ...sigOnlyScope } = bundle as Record<string, unknown> as any;
const signatureOnlyExcludedHash = jcsHashHex(sigOnlyScope);
const perKindExclusionMatters = signatureOnlyExcludedHash !== b2ContentHash;
const signaturesVerifyOverSignatureOnly = verifyAll(signatureOnlyExcludedHash);
// The whole point of #278: the signatures commit to the §B.2 scope, NOT to the published value.
// If these ever coincided, the vector would no longer discriminate and must not be published.
if (!signaturesVerify) throw new Error('signed-artifact-b2: emitted bundle does not self-verify');
if (!hashesDiverge) throw new Error('signed-artifact-b2: hashes coincide — vector cannot discriminate, refusing to emit');
if (!scopeMatchesImpl) throw new Error('signed-artifact-b2: computed B.2 scope != emitter signed scope — refusing to emit');
if (!signaturesVerifyOverB2) throw new Error('signed-artifact-b2: signatures do NOT verify over the B.2 value — the core claim is false, refusing to emit');
if (signaturesVerifyOverPublishedStyle) throw new Error('signed-artifact-b2: signatures ALSO verify over the published-style value — no discrimination, refusing to emit');
if (!perKindExclusionMatters) throw new Error('signed-artifact-b2: signature-only exclusion equals the B.2 scope — the per-kind claim is unsupported, refusing to emit');
if (signaturesVerifyOverSignatureOnly) throw new Error('signed-artifact-b2: signatures verify over the signature-only scope — per-kind exclusion not demonstrated, refusing to emit');
if (pyHash !== publishedStyle) throw new Error(`signed-artifact-b2: python/JS parity failed for the validator method (py=${pyHash} js=${publishedStyle}) — refusing to emit an unverified 'validator method' claim`);
if (!encodersAgreeOnThisArtifact) throw new Error('signed-artifact-b2: JCS and json.dumps disagree on this artifact — the stated scope-only divergence would be false, refusing to emit');

const SOURCE_HASHES = sourceHashes();
// The lockfile carries per-package integrity hashes, so pinning it constrains dependency
// CONTENTS rather than just their self-reported version strings.
const LOCKFILE_SHA256 = (() => {
  for (const f of ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']) {
    try { return `${f}:${createHash('sha256').update(readFileSync(path.join(HERE, '..', f))).digest('hex')}`; }
    catch { /* try next */ }
  }
  throw new Error('no lockfile found — refusing to emit without dependency-content provenance');
})();
const PYTHON_VERSION = execFileSync('python3', ['--version'], { encoding: 'utf8' }).trim();

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
  encoderAgreement: {
    jcsWholeArtifactHash,                    // RFC 8785 JCS over the whole artifact
    pythonJsonDumpsHash: pyHash,             // python json.dumps over the same input
    agree: encodersAgreeOnThisArtifact,      // MUST be true — executed, not assumed
    note: 'Equal on THIS artifact, which is why the divergence below is scope-only. Encoder '
      + 'divergence between JCS and json.dumps is real in general (non-ASCII, numeric forms) but '
      + 'is a separate property that this vector deliberately does not claim to exercise.',
  },
  divergence: {
    axis: 'scope — which fields are hashed',
    detail: 'the published-style value hashes the whole artifact including `signatures`; the §B.2 value '
      + 'omits the per-kind excluded fields. This vector does NOT exercise an encoder-level difference '
      + 'between RFC 8785 JCS and json.dumps: the artifact is ASCII with no distinguishing numeric or '
      + 'string forms, so the two encoders agree on identical input here. Encoder divergence is real in '
      + 'general but is a separate property needing its own vector.',
  },
  perKindExclusion: {
    signatureOnlyExcludedHash,                      // JCS(bundle minus `signatures` only)
    differsFromB2: perKindExclusionMatters,          // MUST be true
    signaturesVerifyOverSignatureOnly,               // MUST be false
    why: 'omitting only `signatures` is not the §B.2 scope for AttestationBundleV1 — `anchoredByRole` '
      + 'is also excluded (§10.4.1 R5-1), so a single global rule computes the wrong hash. This is the '
      + 'executable case for the per-kind excluded-field table.',
  },
  signaturesCommitTo: 'b2ContentHash',
  selfVerified: {
    signaturesVerify,
    hashesDiverge,
    scopeMatchesImplementation: scopeMatchesImpl,
    signaturesVerifyOverB2,                       // MUST be true
    signaturesVerifyOverPublishedStyle,           // MUST be false — this is what discriminates
    publishedStyleHashPythonParity: pyHash === publishedStyle,  // computed by real python3, not reproduced in JS
  },
  provenance: {
    generator: 'pathos-dacs-ref conformance/signed-artifact-b2-vector.mts',
    repo: 'https://github.com/cX3po/pathos-dacs-ref',
    // sha256 of EVERY source whose bytes can change this output — the generator and the
    // implementation modules it emits/hashes through. Verify with `sha256sum <path>` per entry.
    sourceHashes: SOURCE_HASHES,
    command: 'npx tsx conformance/signed-artifact-b2-vector.mts',
    checkCommand: 'npx tsx conformance/signed-artifact-b2-vector.mts --check',
    // Signature BYTES depend on the ed25519 implementation, so the library version is part of
    // reproducibility, not a footnote. Byte-stability across runs of the same tree is not the
    // same as reproducibility by a third party at an unspecified commit.
    // Signature and hash BYTES come out of these, so they are reproduction inputs, not trivia.
    // python3 is pinned because the published-style value is measured by executing it.
    dependencies: {
      '@noble/ed25519': depVersion('@noble/ed25519'),
      '@noble/hashes': depVersion('@noble/hashes'),
      canonicalize: depVersion('canonicalize'),
      node: process.version,
      python3: PYTHON_VERSION,
    },
    lockfile: LOCKFILE_SHA256,
    // HONEST SCOPE OF THESE PINS. They identify the inputs; they are not a hermetic
    // supply-chain attestation and this vector does not claim to be one. Specifically NOT
    // pinned: the TypeScript runner and transformer (tsx/esbuild), the python3 binary itself
    // beyond its reported version, and the OS/runtime closure. A different transformer, a
    // rebuilt dependency carrying the same version string, or a different python3 with the
    // same --version could in principle change bytes without changing any value above.
    // `--check` is the operative guarantee: it re-runs the generator in YOUR environment and
    // byte-compares, which detects such a divergence directly rather than assuming its absence.
    pinScope: 'identifies inputs; not a hermetic build attestation — see --check',
    deterministic: 'INPUTS are fixed: ed25519 fill-byte keys (0x11 buyer / 0x22 seller) and the '
      + 'timestamp 2026-01-01T00:00:00.000Z, so nothing here varies per run by construction. Byte '
      + 'stability is NOT asserted from the pins above — it is established only by a successful '
      + '`--check` in the environment doing the checking. No git commit is pinned, because the '
      + 'commit containing this output does not exist when the output is produced.',
  },
  artifact: bundle,
};

const serialized = JSON.stringify(vector, null, 2) + '\n';

if (process.argv.includes('--check')) {
  if (!existsSync(OUT)) { console.error(`missing ${OUT} — run without --check first`); process.exit(1); }
  // A TRUE byte comparison — nothing is exempted. Normalizing any field would mean --check
  // could not detect tampering in it while still reporting "byte-identical".
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
