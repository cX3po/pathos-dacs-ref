/**
 * partner-kit/generate.mts — REPO-SIDE generator for the partner kit's vectors.json + MANIFEST.json.
 *
 * Run from the repo root:  npx tsx conformance/partner-kit/generate.mts
 *
 * Everything the kit asserts is derived from the IN-REPO reference implementation (the oracle):
 *  - canonical accept vectors: re-verified against BOTH src/jcs.ts (canonicalize-backed) and the
 *    kit's original serializer (kit ships nothing the oracle didn't reproduce);
 *  - sign vectors: signatures produced by src/lib/sign.ts (@noble/ed25519), then reproduced with
 *    the kit's node:crypto path before being written (cross-impl determinism check);
 *  - drift vectors: expected rows computed by the KIT evaluator and asserted row-for-row against
 *    the reference evaluator (src/lib/dacs-drift.ts + verifyBundleV1) — the parity receipt.
 *
 * The generator then self-runs the kit (node run-conformance.mjs --json), requires 49/49, and
 * records the exact command + result + timestamp + full source commit in MANIFEST.json.
 *
 * This file is repo tooling; it travels with the kit only so the kit directory is fully
 * tamper-evident (it is hashed in MANIFEST.files like everything else).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { jcsHashHex as srcJcsHashHex, jcsCanonical as srcJcsCanonical } from '../../src/jcs.js';
import { sign as srcSign, verify as srcVerify } from '../../src/lib/sign.js';
import {
  DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS, DACS_X_EXTENSION_SEPARATORS,
  PATHOS_EXTENSION_SEPARATORS, buildSignedBytes as srcBuildSignedBytes,
} from '../../src/domain-sep.js';
import { evaluateArtifact as srcEvaluateArtifact } from '../../src/lib/dacs-drift.js';
import { bundleSignedScopeHashV1 as srcBundleSignedScopeHashV1 } from '../../src/lib/bundle-signed-scope-v1.js';
import { rejectCases } from '../../vectors/canonical-form/cases.js';
import * as ed25519 from '@noble/ed25519';

const KIT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(KIT_DIR, '..', '..');

const kitJcs = await import('./jcs.mjs');
const kitSign = await import('./sign.mjs');
const kitDrift = await import('./drift.mjs');

const hex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');
const utf8 = (s: string) => new TextEncoder().encode(s);
const sha256hex = (b: Buffer | Uint8Array | string) => createHash('sha256').update(b).digest('hex');

function assertEq(actual: unknown, expected: unknown, label: string): void {
  if (actual !== expected) {
    throw new Error(`generation assert failed: ${label}\n  actual:   ${String(actual)}\n  expected: ${String(expected)}`);
  }
}

// ── 1. canonical-accept (21) — re-verified against BOTH oracles ─────────
const existing = JSON.parse(
  readFileSync(path.join(REPO_ROOT, 'vectors/canonical-form/canonical-form-vectors.json'), 'utf8'),
) as { acceptVectors: Array<{ id: string; description: string; input: unknown; canonicalUtf8Hex: string; expectedSha256: string }>; rejectVectors: Array<{ id: string; description: string; reason: string }> };

const acceptVectors = existing.acceptVectors.map((v) => {
  assertEq(srcJcsHashHex(v.input), v.expectedSha256, `src oracle hash for accept "${v.id}"`);
  assertEq(hex(srcJcsCanonical(v.input)), v.canonicalUtf8Hex, `src oracle canonical bytes for accept "${v.id}"`);
  assertEq(kitJcs.jcsHashHex(v.input), v.expectedSha256, `kit hash for accept "${v.id}"`);
  assertEq(hex(kitJcs.jcsCanonical(v.input)), v.canonicalUtf8Hex, `kit canonical bytes for accept "${v.id}"`);
  return { id: `ca-${v.id}`, section: 'canonical-accept', description: v.description,
    input: v.input, canonicalUtf8Hex: v.canonicalUtf8Hex, expectedSha256: v.expectedSha256 };
});
// 22, not 21: 'nfc-key-collision' moved reject -> accept as 'nfc-nfd-key-pair-distinct'.
// Member names are no longer NFC-normalised (CF-1 covers string VALUES only), so an
// NFC/NFD name pair cannot collide and is a valid two-member object. See #270.
assertEq(acceptVectors.length, 22, 'canonical-accept count');

// ── 2. canonical-reject (5) — both oracles must reject each constructor ─
const rejectVectors = rejectCases.map((c) => {
  let srcRejected = false, kitRejected = false;
  try { srcJcsCanonical(c.build()); } catch { srcRejected = true; }
  try { kitJcs.jcsCanonical(c.build()); } catch { kitRejected = true; }
  assertEq(srcRejected, true, `src oracle rejects "${c.id}"`);
  assertEq(kitRejected, true, `kit rejects "${c.id}"`);
  return { id: `cr-${c.id}`, section: 'canonical-reject', description: c.description,
    constructorId: c.id, reason: c.reason };
});
assertEq(rejectVectors.length, 5, 'canonical-reject count (was six; nfc-key-collision moved to accept — see the accept-count note above)');

// ── 3. domain-sep-sign (12) ─────────────────────────────────────────────
// Deterministic, publicly-derivable TEST keys (sha256 of a published label — NOT secrets).
const TEST_KEY_LABEL_1 = 'pathos-dacs-partner-kit deterministic TEST key #1 — NOT A SECRET';
const TEST_KEY_LABEL_2 = 'pathos-dacs-partner-kit deterministic TEST key #2 — NOT A SECRET';
const priv1 = new Uint8Array(createHash('sha256').update(TEST_KEY_LABEL_1).digest());
const priv2 = new Uint8Array(createHash('sha256').update(TEST_KEY_LABEL_2).digest());
const pub1 = kitSign.publicKeyFromPrivate(priv1);
const pub2 = kitSign.publicKeyFromPrivate(priv2);
// node:crypto and @noble/ed25519 must agree on key derivation (cross-impl check #0).
assertEq(hex(pub1), hex(ed25519.getPublicKey(priv1)), 'pub1 derivation: node:crypto == @noble/ed25519');
assertEq(hex(pub2), hex(ed25519.getPublicKey(priv2)), 'pub2 derivation: node:crypto == @noble/ed25519');

const S1_BODY = 'partner-kit sign vector S1 body (dacs-bundle roundtrip)';
const s1Sig = srcSign(DOMAIN_SEPARATORS.BUNDLE, utf8(S1_BODY), priv1);
const S9_INTER = new Uint8Array(createHash('sha256').update('partner-kit session-key intermediate').digest());
const s9Sig = srcSign(DOMAIN_SEPARATORS.SESSION_BINDING, utf8('composite body'), priv1, S9_INTER);
const s7Sig = srcSign(DACS_X_EXTENSION_SEPARATORS.CLAIM_COMMIT, utf8('dacs-x claim commit body'), priv2);
const s8Sig = srcSign(PATHOS_EXTENSION_SEPARATORS.CROSS_VPS_ATTESTATION, utf8('abc123responsehash'), priv2);
// Legacy READ separator: construct a pre-cutover-style signature directly (src sign() rightly
// refuses to emit under it — that refusal is vector S6). @noble sha512Sync is wired by the
// src/lib/sign.ts import above.
const legacySignedBytes = srcBuildSignedBytes(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, utf8('legacy bundle body'));
const legacySig = ed25519.sign(legacySignedBytes, priv1);
const tamperedSig = new Uint8Array(s1Sig); tamperedSig[0] ^= 0xff;
const s12Inter = new Uint8Array(createHash('sha256').update('golden intermediate').digest());
const s12Expected = hex(srcBuildSignedBytes(DOMAIN_SEPARATORS.BUNDLE, utf8('golden'), s12Inter));

const signVectors = [
  { id: 'ds-s1-bundle-roundtrip', op: 'sign-roundtrip', separatorRef: 'DOMAIN_SEPARATORS.BUNDLE',
    description: 'sign+verify roundtrip under dacs-bundle:v1: — signature must equal the reference-generated one (cross-impl ed25519 determinism)',
    bodyUtf8: S1_BODY, privKeyHex: hex(priv1), pubKeyHex: hex(pub1), expectedSigHex: hex(s1Sig), derivedPubMustMatch: true },
  { id: 'ds-s2-wrong-separator-false', op: 'verify-false', separatorRef: 'DOMAIN_SEPARATORS.REPUTATION_ATTESTATION',
    description: 'a valid dacs-bundle signature MUST NOT verify under a different registered separator (domain separation is load-bearing)',
    bodyUtf8: S1_BODY, pubKeyHex: hex(pub1), sigHex: hex(s1Sig) },
  { id: 'ds-s3-unknown-separator-sign-throws', op: 'sign-must-throw', rawSeparator: 'dacs-unregistered:v1:',
    description: 'sign() MUST refuse a separator outside the §B.7 closed registry (SIG-1..4 closure)',
    bodyUtf8: 'any body', privKeyHex: hex(priv1) },
  { id: 'ds-s4-unknown-separator-verify-false', op: 'verify-unknown-separator-false', rawSeparator: 'dacs-unregistered:v1:',
    description: 'verify() MUST return false (not throw) on an unknown separator',
    bodyUtf8: S1_BODY, pubKeyHex: hex(pub1), sigHex: hex(s1Sig) },
  { id: 'ds-s5-legacy-read-verifies', op: 'verify-true', separatorRef: 'LEGACY_READ_SEPARATORS.BUNDLE_DACS5',
    description: 'a pre-cutover artifact sealed under dacs5-bundle:v1: MUST still verify (§10.4.2 backwards-compatible READ)',
    bodyUtf8: 'legacy bundle body', pubKeyHex: hex(pub1), sigHex: hex(legacySig) },
  { id: 'ds-s6-legacy-emission-refused', op: 'sign-must-throw', separatorRef: 'LEGACY_READ_SEPARATORS.BUNDLE_DACS5',
    description: 'sign() MUST refuse to EMIT under a read-only legacy separator (emission closure)',
    bodyUtf8: 'legacy bundle body', privKeyHex: hex(priv1) },
  { id: 'ds-s7-dacs-x-roundtrip', op: 'sign-roundtrip', separatorRef: 'DACS_X_EXTENSION_SEPARATORS.CLAIM_COMMIT',
    description: 'SIG-4 dacs-x extension separator signs and verifies like a registry entry',
    bodyUtf8: 'dacs-x claim commit body', privKeyHex: hex(priv2), pubKeyHex: hex(pub2), expectedSigHex: hex(s7Sig) },
  { id: 'ds-s8-pathos-ext-roundtrip', op: 'sign-roundtrip', separatorRef: 'PATHOS_EXTENSION_SEPARATORS.CROSS_VPS_ATTESTATION',
    description: 'PATH-OS Labs extension separator (non-normative sibling map) signs and verifies',
    bodyUtf8: 'abc123responsehash', privKeyHex: hex(priv2), pubKeyHex: hex(pub2), expectedSigHex: hex(s8Sig) },
  { id: 'ds-s9-composite-intermediate', op: 'sign-roundtrip', separatorRef: 'DOMAIN_SEPARATORS.SESSION_BINDING',
    description: 'composite form: signed_bytes = sep || intermediateHash || body (§6.3.2 session binding)',
    bodyUtf8: 'composite body', intermediateHashHex: hex(S9_INTER), privKeyHex: hex(priv1), pubKeyHex: hex(pub1), expectedSigHex: hex(s9Sig) },
  { id: 'ds-s10-tampered-body-false', op: 'verify-false', separatorRef: 'DOMAIN_SEPARATORS.BUNDLE',
    description: 'tampered body MUST NOT verify',
    bodyUtf8: S1_BODY + ' (tampered)', pubKeyHex: hex(pub1), sigHex: hex(s1Sig) },
  { id: 'ds-s11-tampered-sig-false', op: 'verify-false', separatorRef: 'DOMAIN_SEPARATORS.BUNDLE',
    description: 'tampered signature MUST NOT verify',
    bodyUtf8: S1_BODY, pubKeyHex: hex(pub1), sigHex: hex(tamperedSig) },
  { id: 'ds-s12-signed-bytes-golden', op: 'signed-bytes-golden', separatorRef: 'DOMAIN_SEPARATORS.BUNDLE',
    description: 'byte-exact signed_bytes layout: sep || intermediateHash || body',
    bodyUtf8: 'golden', intermediateHashHex: hex(s12Inter), expectedSignedBytesHex: s12Expected },
].map((v) => ({ ...v, section: 'domain-sep-sign' }));
assertEq(signVectors.length, 12, 'domain-sep-sign count');

// Reference-side sanity on the sign vectors before writing (kit re-checks at run time):
assertEq(srcVerify(DOMAIN_SEPARATORS.BUNDLE, s1Sig, utf8(S1_BODY), pub1), true, 'src verifies S1');
assertEq(srcVerify(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, legacySig, utf8('legacy bundle body'), pub1), true, 'src verifies legacy S5');
assertEq(hex(kitSign.sign(DOMAIN_SEPARATORS.BUNDLE, utf8(S1_BODY), priv1)), hex(s1Sig), 'kit reproduces S1 signature (node:crypto == @noble)');

// ── 4. drift-signed-scope (10) — kit rows asserted against the reference evaluator ─
const bundle0004 = JSON.parse(readFileSync(path.join(REPO_ROOT, 'test/vectors/dacs-x-fixtures/attestation-bundle-0004.json'), 'utf8'));
const goldenBundleHash = srcBundleSignedScopeHashV1(bundle0004);
assertEq(kitDrift.bundleSignedScopeHashV1(bundle0004), goldenBundleHash, 'kit reproduces the R5-1 signed-scope hash');

// jobId is a free string: mutating it keeps the bundle structurally valid in BOTH
// evaluators (outcome is enum-constrained in the reference) while changing the hash.
const driftedBundle = structuredClone(bundle0004); driftedBundle.jobId = bundle0004.jobId + '-MUTATED';
const structFailBundle = { bundleVersion: '1', outcome: 'completed' }; // no jobId, no parties
const settlementGolden = { evidenceVersion: '1', jobId: 'pk-settle-1', outcome: 'completed',
  amount: '42', rail: 'demos-testnet', signature: 'stripped-from-signed-scope' };
const goldenEvidenceHash = srcJcsHashHex((({ signature: _s, ...rest }) => rest)(settlementGolden));
const settlementDrift = { ...settlementGolden, amount: '43' };
const settlementStructFail = { evidenceVersion: '1', amount: '42' }; // no jobId
const nonDacs = { hello: 'world', note: 'neither bundleVersion nor evidenceVersion' };
const ZEROS64 = '0'.repeat(64);

type DriftSpec = { id: string; description: string; artifact: unknown; fixtureName: string;
  expectedHash?: string; expectRow: Record<string, unknown> };
const driftEvaluateSpecs: DriftSpec[] = [
  { id: 'dr-d1-bundle-golden-match', fixtureName: 'attestation-bundle-0004.json', artifact: bundle0004, expectedHash: goldenBundleHash,
    description: 'real reference fixture reproduces its R5-1 signed-scope bundleHash (match)',
    expectRow: { hashStatus: 'match', structurallyValid: true, decision: 'accept', ourHash: goldenBundleHash } },
  { id: 'dr-d2-bundle-drift-detected', fixtureName: 'attestation-bundle-0004-mutated.json', artifact: driftedBundle, expectedHash: goldenBundleHash,
    description: 'a mutated bundle against the golden expected hash MUST report drift',
    expectRow: { hashStatus: 'drift', structurallyValid: true, decision: 'accept' } },
  { id: 'dr-d3-bundle-struct-fail', fixtureName: 'broken-bundle.json', artifact: structFailBundle,
    description: 'a bundleVersion file missing jobId/parties MUST be structurally rejected',
    expectRow: { structurallyValid: false, decision: 'reject', hashStatus: 'computed' } },
  { id: 'dr-d4-settlement-golden-match', fixtureName: 'settlement-golden.json', artifact: settlementGolden, expectedHash: goldenEvidenceHash,
    description: 'DACS-4 evidenceHash = sha256(JCS(evidence minus signature)) reproduces (match)',
    expectRow: { hashStatus: 'match', structurallyValid: true, decision: 'accept', kind: 'settlement', ourHash: goldenEvidenceHash } },
  { id: 'dr-d5-settlement-drift', fixtureName: 'settlement-mutated.json', artifact: settlementDrift, expectedHash: goldenEvidenceHash,
    description: 'a mutated settlement evidence against the golden expected hash MUST report drift',
    expectRow: { hashStatus: 'drift', structurallyValid: true, decision: 'accept', kind: 'settlement' } },
  { id: 'dr-d6-settlement-struct-fail', fixtureName: 'settlement-broken.json', artifact: settlementStructFail,
    description: 'a SettlementEvidence missing jobId MUST be structurally rejected',
    expectRow: { structurallyValid: false, decision: 'reject' } },
  { id: 'dr-d7-non-dacs-skipped', fixtureName: 'not-dacs.json', artifact: nonDacs,
    description: 'a non-DACS JSON file in discovery mode is SKIPPED, never a failure',
    expectRow: { hashStatus: 'skipped', structurallyValid: true, decision: 'skipped' } },
  { id: 'dr-d8-non-dacs-expected-fails-closed', fixtureName: 'not-dacs.json', artifact: nonDacs, expectedHash: ZEROS64,
    description: 'a manifest-expected hash on a non-DACS file MUST fail closed (cannot verify ⇒ reject)',
    expectRow: { structurallyValid: false, decision: 'reject' } },
];
// PARITY RECEIPT: the kit evaluator must agree with the reference evaluator row-for-row.
const PARITY_FIELDS = ['hashStatus', 'structurallyValid', 'decision', 'ourHash', 'expected'] as const;
const parityRows: Array<Record<string, unknown>> = [];
for (const spec of driftEvaluateSpecs) {
  const ref = srcEvaluateArtifact(spec.artifact, spec.fixtureName, spec.expectedHash ?? null) as unknown as Record<string, unknown>;
  const kit = kitDrift.evaluateArtifact(spec.artifact, spec.fixtureName, spec.expectedHash ?? null) as Record<string, unknown>;
  for (const f of PARITY_FIELDS) {
    assertEq(kit[f], ref[f], `drift parity "${spec.id}" field ${f} (kit vs reference evaluator)`);
  }
  parityRows.push({ id: spec.id, fixture: spec.fixtureName,
    reference: Object.fromEntries(PARITY_FIELDS.map((f) => [f, ref[f]])) });
}

const driftVectors: Array<Record<string, unknown>> = [
  ...driftEvaluateSpecs.map((s) => ({ id: s.id, section: 'drift-signed-scope', op: 'evaluate',
    description: s.description, fixtureName: s.fixtureName, artifact: s.artifact,
    ...(s.expectedHash ? { expectedHash: s.expectedHash } : {}), expectRow: s.expectRow })),
  { id: 'dr-d9-expected-but-missing', section: 'drift-signed-scope', op: 'summarise-missing',
    description: 'a manifest entry with no matching fixture MUST fail the run (expected-but-missing)',
    artifacts: { 'attestation-bundle-0004.json': bundle0004 },
    manifest: { 'attestation-bundle-0004.json': goldenBundleHash, 'missing-fixture.json': ZEROS64 },
    expectMissingCount: 1, expectFailClosed: true },
  { id: 'dr-d10-malformed-manifest-throws', section: 'drift-signed-scope', op: 'manifest-must-throw',
    description: 'a manifest with a non-sha256 value MUST be refused up front (fail-closed), never read as drift',
    manifest: { 'x.json': 'not-a-hash' } },
];
assertEq(driftVectors.length, 10, 'drift-signed-scope count');

// ── 5. Assemble vectors.json (declaredTotal MUST be 49) ─────────────────
const vectors = [...acceptVectors, ...rejectVectors, ...signVectors, ...driftVectors];
assertEq(vectors.length, 49, 'declared vector total');
const ids = new Set(vectors.map((v) => v.id));
assertEq(ids.size, 49, 'vector ids are unique');

const vectorsDoc = {
  name: 'pathos-dacs partner-kit conformance vectors',
  nonNormative: 'NON-NORMATIVE sanity vectors extracted from pathos-dacs-ref. Passing them is NOT a DACS certification; the normative source is the DACS specification (KyneSys Labs / Demos Network).',
  declaredTotal: 49,
  // 22/5, not 21/6: nfc-key-collision moved reject -> accept (see the count guards above).
  // The TOTAL is 49 either way, which is why declaredTotal alone did not catch the drift.
  sections: { 'canonical-accept': 22, 'canonical-reject': 5, 'domain-sep-sign': 12, 'drift-signed-scope': 10 },
  testKeyNote: `privKeyHex values are deterministic PUBLIC test vectors: sha256("${TEST_KEY_LABEL_1}") and sha256("${TEST_KEY_LABEL_2}"). Not secrets. Never use outside these vectors.`,
  vectors,
};
writeFileSync(path.join(KIT_DIR, 'vectors.json'), JSON.stringify(vectorsDoc, null, 2) + '\n');

// ── 6. MANIFEST.json — per-file hashes + provenance + receipts ──────────
const git = (...args: string[]) => execFileSync('git', args, { cwd: REPO_ROOT }).toString().trim();
const sourceCommit = git('rev-parse', 'HEAD');
const branch = git('rev-parse', '--abbrev-ref', 'HEAD');

const SOURCE_FILES = [
  'src/jcs.ts', 'src/domain-sep.ts', 'src/lib/sign.ts', 'src/lib/dacs-drift.ts',
  'src/lib/bundle-signed-scope-v1.ts', 'dacs-drift.mts',
  'vectors/canonical-form/canonical-form-vectors.json', 'vectors/canonical-form/cases.ts',
  'test/vectors/dacs-x-fixtures/attestation-bundle-0004.json',
];
// Cleanliness MUST cover exactly the files provenance.sourceFiles vouches for — a broader
// dir pathspec that misses one of them would let sourceTreeClean:true sit next to a hash
// the sourceCommit doesn't contain (Claude peer review 2026-07-10, finding #1).
const dirtySrc = git('status', '--porcelain', '--', ...SOURCE_FILES);
const KIT_FILES = ['jcs.mjs', 'domain-sep.mjs', 'sign.mjs', 'drift.mjs', 'run-conformance.mjs',
  'vectors.json', 'README.md', 'LICENSE', 'generate.mts'];

const manifest: Record<string, unknown> = {
  kit: {
    name: 'pathos-dacs partner kit',
    version: '1.0.0',
    license: 'MIT',
    nonNormative: 'This kit is a NON-NORMATIVE conformance sanity kit. Passing its 49 vectors means this environment reproduces pathos-dacs-ref reference behavior on the covered surfaces only — it is NOT a full DACS conformance certification.',
    attribution: 'DACS — Demos Agent Commerce Standards — is specified upstream by KyneSys Labs / the Demos Network project. RFC 8785 (JCS) is an IETF specification. Reference signatures were generated via @noble/ed25519 (MIT); the in-repo canonicalization oracle uses the canonicalize npm package (Apache-2.0, not vendored here).',
  },
  files: Object.fromEntries(KIT_FILES.map((f) => [f, sha256hex(readFileSync(path.join(KIT_DIR, f)))])),
  provenance: {
    repository: 'pathos-dacs-ref',
    branch,
    sourceCommit,
    sourceTreeClean: dirtySrc === '',
    sourceFiles: Object.fromEntries(SOURCE_FILES.map((f) => [f, sha256hex(readFileSync(path.join(REPO_ROOT, f)))])),
    generatedAt: new Date().toISOString(),
    generatorCommand: 'npx tsx conformance/partner-kit/generate.mts',
  },
  parityReceipt: {
    note: 'kit drift evaluator vs reference evaluator (src/lib/dacs-drift.ts + verifyBundleV1, requireSignatures:false), compared on ' + PARITY_FIELDS.join('/'),
    rows: parityRows,
  },
  receipt: null,
};
const manifestPath = path.join(KIT_DIR, 'MANIFEST.json');
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

// ── 7. Self-run receipt: the kit must pass 49/49, twice ─────────────────
function selfRun(): { exitCode: number; report: { declared: number; executed: number; passed: number; failed: number; countOk: boolean } } {
  let out = ''; let exitCode = 0;
  try {
    out = execFileSync('node', ['run-conformance.mjs', '--json'], { cwd: KIT_DIR }).toString();
  } catch (e) {
    const err = e as { status?: number; stdout?: Buffer };
    exitCode = err.status ?? 1;
    out = err.stdout?.toString() ?? '';
  }
  return { exitCode, report: JSON.parse(out) };
}

const run1 = selfRun();
assertEq(run1.exitCode, 0, 'self-run exit code');
assertEq(run1.report.passed, 49, 'self-run passed count');
assertEq(run1.report.countOk, true, 'self-run declared/executed == 49');

(manifest as { receipt: unknown }).receipt = {
  command: 'node run-conformance.mjs --json  (cwd: conformance/partner-kit)',
  ranAt: new Date().toISOString(),
  exitCode: run1.exitCode,
  result: { declared: run1.report.declared, executed: run1.report.executed,
    passed: run1.report.passed, failed: run1.report.failed },
};
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

const run2 = selfRun(); // MANIFEST.receipt changed; MANIFEST is not self-hashed, so still green
assertEq(run2.exitCode, 0, 'confirmation re-run exit code');
(manifest as { receipt: { confirmedOnRerun?: boolean } }).receipt.confirmedOnRerun = true;
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

console.log(`✅ partner-kit generated: 49/49 vectors green (self-run twice) · source ${sourceCommit.slice(0, 12)} · srcClean=${dirtySrc === ''}`);
