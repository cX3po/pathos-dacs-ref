/**
 * conformance/shared-suite/seed-corpus.mjs — loads the seed corpus declared in ADAPTER.md
 * ("Seed corpus" section) and normalises each raw vector into the generic shape `crossRun()`
 * (in `adapter-contract.mjs`) consumes:
 *
 *   { id, family, fnName, description, expected, invoke(adapter) -> string }
 *
 * `invoke` NEVER throws — it calls the named adapter function and normalises the result (or
 * a thrown error) to a comparable string ('THROWN' / 'ACCEPTED' / 'DID-NOT-THROW' / a lowercase
 * hex string / 'true' | 'false' / 'ACCEPT' | 'REJECT'). That keeps `crossRun()` fully generic:
 * it never needs to know what a "sig-value-encoding" vector or a "domain-sep-sign" vector
 * looks like, only that adapter output === vector.expected.
 *
 * Sources (read-only, never mutated):
 *  - ../partner-kit/vectors.json        — 49 declared vectors (canonical-accept/reject,
 *                                          domain-sep-sign, drift-signed-scope)
 *  - ../vectors/dacs-263-sig-value-encoding-v1.json — SIG-6 (3 encodings -> 3 sub-vectors)
 *
 * HONEST SCOPE NOTE: not every raw vector maps to a family function declared in ADAPTER.md.
 * Those are collected in `outOfScope` (never silently dropped) with a reason each:
 *  - `domain-sep-sign` op `signed-bytes-golden` (ds-s12) tests the raw `signed_bytes` byte
 *    layout (`buildSignedBytes`), which F5 does not expose (F5 is sign/verify only).
 *  - `drift-signed-scope` vectors other than the two "golden-match" ones (dr-d1 bundle,
 *    dr-d4 settlement) exercise the FULL `evaluateArtifact`/`evaluateBundle` pipeline —
 *    structural validation, drift-vs-golden classification, skip/manifest-fail-closed
 *    semantics — which is broader than F2's declared scope ("sha256 over the signed scope").
 *    Using their `expectedHash` field as an F2 "expected" would be a category error: for the
 *    two "drift" vectors (dr-d2, dr-d5) that field is the ORIGINAL golden hash, not the true
 *    signed-scope hash of the (deliberately mutated) artifact under test — asserting the two
 *    should be equal would fail a CORRECT adapter. A future `bundle-verify`-shaped family
 *    (see the F4 note in reference-adapter.mjs) is the right home for that fuller surface.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS,
  DACS_X_EXTENSION_SEPARATORS, PATHOS_EXTENSION_SEPARATORS,
} from '../partner-kit/domain-sep.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const utf8 = (s) => new TextEncoder().encode(s);
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

const SEP_MAPS = { DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS, DACS_X_EXTENSION_SEPARATORS, PATHOS_EXTENSION_SEPARATORS };
function sepByRef(ref) {
  const [map, key] = ref.split('.');
  const v = SEP_MAPS[map]?.[key];
  if (!v) throw new Error(`unknown separator ref: ${ref}`);
  return v;
}

// The 6 canonical reject constructors (§B.2 foot-guns) — identical to
// partner-kit/run-conformance.mjs's REJECT_CONSTRUCTORS. These BUILD malformed test inputs
// (BigInt, lone surrogate, precise unsafe integers aren't always faithfully JSON-serialisable
// as vector data); they are not a reimplementation of jcs.mjs itself.
const NFC_CAFE = 'café';   // c a f + U+00E9 (precomposed)
const NFD_CAFE = 'café';  // c a f e + U+0301 (combining acute)
const REJECT_CONSTRUCTORS = {
  'number-over-2pow53': () => ({ big: 9007199254740992 }),
  'number-large-magnitude-over-range': () => ({ n: 1e300 }),
  'number-exponent-over-range': () => ({ n: 1e21 }),
  'lone-surrogate': () => ({ s: '\uD800' }),
  'bigint': () => ({ b: BigInt(1) }),
  'nfc-key-collision': () => { const o = {}; o[NFC_CAFE] = 1; o[NFD_CAFE] = 2; return o; },
};

function loadPinnedSource(source) {
  const bytes = readFileSync(path.join(HERE, source.path));
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== source.sha256) {
    throw new Error(`pinned source hash mismatch for ${source.path}: expected ${source.sha256}, got ${actual}`);
  }
  const parsed = JSON.parse(bytes.toString('utf8'));
  const declared = parsed.declaredTotal ?? Object.keys(parsed.encodings ?? {}).length;
  if (declared !== source.declared) {
    throw new Error(`pinned source count mismatch for ${source.path}: expected ${source.declared}, got ${declared}`);
  }
  return parsed;
}

function loadDomainSepVectors(v, vectors, outOfScope) {
  const body = utf8(v.bodyUtf8);
  const inter = v.intermediateHashHex ? unhex(v.intermediateHashHex) : undefined;
  const sep = v.separatorRef ? sepByRef(v.separatorRef) : v.rawSeparator;

  if (v.op === 'sign-roundtrip') {
    const priv = unhex(v.privKeyHex);
    vectors.push({
      id: v.id, family: 'domain-sep-sign', fnName: 'domainSepSign', description: v.description,
      expected: v.expectedSigHex.toLowerCase(),
      invoke: async (adapter) => {
        try { return String((await adapter.domainSepSign(body, sep, priv, inter)).hex).toLowerCase(); }
        catch { return 'THROWN'; }
      },
    });
    return;
  }
  if (v.op === 'verify-true' || v.op === 'verify-false' || v.op === 'verify-unknown-separator-false') {
    const sig = unhex(v.sigHex);
    const pub = unhex(v.pubKeyHex);
    vectors.push({
      id: v.id, family: 'domain-sep-sign', fnName: 'domainSepVerify', description: v.description,
      expected: v.op === 'verify-true' ? 'true' : 'false',
      invoke: async (adapter) => {
        try { return String(await adapter.domainSepVerify(body, sep, sig, pub, inter)); }
        catch { return 'THROWN'; }
      },
    });
    return;
  }
  if (v.op === 'sign-must-throw') {
    const priv = v.privKeyHex ? unhex(v.privKeyHex) : new Uint8Array(32);
    vectors.push({
      id: v.id, family: 'domain-sep-sign', fnName: 'domainSepSign', description: v.description,
      expected: 'THROWN',
      invoke: async (adapter) => {
        try { await adapter.domainSepSign(body, sep, priv, inter); return 'DID-NOT-THROW'; }
        catch { return 'THROWN'; }
      },
    });
    return;
  }
  if (v.op === 'signed-bytes-golden') {
    outOfScope.push({
      id: v.id, section: v.section,
      reason: 'tests buildSignedBytes (raw signed_bytes layout) — F5 only declares sign/verify, not a byte-layout function; a future family could add it without breaking existing adapters',
    });
    return;
  }
  outOfScope.push({ id: v.id, section: v.section, reason: `unrecognised domain-sep-sign op "${v.op}"` });
}

function loadDriftVector(v, vectors, outOfScope) {
  const isGoldenMatch = v.op === 'evaluate' && v.artifact && v.expectRow
    && v.expectRow.hashStatus === 'match' && typeof v.expectRow.ourHash === 'string';
  if (isGoldenMatch) {
    vectors.push({
      id: v.id, family: 'drift-signed-scope', fnName: 'signedScopeHash', description: v.description,
      expected: v.expectRow.ourHash.toLowerCase(),
      invoke: async (adapter) => {
        try { return String((await adapter.signedScopeHash(v.artifact)).hex).toLowerCase(); }
        catch { return 'THROWN'; }
      },
    });
    return;
  }
  outOfScope.push({
    id: v.id, section: v.section,
    reason: 'exercises the full evaluateArtifact/evaluateBundle pipeline (structural validation, drift classification, skip/manifest fail-closed semantics) beyond F2\'s narrow "sha256 over the signed scope" — see file header',
  });
}

/**
 * @returns {{ vectors: Array<{id:string,family:string,fnName:string,description:string,expected:string,invoke:(adapter:object)=>string}>, outOfScope: Array<{id:string,section:string,reason:string}>, sourceFiles: {partnerKit:string,sig6:string} }}
 */
export function loadSeedCorpus() {
  const sourceLock = JSON.parse(readFileSync(path.join(HERE, 'PINNED-SOURCES.json'), 'utf8'));
  const partnerKit = loadPinnedSource(sourceLock.sources.partnerKit);
  const sig6 = loadPinnedSource(sourceLock.sources.sig6);

  const vectors = [];
  const outOfScope = [];

  for (const v of partnerKit.vectors) {
    switch (v.section) {
      case 'canonical-accept':
        vectors.push({
          id: v.id, family: 'canonical-accept', fnName: 'canonicalize', description: v.description,
          expected: v.canonicalUtf8Hex.toLowerCase(),
          invoke: async (adapter) => {
            try { return String((await adapter.canonicalize(v.input)).hex).toLowerCase(); }
            catch { return 'THROWN'; }
          },
        });
        break;
      case 'canonical-reject': {
        const build = REJECT_CONSTRUCTORS[v.constructorId];
        if (!build) {
          outOfScope.push({ id: v.id, section: v.section, reason: `no reject constructor registered for "${v.constructorId}"` });
          break;
        }
        vectors.push({
          id: v.id, family: 'canonical-reject', fnName: 'canonicalize', description: v.description,
          expected: 'THROWN',
          invoke: async (adapter) => {
            try { await adapter.canonicalize(build()); return 'ACCEPTED'; }
            catch { return 'THROWN'; }
          },
        });
        break;
      }
      case 'domain-sep-sign':
        loadDomainSepVectors(v, vectors, outOfScope);
        break;
      case 'drift-signed-scope':
        loadDriftVector(v, vectors, outOfScope);
        break;
      default:
        outOfScope.push({ id: v.id, section: v.section, reason: `unrecognised section "${v.section}"` });
    }
  }

  // SIG-6 (dacs-263): one source file, 3 declared cases -> 3 executed operations. The
  // source's standard-Base64 migration case is routed only to the explicit legacy-import
  // operation, with its source encoding supplied out of band. It never reaches F3.
  for (const [name, e] of Object.entries(sig6.encodings)) {
    if (name === 'canonical_base64') {
      vectors.push({
        id: `${sig6.id}::${name}`, family: 'sig-value-legacy-import', fnName: 'legacySignatureValueImport',
        description: `${sig6.purpose} (explicit migration import; source encoding: base64)`,
        expected: e.expect,
        invoke: async (adapter) => {
          try { return (await adapter.legacySignatureValueImport(e.value, 'base64')).verdict; }
          catch { return 'THROWN'; }
        },
      });
      continue;
    }
    vectors.push({
      id: `${sig6.id}::${name}`, family: 'sig-value-encoding', fnName: 'signatureValueVerdict',
      description: `${sig6.purpose} (encoding: ${name})`,
      expected: e.expect,
      invoke: async (adapter) => {
        try { return await adapter.signatureValueVerdict(e.value); }
        catch { return 'THROWN'; }
      },
    });
  }

  return {
    vectors, outOfScope,
    sourceFiles: {
      lock: './PINNED-SOURCES.json',
      partnerKit: sourceLock.sources.partnerKit.path,
      sig6: sourceLock.sources.sig6.path,
    },
    sourceCounts: {
      partnerKitDeclared: partnerKit.declaredTotal,
      sig6DeclaredCases: Object.keys(sig6.encodings).length,
      executedAssertions: vectors.length,
      partnerKitNotExecuted: outOfScope.length,
      f4Declared: 0,
      f4Executed: 0,
    },
  };
}
