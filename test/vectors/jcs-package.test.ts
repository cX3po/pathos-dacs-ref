import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import {
  DOMAIN_SEPARATORS,
  generateKeypair,
  jcsCanonical as packageCanonical,
  jcsHashHex as packageHashHex,
  sign,
  verify,
} from '../../packages/jcs/dist/index.js';
import { jcsCanonical as sourceCanonical, jcsHashHex as sourceHashHex } from '../../src/jcs.js';

type Vector = {
  id: string;
  section: string;
  input?: unknown;
  canonicalUtf8Hex?: string;
  expectedSha256?: string;
  constructorId?: string;
};

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const packageRoot = join(repoRoot, 'packages', 'jcs');
const vectorPath = join(packageRoot, 'vectors', 'canonical-form-v0.1.json');
const vectorDocument = JSON.parse(await readFile(vectorPath, 'utf8')) as { vectors: Vector[] };
const canonicalVectors = vectorDocument.vectors.filter((vector) => vector.section.startsWith('canonical-'));

async function packageFiles(path: string, prefix = ''): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const relativePath = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) result.push(...await packageFiles(join(path, entry.name), relativePath));
    else if (entry.isFile()) result.push(relativePath);
  }
  return result;
}

function rejectedInput(constructorId: string): unknown {
  switch (constructorId) {
    case 'number-over-2pow53': return { n: Number.MAX_SAFE_INTEGER + 1 };
    case 'number-large-magnitude-over-range': return { n: 1e300 };
    case 'number-exponent-over-range': return { n: 1e21 };
    case 'lone-surrogate': return JSON.parse('{"s":"\\ud800"}');
    case 'bigint': return { n: 1n };
    default: throw new Error(`Unknown canonical reject constructor: ${constructorId}`);
  }
}

test('built package matches src byte-for-byte on every canonical-form vector', () => {
  assert.equal(canonicalVectors.length, 27);
  for (const vector of canonicalVectors) {
    if (vector.section === 'canonical-accept') {
      assert.ok('input' in vector);
      const packageBytes = packageCanonical(vector.input);
      const sourceBytes = sourceCanonical(vector.input);
      assert.deepEqual(packageBytes, sourceBytes, vector.id);
      assert.equal(packageHashHex(vector.input), sourceHashHex(vector.input), vector.id);
      assert.equal(Buffer.from(packageBytes).toString('hex'), vector.canonicalUtf8Hex, vector.id);
      assert.equal(packageHashHex(vector.input), vector.expectedSha256, vector.id);
    } else {
      assert.ok(vector.constructorId);
      const input = rejectedInput(vector.constructorId);
      assert.throws(() => sourceCanonical(input), vector.id);
      assert.throws(() => packageCanonical(input), vector.id);
    }
  }
});

test('packaged NFC/NFD cases enforce values-only CF-1 normalization', () => {
  const byId = new Map(canonicalVectors.map((vector) => [vector.id, vector]));
  const nfcValue = byId.get('ca-nfc-precomposed')!;
  const nfdValue = byId.get('ca-nfd-decomposed')!;
  assert.deepEqual(packageCanonical(nfdValue.input), packageCanonical(nfcValue.input));

  const nfcKey = byId.get('ca-unicode-key-nfc')!;
  const nfdKey = byId.get('ca-unicode-key-nfd')!;
  assert.notDeepEqual(packageCanonical(nfdKey.input), packageCanonical(nfcKey.input));
  const nfdKeyText = new TextDecoder().decode(packageCanonical(nfdKey.input));
  assert.ok(nfdKeyText.includes('cafe\u0301'));
  assert.ok(!nfdKeyText.includes('caf\u00e9'));
});

test('package signing round-trips only with registered emission separators', () => {
  const body = packageCanonical({ package: '@pathos-labs/dacs-jcs', v: 1 });
  const keypair = generateKeypair();
  const signature = sign(DOMAIN_SEPARATORS.LISTING, body, keypair.privKey);
  assert.equal(verify(DOMAIN_SEPARATORS.LISTING, signature, body, keypair.pubKey), true);
  assert.throws(() => sign('dacs-unregistered:v1:', body, keypair.privKey), /Unknown domain separator/);
  assert.equal(verify('dacs-unregistered:v1:', signature, body, keypair.pubKey), false);
});

test('package vector index describes the copied bytes', async () => {
  const index = JSON.parse(await readFile(join(packageRoot, 'vectors', 'index.json'), 'utf8')) as {
    files: Array<{ path: string; bytes: number; sha256: string; origin: { path: string; sourceSha256?: string; derived?: string } }>;
  };
  assert.equal(index.files.length, 1);
  const entry = index.files[0]!;
  const bytes = await readFile(join(packageRoot, entry.path));
  assert.equal(entry.bytes, bytes.length);
  assert.equal(entry.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(entry.origin.path, 'conformance/partner-kit/vectors.json');
  const sourceBytes = await readFile(join(repoRoot, entry.origin.path));
  assert.equal(entry.origin.sourceSha256, createHash('sha256').update(sourceBytes).digest('hex'));
  const packaged = JSON.parse(bytes.toString('utf8')) as { derivedFrom: { sha256: string; sections: string[] }; vectors: Array<Record<string, unknown>> };
  assert.equal(packaged.derivedFrom.sha256, entry.origin.sourceSha256);
  assert.deepEqual(packaged.derivedFrom.sections, ['canonical-accept', 'canonical-reject']);
  assert.deepEqual([...new Set(packaged.vectors.map((vector) => vector.section))].sort(), ['canonical-accept', 'canonical-reject']);
  assert.equal(packaged.vectors.length, 27);
  assert.equal(bytes.toString('utf8').includes('privKeyHex'), false, 'no key material in the packaged vectors');
});

test('consumer imports built ESM and canonicalizes a packaged vector', async () => {
  const consumer = await import('../../packages/jcs/dist/index.js');
  const vector = canonicalVectors.find((item) => item.id === 'ca-ascii-basic')!;
  assert.equal(Buffer.from(consumer.jcsCanonical(vector.input)).toString('hex'), vector.canonicalUtf8Hex);
});

test('deterministic package --check passes', async () => {
  await run(process.execPath, ['--import', 'tsx', 'scripts/build-jcs-package.mts', '--check'], { cwd: repoRoot });
});

test('npm dry-run pack contains exactly the declared package files', async (t) => {
  const npmCache = await mkdtemp(join(tmpdir(), 'pathos-jcs-npm-cache-'));
  try {
    let stdout = '';
    try {
      ({ stdout } = await run('npm', ['pack', '--dry-run', '--json', './packages/jcs'], {
        cwd: repoRoot,
        env: { ...process.env, npm_config_cache: npmCache },
      }));
    } catch (error) {
      t.skip(`npm pack is unavailable here: ${(error as Error).message.slice(0, 120)}`);
      return;
    }
    assert.ok(stdout.trim().length > 0, 'npm pack --json produced no output');
    const actual = (JSON.parse(stdout) as Array<{ files: Array<{ path: string }> }>)[0]!.files.map((file) => file.path).sort();
    const expected = [
      'LICENSE',
      'NOTICE',
      'README.md',
      'dist/domain-sep.d.ts',
      'dist/domain-sep.js',
      'dist/index.d.ts',
      'dist/index.js',
      'dist/jcs.d.ts',
      'dist/jcs.js',
      'dist/lib/sign.d.ts',
      'dist/lib/sign.js',
      'package.json',
      'provenance.json',
      'vectors/canonical-form-v0.1.json',
      'vectors/index.json',
    ].sort();
    assert.deepEqual(actual, expected);
  } finally {
    await rm(npmCache, { recursive: true, force: true });
  }
});

test('built package executes the partner-kit signing vectors (golden signatures, refusals, legacy read)', async () => {
  const pkg = await import('../../packages/jcs/dist/index.js');
  const partnerKit = JSON.parse(await readFile(join(repoRoot, 'conformance/partner-kit/vectors.json'), 'utf8')) as {
    vectors: Array<Record<string, string | boolean | undefined>>;
  };
  const signVectors = partnerKit.vectors.filter((vector) => vector.section === 'domain-sep-sign');
  assert.equal(signVectors.length, 12);
  const maps: Record<string, Record<string, string>> = {
    DOMAIN_SEPARATORS: pkg.DOMAIN_SEPARATORS as Record<string, string>,
    DACS_X_EXTENSION_SEPARATORS: pkg.DACS_X_EXTENSION_SEPARATORS as Record<string, string>,
    REVIEWED_DACS_X_EXTENSION_SEPARATORS: pkg.REVIEWED_DACS_X_EXTENSION_SEPARATORS as Record<string, string>,
    PATHOS_EXTENSION_SEPARATORS: pkg.PATHOS_EXTENSION_SEPARATORS as Record<string, string>,
    ADDITIVE_DOMAIN_SEPARATORS: pkg.ADDITIVE_DOMAIN_SEPARATORS as Record<string, string>,
    LEGACY_READ_SEPARATORS: pkg.LEGACY_READ_SEPARATORS as Record<string, string>,
  };
  const sepByRef = (ref: string): string => {
    const [map, key] = ref.split('.');
    const value = maps[map!]?.[key!];
    assert.ok(value, `unknown separator ref ${ref}`);
    return value;
  };
  const unhex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
  const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
  for (const v of signVectors) {
    const sep = typeof v.separatorRef === 'string' ? sepByRef(v.separatorRef) : undefined;
    const body = new TextEncoder().encode(String(v.bodyUtf8));
    const inter = typeof v.intermediateHashHex === 'string' ? unhex(v.intermediateHashHex) : undefined;
    const priv = typeof v.privKeyHex === 'string' ? unhex(v.privKeyHex) : undefined;
    const pub = typeof v.pubKeyHex === 'string' ? unhex(v.pubKeyHex) : undefined;
    const id = String(v.id);
    switch (v.op) {
      case 'sign-roundtrip': {
        const sig = pkg.sign(sep as never, body, priv!, inter);
        assert.equal(hex(sig), v.expectedSigHex, id);
        assert.equal(pkg.verify(sep as never, sig, body, pub!, inter), true, id);
        if (v.derivedPubMustMatch) assert.equal(hex(ed25519.getPublicKey(priv!)), v.pubKeyHex, id);
        break;
      }
      case 'verify-true':
        assert.equal(pkg.verify(sep as never, unhex(String(v.sigHex)), body, pub!, inter), true, id); break;
      case 'verify-false':
        assert.equal(pkg.verify(sep as never, unhex(String(v.sigHex)), body, pub!, inter), false, id); break;
      case 'verify-unknown-separator-false':
        assert.equal(pkg.verify(String(v.rawSeparator) as never, unhex(String(v.sigHex)), body, pub!, inter), false, id); break;
      case 'sign-must-throw':
        assert.throws(() => pkg.sign((typeof v.rawSeparator === 'string' ? v.rawSeparator : sep) as never, body, priv!, inter), id); break;
      case 'signed-bytes-golden':
        assert.equal(hex(pkg.buildSignedBytes(sep as never, body, inter)), v.expectedSignedBytesHex, id); break;
      default:
        assert.fail(`unknown sign op ${String(v.op)} in ${id}`);
    }
  }
});
