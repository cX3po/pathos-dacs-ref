/**
 * packages/verifier — the verifier as a package: stable API, CLI, HTTP service, MCP tool.
 *
 * What is proven here (no network anywhere; the chain reader is injected or the run is offline):
 *   - one implementation: the package entry re-exports the very functions src/lib exports;
 *   - the built dist is reproducible (build --check) and its bare imports are declared dependencies;
 *   - CLI (built dist, spawned), HTTP route() and MCP verify_bundle return the SAME verdict for the
 *     same bundle, and that verdict satisfies schemas/verify-verdict.schema.json;
 *   - never coerced: an unanchored bundle without offline is indeterminate; a tampered bundle fails;
 *     an unrecognised document is indeterminate; a load error is indeterminate (exit 2);
 *   - HTTP caller-side problems answer 4xx; rpc is refused as a request field; oversized bodies 413;
 *   - MCP: invalid frames, non-object params and unknown tools are structured errors, the loop survives.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { request as httpRequest } from 'node:http';
import { spawn } from 'node:child_process';
import { ed25519 } from '@noble/curves/ed25519';
import { emitAttestationBundleV1 } from '../../src/lib/emit-bundle-v1.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';
import * as doc from '../../src/lib/verify-document.js';
import * as v1 from '../../src/lib/verify-bundle-v1.js';
import * as legacy from '../../src/lib/verify-bundle.js';
import * as pkg from '../../packages/verifier/src/index.js';
import { route, MAX_BODY_BYTES, createVerifierServer } from '../../packages/verifier/src/http.js';
import { handleRequest, serve, MAX_FRAME_BYTES } from '../../packages/verifier/src/mcp.js';
import { PassThrough } from 'node:stream';

const REPO = join(import.meta.dirname ?? new URL('.', import.meta.url).pathname, '..', '..');
const PKG = join(REPO, 'packages', 'verifier');
const DIST_CLI = join(PKG, 'dist', 'packages', 'verifier', 'src', 'cli.js');
const DIST_MCP = join(PKG, 'dist', 'packages', 'verifier', 'src', 'mcp.js');
const SCHEMA_VERDICT = JSON.parse(readFileSync(join(PKG, 'schemas', 'verify-verdict.schema.json'), 'utf8'));
const SCHEMA_REQUEST = JSON.parse(readFileSync(join(PKG, 'schemas', 'verify-request.schema.json'), 'utf8'));

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };

function makeBundle(jobId = 'verifier-pkg-test-0001'): AttestationBundleV1 {
  const buyer = mk(0x31), seller = mk(0x32);
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId, outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst-fixture', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  return emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci', identifier: seller.pubHex }, privKey: seller.priv },
  ]);
}

/** Minimal JSON-Schema checker for the subset these schemas use (type, const, enum, properties, required, additionalProperties, items, minimum). */
function validate(schema: any, value: any, path = '$'): string[] {
  const errs: string[] = [];
  if ('const' in schema && value !== schema.const) errs.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${path}: not in enum`);
  if (schema.type) {
    const t = schema.type;
    const ok = t === 'object' ? (value && typeof value === 'object' && !Array.isArray(value))
      : t === 'array' ? Array.isArray(value)
      : t === 'integer' ? Number.isInteger(value)
      : typeof value === t;
    if (!ok) errs.push(`${path}: expected ${t}`);
  }
  if (schema.minimum !== undefined && typeof value === 'number' && value < schema.minimum) errs.push(`${path}: below minimum`);
  if (schema.properties && value && typeof value === 'object') {
    for (const k of schema.required ?? []) if (!(k in value)) errs.push(`${path}.${k}: required`);
    for (const [k, sub] of Object.entries<any>(schema.properties)) if (k in value) errs.push(...validate(sub, value[k], `${path}.${k}`));
    if (schema.additionalProperties === false) for (const k of Object.keys(value)) if (!(k in schema.properties)) errs.push(`${path}.${k}: additional property`);
  }
  if (schema.items && Array.isArray(value)) value.forEach((item, i) => errs.push(...validate(schema.items, item, `${path}[${i}]`)));
  return errs;
}

test('package entry re-exports the repository implementation (no second verifier)', () => {
  assert.equal(pkg.verifyDocument, doc.verifyDocument);
  assert.equal(pkg.loadBundleSource, doc.loadBundleSource);
  assert.equal(pkg.classifyBundle, doc.classifyBundle);
  assert.equal(pkg.verifyBundleV1Full, v1.verifyBundleV1Full);
  assert.equal(pkg.verifyBundle, legacy.verifyBundle);
  assert.equal(pkg.VERIFIER_API_VERSION, 'pathos-dacs-verifier:1');
  const meta = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));
  assert.equal(meta.version, pkg.PACKAGE_VERSION);
  assert.equal(meta.name, pkg.PACKAGE_NAME);
});

test('built dist is reproducible from the committed sources and imports only declared dependencies', () => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', join(REPO, 'scripts', 'build-verifier-package.mts'), '--check'], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const prov = JSON.parse(readFileSync(join(PKG, 'provenance.json'), 'utf8'));
  assert.ok(prov.compiledSources.some((s: any) => s.sourcePath === 'src/lib/verify-bundle-v1.ts'));
  assert.ok(prov.compiledSources.every((s: any) => existsSync(join(REPO, s.sourcePath)) && !s.sourcePath.startsWith('node_modules/')));
  const meta = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));
  const declared = new Set(Object.keys(meta.dependencies));
  for (const e of prov.emitted as { path: string }[]) {
    if (!e.path.endsWith('.js')) continue;
    const src = readFileSync(join(PKG, 'dist', e.path), 'utf8');
    for (const m of src.matchAll(/from '([^.\/][^']*)'/g)) {
      const spec = m[1]!;
      if (spec.startsWith('node:')) continue;
      const name = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!;
      assert.ok(declared.has(name), `undeclared dependency in dist/${e.path}: ${spec}`);
    }
  }
});

test('CLI (dist), HTTP route and MCP tool return the same verdict, and it satisfies the schema', async () => {
  const bundle = makeBundle();
  const dir = mkdtempSync(join(tmpdir(), 'dacs-verifier-'));
  try {
    const file = join(dir, 'bundle.json');
    writeFileSync(file, JSON.stringify(bundle));
    const cli = spawnSync(process.execPath, [relative(PKG, DIST_CLI), '--bundle-file', file, '--offline', '--json'], { encoding: 'utf8', cwd: PKG });
    assert.equal(cli.status, 0, cli.stderr);
    const fromCli = JSON.parse(cli.stdout);
    const http = await route('POST', '/verify', JSON.stringify({ bundle, offline: true }));
    assert.equal(http.status, 200);
    const mcp = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'verify_bundle', arguments: { bundle, offline: true } } });
    const fromMcp = JSON.parse((mcp as any).result.content[0].text);
    assert.deepEqual(fromCli, http.body);
    assert.deepEqual(fromCli, fromMcp);
    assert.equal(fromCli.verdict.decision, 'pass');
    assert.equal(fromCli.exitCode, 0);
    assert.equal(fromCli.bundleKind, 'v1');
    assert.deepEqual(validate(SCHEMA_VERDICT, fromCli), []);
    assert.deepEqual(validate(SCHEMA_REQUEST, { bundle, offline: true }), []);
    assert.ok(validate(SCHEMA_REQUEST, { bundle, rpc: 'x' }).length > 0);
    // stdin path of the CLI
    const viaStdin = spawnSync(process.execPath, [DIST_CLI, '--stdin', '--offline', '--json'], { encoding: 'utf8', input: JSON.stringify(bundle) });
    assert.equal(viaStdin.status, 0, viaStdin.stderr);
    assert.deepEqual(JSON.parse(viaStdin.stdout), fromCli);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verdicts are never coerced: unanchored, tampered, unrecognised, unloadable', async () => {
  const bundle = makeBundle();
  const noChain = (async () => null) as unknown as doc.VerifyDocumentOptions['fetchAnchoredImpl'];
  const unanchored = await doc.verifyDocument(bundle, { fetchAnchoredImpl: noChain });
  assert.equal(unanchored.verdict.decision, 'indeterminate');
  assert.equal(unanchored.exitCode, 2);
  const tampered = { ...bundle, jobId: 'tampered-after-signing' } as AttestationBundleV1;
  const bad = await doc.verifyDocument(tampered, { offline: true });
  assert.equal(bad.verdict.decision, 'fail');
  assert.equal(bad.exitCode, 1);
  const unknown = await doc.verifyDocument({ hello: 'world' }, { offline: true });
  assert.equal(unknown.bundleKind, 'unrecognised');
  assert.equal(unknown.verdict.decision, 'indeterminate');
  assert.deepEqual(validate(SCHEMA_VERDICT, unknown), []);
  const missing = spawnSync(process.execPath, [DIST_CLI, '--bundle-file', '/nonexistent/bundle.json', '--offline', '--json'], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
  const missingResult = JSON.parse(missing.stdout);
  assert.equal(missingResult.verdict.decision, 'indeterminate');
  assert.equal(missingResult.exitCode, 2);
  assert.deepEqual(validate(SCHEMA_VERDICT, missingResult), []);
  const usage = spawnSync(process.execPath, [DIST_CLI, '--offline'], { encoding: 'utf8' });
  assert.equal(usage.status, 3);
  const rpcError = (async () => { throw new Error('simulated RPC outage'); }) as unknown as doc.VerifyDocumentOptions['fetchAnchoredImpl'];
  const loaded = await doc.loadBundleSource({ anchor: 'stor-deadbeef', fetchAnchoredImpl: rpcError });
  assert.ok(doc.isLoadError(loaded) && /RPC error/.test(loaded.error));
});

test('HTTP: caller-side problems are 4xx, rpc is refused as a request field, body limit is enforced', async () => {
  const bundle = makeBundle();
  assert.equal((await route('GET', '/healthz', '')).status, 200);
  assert.equal(((await route('GET', '/schemas/verify-request.json', '')).body as any).title, SCHEMA_REQUEST.title);
  assert.equal(((await route('GET', '/schemas/verify-verdict.json', '')).body as any).title, SCHEMA_VERDICT.title);
  assert.equal((await route('GET', '/verify', '')).status, 405);
  assert.equal((await route('POST', '/verify', 'not json')).status, 400);
  assert.equal((await route('POST', '/verify', '[1]')).status, 400);
  assert.equal((await route('POST', '/verify', '{"bundle": 5}')).status, 400);
  assert.equal((await route('POST', '/verify', JSON.stringify({ bundle, offline: 'yes' }))).status, 400);
  assert.equal((await route('POST', '/verify', JSON.stringify({ bundle, rpc: 'http://evil' }))).status, 400);
  assert.equal((await route('GET', '/nope', '')).status, 404);
  // a chain failure during verification is an indeterminate verdict with status 200, never fail or 5xx
  const rpcError = (async () => { throw new Error('simulated RPC outage'); }) as unknown as doc.VerifyDocumentOptions['fetchAnchoredImpl'];
  const r = await route('POST', '/verify', JSON.stringify({ bundle }), { fetchAnchoredImpl: rpcError });
  assert.equal(r.status, 200);
  assert.equal((r.body as any).verdict.decision, 'indeterminate');
  // real server: healthz over a socket + 413 on an oversized body
  const server = createVerifierServer({});
  await new Promise<void>((res) => server.listen(0, '127.0.0.1', () => res()));
  try {
    const addr = server.address() as { port: number };
    const h = await fetch(`http://127.0.0.1:${addr.port}/healthz`);
    assert.equal(h.status, 200);
    assert.equal((await h.json()).apiVersion, 'pathos-dacs-verifier:1');
    const big = await postRaw(addr.port, '{"bundle":{"x":"' + 'a'.repeat(MAX_BODY_BYTES + 10) + '"}}');
    assert.equal(big.status, 413);
    assert.match(JSON.parse(big.body).error, /exceeds 1048576 bytes/);
  } finally {
    await new Promise<void>((res) => server.close(() => res()));
  }
});

/** POST a raw body with node:http and return the status even if the server closes the socket early. */
function postRaw(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/verify', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (r) => {
      const chunks: Buffer[] = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => res({ status: r.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', (e) => rej(e));
    req.end(body);
  });
}

test('built HTTP service starts the way the container and npm bin shims start it (relative argv) and listens', async () => {
  const child = spawn(process.execPath, ['dist/packages/verifier/src/http.js', '--port', '0'], { cwd: PKG, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c.toString(); });
  const exited = new Promise<number | null>((res) => child.on('exit', (code) => res(code)));
  try {
    const port = await Promise.race([
      new Promise<number>((res, rej) => {
        const timer = setTimeout(() => rej(new Error(`no listen line within 15s; stderr: ${stderr}`)), 15000);
        child.stderr.on('data', () => { const m = stderr.match(/listening on http:\/\/[^:]+:(\d+)/); if (m) { clearTimeout(timer); res(Number(m[1])); } });
      }),
      exited.then((code) => { throw new Error(`process exited before listening (code ${code}); stderr: ${stderr}`); }),
    ]);
    const h = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(h.status, 200);
    assert.equal((await h.json()).name, '@pathos-labs/dacs-verifier');
    const bundle = makeBundle();
    const v = await fetch(`http://127.0.0.1:${port}/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bundle, offline: true }) });
    assert.equal(v.status, 200);
    assert.equal((await v.json()).verdict.decision, 'pass');
  } finally {
    child.kill('SIGTERM');
    await exited;
  }
});

test('MCP stdio rejects an oversized frame with a structured error and keeps serving', async () => {
  const input = new PassThrough(); const output = new PassThrough();
  const chunks: string[] = []; output.on('data', (c) => chunks.push(c.toString()));
  const done = serve({}, input, output);
  input.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_bundle","arguments":{"bundle":{"pad":"' + 'a'.repeat(MAX_FRAME_BYTES + 100) + '"}}}}\n');
  input.end(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'verifier_info' } }) + '\n');
  await done;
  const out = chunks.join('').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(out.length, 2);
  assert.equal(out[0].error.code, -32600);
  assert.match(out[0].error.message, /frame exceeds/);
  assert.equal(JSON.parse(out[1].result.content[0].text).apiVersion, 'pathos-dacs-verifier:1');
});

test('MCP: initialize/list/call over stdio on the built dist; bad frames are structured errors', async () => {
  const bundle = makeBundle();
  const frames = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'verify_bundle', arguments: { bundle, offline: true } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'verify_bundle', arguments: { bundle: 'x' } } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'verify_bundle', arguments: { bundle, rpc: 'x' } } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: ['bad'] },
    { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'nope' } },
    'a JSON string is not a request',
  ].map((f) => JSON.stringify(f)).join('\n') + '\nnot json\n' + JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'verifier_info' } }) + '\n';
  const r = spawnSync(process.execPath, [relative(PKG, DIST_MCP)], { encoding: 'utf8', input: frames, cwd: PKG });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(out.length, 10);
  assert.equal(out[0].result.protocolVersion, '2024-11-05');
  assert.deepEqual(out[1].result.tools.map((t: any) => t.name), ['verify_bundle', 'verifier_info']);
  const verdict = JSON.parse(out[2].result.content[0].text);
  assert.equal(verdict.verdict.decision, 'pass');
  assert.deepEqual(validate(SCHEMA_VERDICT, verdict), []);
  assert.equal(out[3].result.isError, true);
  assert.equal(out[4].result.isError, true);
  assert.equal(out[5].error.code, -32600);
  assert.equal(out[6].error.code, -32601);
  assert.equal(out[7].error.code, -32600);
  assert.equal(out[8].error.code, -32700);
  assert.equal(JSON.parse(out[9].result.content[0].text).apiVersion, 'pathos-dacs-verifier:1');
  // in-process serve() with an injected chain reader: an unanchored bundle stays indeterminate
  const input = new PassThrough(); const output = new PassThrough();
  const chunks: string[] = []; output.on('data', (c) => chunks.push(c.toString()));
  const done = serve({ fetchAnchoredImpl: (async () => null) as any }, input, output);
  input.end(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'verify_bundle', arguments: { bundle } } }) + '\n');
  await done;
  assert.equal(JSON.parse(JSON.parse(chunks.join('')).result.content[0].text).verdict.decision, 'indeterminate');
});

test('container recipe references files the build produces', () => {
  const df = readFileSync(join(PKG, 'Dockerfile'), 'utf8');
  for (const rel of ['dist/packages/verifier/src/http.js', 'dist/packages/verifier/src/mcp.js', 'schemas/verify-request.schema.json', 'provenance.json', 'README.md', 'LICENSE', 'NOTICE']) {
    assert.ok(existsSync(join(PKG, rel)), `missing ${rel}`);
  }
  assert.ok(df.includes('ENTRYPOINT ["node"]') && df.includes('CMD ["dist/packages/verifier/src/http.js"]') && df.includes('USER node'));
  assert.ok(df.includes('npm ci') && existsSync(join(PKG, 'package-lock.json')));
  const lock = JSON.parse(readFileSync(join(PKG, 'package-lock.json'), 'utf8'));
  const meta = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));
  for (const dep of Object.keys(meta.dependencies)) assert.ok(lock.packages[`node_modules/${dep}`], `lockfile misses ${dep}`);
});
