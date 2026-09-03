#!/usr/bin/env node
/**
 * dacs-verifier-http — the verifier as a small HTTP service.
 *
 *   POST /verify                     body {bundle, offline?, requireSignatures?} → VerifyDocumentResult
 *   GET  /healthz                    {ok, name, version, apiVersion}
 *   GET  /schemas/verify-request.json, /schemas/verify-verdict.json
 *
 * A well-formed request always answers 200 with a verdict (pass / fail / indeterminate, never
 * coerced). Caller-side problems answer 4xx with {error}. The Demos RPC used for anchor
 * lookups is server configuration (DACS_VERIFIER_RPC or --rpc), never taken from the request.
 * Binds 127.0.0.1 unless DACS_VERIFIER_HOST / --host says otherwise; there is no
 * authentication, so expose it only behind something that provides it.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { VERIFIER_API_VERSION, indeterminateVerdict, verifyDocument, type VerifyDocumentOptions } from '../../../src/lib/verify-document.js';
import { PACKAGE_NAME, PACKAGE_VERSION } from './index.js';

export const MAX_BODY_BYTES = 1_048_576;
/** The package's schemas directory: the nearest ancestor of this module that holds schemas/verify-request.schema.json
 *  (packages/verifier from the sources, and again from dist/packages/verifier/src once compiled). */
function findSchemasDir(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, 'schemas');
    if (existsSync(join(candidate, 'verify-request.schema.json'))) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return join(dirname(fileURLToPath(import.meta.url)), 'schemas');
}
const SCHEMAS_DIR = findSchemasDir();
const SCHEMA_FILES: Record<string, string> = {
  '/schemas/verify-request.json': 'verify-request.schema.json',
  '/schemas/verify-verdict.json': 'verify-verdict.schema.json',
};

export interface ServiceConfig {
  rpc?: string;
  fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
  /** Where the JSON schemas live (defaults to the package's schemas directory). */
  schemasDir?: string;
}

export interface RouteResult { status: number; body: unknown }

/** Pure request handler: (method, path, body text) → (status, JSON body). Used by the server and by tests. */
export async function route(method: string, path: string, bodyText: string, config: ServiceConfig = {}): Promise<RouteResult> {
  if (method === 'GET' && path === '/healthz') {
    return { status: 200, body: { ok: true, name: PACKAGE_NAME, version: PACKAGE_VERSION, apiVersion: VERIFIER_API_VERSION } };
  }
  if (method === 'GET' && path in SCHEMA_FILES) {
    const file = join(config.schemasDir ?? SCHEMAS_DIR, SCHEMA_FILES[path]!);
    try {
      return { status: 200, body: JSON.parse(readFileSync(file, 'utf-8')) };
    } catch (e) {
      return { status: 500, body: { error: `schema unavailable: ${(e as Error).message}` } };
    }
  }
  if (path === '/verify') {
    if (method !== 'POST') return { status: 405, body: { error: 'use POST /verify' } };
    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyText);
    } catch (e) {
      return { status: 400, body: { error: `request body is not valid JSON: ${(e as Error).message}` } };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { status: 400, body: { error: 'request body must be a JSON object' } };
    const req = parsed as Record<string, unknown>;
    if (!req.bundle || typeof req.bundle !== 'object' || Array.isArray(req.bundle)) return { status: 400, body: { error: 'bundle must be a JSON object' } };
    for (const flag of ['offline', 'requireSignatures'] as const) {
      if (req[flag] !== undefined && typeof req[flag] !== 'boolean') return { status: 400, body: { error: `${flag} must be a boolean` } };
    }
    if (req.rpc !== undefined) return { status: 400, body: { error: 'rpc is server configuration, not a request field' } };
    try {
      const result = await verifyDocument(req.bundle, {
        rpc: config.rpc,
        offline: req.offline as boolean | undefined,
        requireSignatures: req.requireSignatures as boolean | undefined,
        fetchAnchoredImpl: config.fetchAnchoredImpl,
      });
      return { status: 200, body: result };
    } catch (e) {
      // An RPC or internal failure is "could not reach a verdict": indeterminate, never fail or pass.
      const verdict = indeterminateVerdict('verifier', `verification did not complete: ${(e as Error).message}`);
      return { status: 200, body: { apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 } };
    }
  }
  return { status: 404, body: { error: 'not found' } };
}

function readBody(request: IncomingMessage): Promise<string | null> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    const declared = Number(request.headers['content-length'] ?? 0);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) { request.pause(); resolveBody(null); return; }
    request.on('data', (chunk: Buffer) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { tooLarge = true; request.pause(); resolveBody(null); return; }
      chunks.push(chunk);
    });
    request.on('end', () => { if (!tooLarge) resolveBody(Buffer.concat(chunks).toString('utf-8')); });
    request.on('error', reject);
  });
}

export function createVerifierServer(config: ServiceConfig = {}) {
  return createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const send = (status: number, body: unknown) => {
      const text = JSON.stringify(body);
      response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(text), connection: 'close' });
      response.end(text);
    };
    try {
      const url = new URL(request.url ?? '/', 'http://localhost');
      const body = await readBody(request);
      if (body === null) {
        // answer first, then drop the rest of the body: the 413 reaches the client before the socket closes
        response.on('finish', () => request.destroy());
        send(413, { error: `request body exceeds ${MAX_BODY_BYTES} bytes` });
        return;
      }
      const r = await route(request.method ?? 'GET', url.pathname, body, config);
      send(r.status, r.body);
    } catch (e) {
      send(500, { error: `internal error: ${(e as Error).message}` });
    }
  });
}

export function main(argv: string[] = process.argv.slice(2)): void {
  const { values } = parseArgs({
    args: argv,
    options: {
      host: { type: 'string', default: process.env.DACS_VERIFIER_HOST ?? '127.0.0.1' },
      port: { type: 'string', default: process.env.DACS_VERIFIER_PORT ?? '8787' },
      rpc: { type: 'string', default: process.env.DACS_VERIFIER_RPC ?? 'https://demosnode.discus.sh/' },
    },
    strict: true,
  });
  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) { console.error(`invalid port: ${values.port}`); process.exit(3); }
  const server = createVerifierServer({ rpc: values.rpc as string });
  server.listen(port, values.host as string, () => {
    const addr = server.address();
    const shown = typeof addr === 'object' && addr ? `${addr.address}:${addr.port}` : String(addr);
    console.error(`${PACKAGE_NAME} ${PACKAGE_VERSION} listening on http://${shown} (rpc ${values.rpc as string})`);
  });
}

/** True when this module is the process entry (argv[1] resolved through symlinks, so npm .bin shims and relative paths both count). */
function isProcessEntry(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  let target = resolve(arg);
  try { target = realpathSync(target); } catch { /* keep the resolved path */ }
  let self = fileURLToPath(import.meta.url);
  try { self = realpathSync(self); } catch { /* keep */ }
  return target === self;
}
const isEntry = isProcessEntry();
if (isEntry) main();
