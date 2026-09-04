#!/usr/bin/env node
/**
 * verify-endpoint — the attestation-bundle verifier behind a d402 payment gate (the parked N5).
 *
 *   POST /verify            d402-gated: the first call answers 402 with a payment requirement
 *                           (recipient, amount in OS, resourceId bound to the SHA-256 of the exact
 *                           body); a call carrying `X-Payment-Proof: <txHash>` for a verified,
 *                           unreplayed payment answers 200 with the verdict plus a `receipt`.
 *   GET  /healthz           free: name, version, apiVersion, priceDem, recipient
 *   GET  /schemas/*         free: the packaged verifier's request and result schemas
 *
 * The verification itself is `handleVerifyRequest()` from src/lib/verify-http.ts, the same
 * handler the packaged HTTP service uses; the payment gate is `createD402Service()` from
 * src/adapters/demos/d402-service.ts with the seller-side reserve-then-commit proof store,
 * so a proof is consumed only when the verdict was actually delivered. Verdicts are never
 * coerced: a chain failure during verification is an indeterminate verdict (200), and a
 * refused payment is 402 with the reason. A paid request whose verification did not complete on
 * this server answers 503 and keeps the proof usable; a repeat of an already-answered paid request
 * is answered again (redelivered from a bounded cache, or re-verified once evicted) rather than
 * billed again. The proof store and the cache live in this process only: after a restart the
 * chain proof is accepted afresh, which is safe for the payer. The request's own `offline` and
 * `requireSignatures` are ignored: the deployment decides what a paid verification is. The Demos
 * RPC is server configuration.
 *
 * Environment: VERIFY_RECIPIENT (required), D402_RPC (default https://demosnode.discus.sh/),
 * VERIFY_PRICE_DEM (default 0.1), VERIFY_PORT (default 8403), VERIFY_HOST (default 127.0.0.1).
 * `--dry-run` prints a sample challenge and exits. `--offline` makes the endpoint skip the
 * two-sided anchor lookup for every request (receipt-archive audit deployments only).
 */
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { demToOs } from '../adapters/dacs/pay-dem.js';
import { createD402Service, type D402Resource, type D402UsedProofs } from '../adapters/demos/d402-service.js';
import { createNodeD402Verifier } from '../adapters/demos/d402-node-verifier.js';
import { VERIFIER_API_VERSION } from '../lib/verify-document.js';
import { fetchAnchored as liveFetchAnchored } from '../demos/storage.js';
import { MAX_VERIFY_BODY_BYTES, handleVerifyRequest, parseVerifyRequest, type VerifyHttpConfig } from '../lib/verify-http.js';
import { createD402ProofStore, proofKey } from './d402-organ.mjs';

export const ENDPOINT_NAME = 'pathos-dacs-verify-endpoint';
export const ENDPOINT_VERSION = '0.1.0';

type D402Service = Pick<ReturnType<typeof createD402Service>, 'challenge' | 'gate'>;

const SCHEMA_FILES: Record<string, string> = {
  '/schemas/verify-request.json': 'verify-request.schema.json',
  '/schemas/verify-verdict.json': 'verify-verdict.schema.json',
};

function schemasDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'packages', 'verifier', 'schemas');
}

/**
 * The payment requirement for one exact request body: the resource id binds the proof to those bytes.
 * The 16 hex characters are the first 64 bits of SHA-256: enough that a payer cannot find a second
 * body with the same id, and short enough for the memo the SDK writes on chain.
 */
export function resourceForBody(bodyText: string, amountOs: string): D402Resource {
  const bodyHash = createHash('sha256').update(bodyText).digest('hex').slice(0, 16);
  return { resourceId: `verify:${bodyHash}`, amount: amountOs, description: 'DACS attestation-bundle verification' };
}

export interface VerifyEndpointOptions {
  service: D402Service;
  amountOs: string;
  priceDem: string;
  recipient: string;
  committed: Set<string>;
  reserved: Set<string>;
  /** Verdicts already delivered, by proof key: a repeat of the same paid request is answered again, not billed again. */
  delivered?: Map<string, string>;
  /** Bound of the redelivery cache (default 10 000). A committed proof evicted from it is re-verified and served, never refused. */
  maxDelivered?: number;
  verify?: VerifyHttpConfig;
  /** Applied to every request (receipt-archive audit deployments). */
  offline?: boolean;
  schemasDir?: string;
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), connection: 'close' });
  response.end(payload);
}

function readBody(request: IncomingMessage): Promise<string | null> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    const declared = Number(request.headers['content-length'] ?? 0);
    if (Number.isFinite(declared) && declared > MAX_VERIFY_BODY_BYTES) { request.pause(); resolveBody(null); return; }
    request.on('data', (chunk: Buffer) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_VERIFY_BODY_BYTES) { tooLarge = true; request.pause(); resolveBody(null); return; }
      chunks.push(chunk);
    });
    request.on('end', () => { if (!tooLarge) resolveBody(Buffer.concat(chunks).toString('utf-8')); });
    request.on('error', reject);
  });
}

export function createVerifyEndpointHandler(options: VerifyEndpointOptions) {
  return async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let url: URL;
    try {
      url = new URL(request.url ?? '/', 'http://localhost');
    } catch {
      json(response, 400, { error: 'bad-request' });
      return;
    }
    const method = request.method ?? 'GET';
    if (method === 'GET' && url.pathname === '/healthz') {
      json(response, 200, { ok: true, name: ENDPOINT_NAME, version: ENDPOINT_VERSION, apiVersion: VERIFIER_API_VERSION, priceDem: options.priceDem, amountOs: options.amountOs, recipient: options.recipient, offline: options.offline === true });
      return;
    }
    if (method === 'GET' && url.pathname in SCHEMA_FILES) {
      const file = join(options.schemasDir ?? schemasDir(), SCHEMA_FILES[url.pathname]!);
      if (!existsSync(file)) { json(response, 500, { error: 'schema unavailable' }); return; }
      json(response, 200, JSON.parse(readFileSync(file, 'utf-8')));
      return;
    }
    if (url.pathname !== '/verify') { json(response, 404, { error: 'not-found' }); return; }
    if (method !== 'POST') { json(response, 405, { error: 'use POST /verify' }); return; }

    const body = await readBody(request);
    if (body === null) {
      response.on('finish', () => request.destroy());
      json(response, 413, { error: `request body exceeds ${MAX_VERIFY_BODY_BYTES} bytes` });
      return;
    }
    // A body that can never yield a verdict is refused before any challenge: nobody is asked to pay for it.
    const parsed = parseVerifyRequest(body);
    if (!parsed.ok) { json(response, 400, { error: parsed.error }); return; }
    const resource = resourceForBody(body, options.amountOs);
    const delivered = options.delivered ?? (options.delivered = new Map());
    // Watch this server's own chain reads: the verifier records an RPC failure as an indeterminate
    // step (never as absence), which is not an answer the payer should be billed for or served as one.
    let rpcFailed = false;
    const baseFetch = options.verify?.fetchAnchoredImpl ?? liveFetchAnchored;
    const watchedFetch: typeof liveFetchAnchored = (async (...args: Parameters<typeof liveFetchAnchored>) => {
      try {
        return await baseFetch(...args);
      } catch (e) {
        rpcFailed = true;
        throw e;
      }
    }) as typeof liveFetchAnchored;
    const outage = (detail: string) => json(response, 503, { error: detail, retry: 'repeat the same request with the same X-Payment-Proof', proofRetained: true });
    let gated: Awaited<ReturnType<D402Service['gate']>>;
    try {
      gated = await options.service.gate({ headers: request.headers, resource });
    } catch {
      json(response, 402, { ...options.service.challenge(resource).body, reason: 'unverifiable' });
      return;
    }
    if (gated.status === 402) {
      // the same proof for the same bytes again: redeliver the verdict it already bought, from the
      // cache while it is there, by verifying again once it has been evicted; never a refusal
      const replayKey = gated.reason === 'replayed' ? deliveredKey(request.headers, resource.resourceId) : null;
      const cached = replayKey ? delivered.get(replayKey) : undefined;
      if (cached !== undefined) {
        const again = JSON.parse(cached) as Record<string, unknown>;
        json(response, 200, { ...again, receipt: { ...(again.receipt as object), redelivered: true } });
        return;
      }
      if (replayKey && options.committed.has(replayKey)) {
        const reverified = await handleVerifyRequest(body, { ...(options.verify ?? {}), fetchAnchoredImpl: watchedFetch, forceOffline: options.offline === true, lockRequestOptions: true });
        const reverifyIncomplete = reverified.status === 200 ? reverified.incomplete : undefined;
        if (rpcFailed || reverifyIncomplete !== undefined) { outage(rpcFailed ? 'a chain read failed on the server during re-verification' : reverifyIncomplete!); return; }
        if (reverified.status === 200) {
          json(response, 200, { ...reverified.body, receipt: { txHash: JSON.parse(replayKey)[0], resourceId: resource.resourceId, redelivered: true, reverified: true } });
          return;
        }
      }
      json(response, 402, { ...gated.body, reason: gated.reason });
      return;
    }

    // Paid. The proof is reserved by the gate; commit it only once the verdict has been sent.
    const key = proofKey(gated.payment.txHash, resource.resourceId);
    const verified = await handleVerifyRequest(body, { ...(options.verify ?? {}), fetchAnchoredImpl: watchedFetch, forceOffline: options.offline === true, lockRequestOptions: true });
    if (verified.status !== 200) {
      // unreachable in practice: the same bytes passed parseVerifyRequest before the gate. Kept as a
      // fail-safe that releases the reservation rather than billing a request that produced no verdict.
      options.reserved.delete(key);
      json(response, 400, verified.body);
      return;
    }
    if (rpcFailed || verified.incomplete !== undefined) {
      // the verifier did not complete on this server (its RPC or an internal failure, not the bundle):
      // not an answer, not billed. The signal is the handler's own `incomplete` flag, never a step
      // name, so a genuine verdict can never be mistaken for an outage and strand a paid caller.
      // The reservation is released so the same proof pays for a retry.
      options.reserved.delete(key);
      outage(rpcFailed ? 'a chain read failed on the server during verification' : verified.incomplete!);
      return;
    }
    const payload = JSON.stringify({ ...verified.body, receipt: { txHash: gated.payment.txHash, from: gated.payment.from, amountOs: gated.payment.amount, resourceId: resource.resourceId } });
    try {
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), connection: 'close' });
    } catch {
      options.reserved.delete(key);
      if (!response.headersSent) { response.writeHead(502); response.end(); }
      return;
    }
    options.reserved.delete(key);
    options.committed.add(key);
    const bound = options.maxDelivered ?? MAX_DELIVERED;
    while (delivered.size >= bound && delivered.size > 0) delivered.delete(delivered.keys().next().value as string);
    delivered.set(key, payload);
    response.end(payload);
  };
}

const MAX_DELIVERED = 10_000;

function deliveredKey(headers: IncomingMessage['headers'], resourceId: string): string | null {
  const raw = headers['x-payment-proof'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || !value.trim()) return null;
  return proofKey(value.trim(), resourceId);
}

export function readConfig(env: NodeJS.ProcessEnv = process.env): { recipient: string; rpcUrl: string; port: number; host: string; priceDem: string; amountOs: string } | { error: string } {
  const recipient = env.VERIFY_RECIPIENT;
  if (!recipient) return { error: 'VERIFY_RECIPIENT is required' };
  if (!/^0x[0-9a-f]{64}$/i.test(recipient)) return { error: 'VERIFY_RECIPIENT must be a Demos address (0x + 64 hex characters)' };
  const rpcUrl = env.D402_RPC ?? 'https://demosnode.discus.sh/';
  const priceDem = env.VERIFY_PRICE_DEM ?? '0.1';
  const port = Number(env.VERIFY_PORT ?? '8403');
  const host = env.VERIFY_HOST ?? '127.0.0.1';
  let amountOs: string;
  try {
    amountOs = demToOs(priceDem).toString();
  } catch {
    return { error: `invalid VERIFY_PRICE_DEM: ${priceDem}` };
  }
  if (BigInt(amountOs) <= 0n) return { error: 'VERIFY_PRICE_DEM must be greater than zero (a free gate is not a gate)' };
  if (!Number.isInteger(port) || port < 0 || port > 65_535) return { error: `invalid VERIFY_PORT: ${env.VERIFY_PORT}` };
  return { recipient, rpcUrl, port, host, priceDem, amountOs };
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const config = readConfig();
  if ('error' in config) { console.error(config.error); return 2; }
  const committed = new Set<string>();
  const reserved = new Set<string>();
  const proofStore: D402UsedProofs = createD402ProofStore(committed, reserved);
  // Payments are confirmed through the node's getTxByHash (src/adapters/demos/d402-node-verifier.ts);
  // the SDK's D402Server uses routes the testnet node does not serve.
  const service = createD402Service({ recipient: config.recipient, rpcUrl: config.rpcUrl, usedProofs: proofStore, verifier: createNodeD402Verifier({ rpcUrl: config.rpcUrl }) });
  const offline = argv.includes('--offline');
  if (argv.includes('--dry-run')) {
    console.log(JSON.stringify(service.challenge(resourceForBody('{"bundle":{}}', config.amountOs)).body));
    return 0;
  }
  const handler = createVerifyEndpointHandler({
    service, amountOs: config.amountOs, priceDem: config.priceDem, recipient: config.recipient, committed, reserved,
    verify: { rpc: config.rpcUrl }, offline,
  });
  const server = createServer((request, response) => {
    void handler(request, response).catch(() => {
      if (!response.headersSent) { response.writeHead(500); response.end(); } else if (!response.writableEnded) response.end();
    });
  });
  // Explicit socket limits: an unpaid request costs at most one body read (bounded by MAX_VERIFY_BODY_BYTES)
  // and one hash; a slow or silent client is cut off rather than holding a worker.
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  await new Promise<void>((resolve) => server.listen(config.port, config.host, () => resolve()));
  const addr = server.address();
  const shown = typeof addr === 'object' && addr ? `${addr.address}:${addr.port}` : String(addr);
  console.error(`${ENDPOINT_NAME} ${ENDPOINT_VERSION} listening on http://${shown} (price ${config.priceDem} DEM, recipient ${config.recipient}, rpc ${config.rpcUrl}${offline ? ', offline' : ''})`);
  return -1; // keeps serving
}

const entryPoint = process.argv[1];
if (entryPoint && import.meta.url === pathToFileURL(entryPoint).href) {
  void main().then((code) => { if (code >= 0) process.exit(code); }).catch((err) => {
    console.error(`${ENDPOINT_NAME}: ${(err as Error).message}`);
    process.exit(1);
  });
}
