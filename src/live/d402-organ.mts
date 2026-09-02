#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { demToOs } from '../adapters/dacs/pay-dem.js';
import {
  createD402Service,
  type D402Resource,
  type D402UsedProofs,
} from '../adapters/demos/d402-service.js';

const MAX_PROOFS = 100_000;
const execFileAsync = promisify(execFile);

type D402Service = Pick<ReturnType<typeof createD402Service>, 'challenge' | 'gate'>;

export function createD402ProofStore(
  committed = new Set<string>(),
  reserved = new Set<string>(),
): D402UsedProofs {
  return {
    has(key) { return committed.has(key) || reserved.has(key); },
    add(key) {
      if (committed.size + reserved.size >= MAX_PROOFS) return false;
      reserved.add(key);
      return true;
    },
  };
}

export function resourceFor(organ: string, query: string, amountOs: string): D402Resource {
  const queryHash = createHash('sha256').update(query).digest('hex').slice(0, 16);
  return {
    resourceId: `organ:${organ}:${queryHash}`,
    amount: amountOs,
    description: `Organ answer: ${organ}`,
  };
}

function canonicalTxHash(txHash: string): string {
  return txHash.replace(/^0x/i, '').toLowerCase();
}

export function proofKey(txHash: string, resourceId: string): string {
  return JSON.stringify([canonicalTxHash(txHash), resourceId]);
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  response.end(payload);
}

export function createD402OrganHandler(options: {
  service: D402Service;
  allowedOrgans: ReadonlySet<string>;
  amountOs: string;
  committed: Set<string>;
  reserved: Set<string>;
  runOrgan(organ: string, query: string): Promise<string>;
}) {
  return async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let url: URL;
    try {
      url = new URL(request.url ?? '/', 'http://localhost');
    } catch {
      json(response, 400, { error: 'bad-request' });
      return;
    }

    const match = /^\/engines\/organ\/([^/]+)$/.exec(url.pathname);
    if (request.method !== 'GET' || !match) {
      json(response, 404, { error: 'not-found' });
      return;
    }

    let organ: string;
    try {
      organ = decodeURIComponent(match[1]!);
    } catch {
      json(response, 404, { error: 'not-found' });
      return;
    }
    if (!options.allowedOrgans.has(organ)) {
      json(response, 404, { error: 'unknown-organ' });
      return;
    }

    const query = url.searchParams.get('q');
    if (!query) {
      json(response, 400, { error: 'missing-q' });
      return;
    }

    const resource = resourceFor(organ, query, options.amountOs);
    let gated: Awaited<ReturnType<D402Service['gate']>>;
    try {
      gated = await options.service.gate({ headers: request.headers, resource });
    } catch {
      json(response, 402, options.service.challenge(resource).body);
      return;
    }
    if (gated.status === 402) {
      json(response, 402, gated.body);
      return;
    }

    const key = proofKey(gated.payment.txHash, resource.resourceId);
    let payload: string;
    try {
      const raw = await options.runOrgan(organ, query);
      const result = JSON.parse(raw) as {
        organ?: unknown;
        answer?: unknown;
        input_commitment?: unknown;
        commitment_scheme?: unknown;
        fetched_at?: unknown;
      };
      if (result.answer === undefined) throw new Error('organ answer missing');
      payload = JSON.stringify({
        organ: result.organ,
        answer: result.answer,
        input_commitment: result.input_commitment,
        commitment_scheme: result.commitment_scheme,
        fetched_at: result.fetched_at,
        receipt: {
          txHash: gated.payment.txHash,
          from: gated.payment.from,
          amountOs: gated.payment.amount,
        },
      });
    } catch {
      options.reserved.delete(key);
      if (!response.headersSent) {
        response.writeHead(502);
        response.end();
      }
      return;
    }

    try {
      response.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(payload),
      });
    } catch {
      if (!response.headersSent) {
        options.reserved.delete(key);
        response.writeHead(502);
        response.end();
      } else {
        options.reserved.delete(key);
        options.committed.add(key);
      }
      return;
    }

    options.reserved.delete(key);
    options.committed.add(key);
    try {
      response.end(payload);
    } catch {
      if (!response.headersSent) {
        response.writeHead(502);
        response.end();
      }
    }
  };
}

async function main(): Promise<void> {
  const recipient = process.env.D402_RECIPIENT;
  if (!recipient) {
    console.error('D402_RECIPIENT is required.');
    process.exitCode = 2;
    return;
  }

  const rpcUrl = process.env.D402_RPC ?? 'https://demosnode.discus.sh/';
  const portText = process.env.D402_PORT ?? '8402';
  const priceDem = process.env.D402_PRICE_DEM ?? '1';
  const axiomPy = process.env.AXIOM_PY ?? 'python3';
  const organCli = process.env.ORGAN_CLI ?? 'organ_answer.py';
  const allowedOrgans = new Set(
    (process.env.D402_ORGANS ?? 'nws_alerts').split(',').map((value) => value.trim()).filter(Boolean),
  );
  const dryRun = process.argv.includes('--dry-run') || process.env.D402_DRY_RUN === '1';

  let amountOs: string;
  let port: number;
  try {
    amountOs = demToOs(priceDem).toString();
    port = Number(portText);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('invalid port');
    if (allowedOrgans.size === 0) throw new Error('no organs configured');
  } catch {
    console.error('Invalid D402 seller configuration.');
    process.exitCode = 2;
    return;
  }

  const committed = new Set<string>();
  const reserved = new Set<string>();
  const proofStore = createD402ProofStore(committed, reserved);
  const service = createD402Service({ recipient, rpcUrl, usedProofs: proofStore });

  if (dryRun) {
    const sampleOrgan = allowedOrgans.values().next().value as string;
    console.log(JSON.stringify(service.challenge(resourceFor(sampleOrgan, '0,0', amountOs)).body));
    return;
  }

  const handler = createD402OrganHandler({
    service,
    allowedOrgans,
    amountOs,
    committed,
    reserved,
    async runOrgan(organ, query) {
      const { stdout } = await execFileAsync(axiomPy, [organCli, organ, query], {
        encoding: 'utf8',
        timeout: 60_000,
      });
      return stdout;
    },
  });

  const server = createServer((request, response) => {
    void handler(request, response).catch(() => {
      if (!response.headersSent) {
        response.writeHead(500);
        response.end();
      } else if (!response.writableEnded) {
        response.end();
      }
    });
  });
  server.listen(port);
}

const entryPoint = process.argv[1];
if (entryPoint && import.meta.url === pathToFileURL(entryPoint).href) {
  void main().catch(() => {
    process.exitCode = 1;
  });
}
