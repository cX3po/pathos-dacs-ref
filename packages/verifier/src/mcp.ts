#!/usr/bin/env node
/**
 * dacs-verifier-mcp — the verifier as an MCP server over stdio (JSON-RPC lines).
 *
 * Tools: `verify_bundle` (bundle object, offline?, requireSignatures?) → VerifyDocumentResult
 * as JSON text; `verifier_info` → name, version, API version, RPC and effective verification
 * policy. RPC and verification policy are server configuration, never caller-controlled.
 */
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERIFIER_API_VERSION, indeterminateVerdict, verifyDocument, type VerifyDocumentOptions } from '../../../src/lib/verify-document.js';
import { PACKAGE_NAME, PACKAGE_VERSION } from './index.js';

export const MCP_PROTOCOL_VERSION = '2024-11-05';
/** Largest accepted stdio frame (one JSON-RPC line); the HTTP service has the same body budget. */
export const MAX_FRAME_BYTES = 1_048_576;

export const MCP_VERIFICATION_POLICIES = ['live-enforcing', 'offline-enforcing', 'offline-fixture'] as const;
export type McpVerificationPolicy = typeof MCP_VERIFICATION_POLICIES[number];

export interface McpConfig {
  rpc?: string;
  fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
  /**
   * Server-owned policy. Clients may echo the effective booleans for compatibility but cannot
   * weaken them. `offline-fixture` is deliberately explicit: it is the only mode that disables
   * cryptographic signature enforcement, and it never claims live anchoring.
   */
  verificationPolicy?: McpVerificationPolicy;
}

type Json = Record<string, unknown>;

type EffectivePolicy = {
  name: McpVerificationPolicy;
  offline: boolean;
  requireSignatures: boolean;
  fixtureMode: boolean;
  signaturePolicy: 'v1-cryptographic-required' | 'v1-placeholder-signatures-allowed';
  anchoringPolicy: 'two-sided-lookup-required-for-pass' | 'two-sided-lookup-skipped';
};

function effectivePolicy(config: McpConfig): EffectivePolicy {
  const name = config.verificationPolicy ?? 'live-enforcing';
  if (!MCP_VERIFICATION_POLICIES.includes(name)) throw new Error(`unsupported MCP verification policy: ${String(name)}`);
  return {
    name,
    offline: name !== 'live-enforcing',
    requireSignatures: name !== 'offline-fixture',
    fixtureMode: name === 'offline-fixture',
    signaturePolicy: name === 'offline-fixture' ? 'v1-placeholder-signatures-allowed' : 'v1-cryptographic-required',
    anchoringPolicy: name === 'live-enforcing' ? 'two-sided-lookup-required-for-pass' : 'two-sided-lookup-skipped',
  };
}

function validateArguments(args: Json, policy: EffectivePolicy): void {
  const known = new Set(['bundle', 'offline', 'requireSignatures']);
  const unknown = Object.keys(args).filter((key) => !known.has(key));
  if (unknown.includes('rpc')) throw new Error('rpc is server configuration, not a tool argument');
  if (unknown.length) throw new Error(`unknown argument(s): ${unknown.sort().join(', ')}`);
  const bundle = args.bundle;
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) throw new Error('bundle must be a JSON object');
  for (const flag of ['offline', 'requireSignatures'] as const) {
    if (args[flag] !== undefined && typeof args[flag] !== 'boolean') throw new Error(`${flag} must be a boolean`);
    if (args[flag] !== undefined && args[flag] !== policy[flag]) {
      throw new Error(`${flag}=${String(args[flag])} conflicts with server policy ${policy.name} (${flag}=${String(policy[flag])})`);
    }
  }
}

async function toolVerifyBundle(args: Json, config: McpConfig): Promise<string> {
  const policy = effectivePolicy(config);
  validateArguments(args, policy);
  try {
    const result = await verifyDocument(args.bundle, {
      rpc: config.rpc,
      offline: policy.offline,
      requireSignatures: policy.requireSignatures,
      fetchAnchoredImpl: config.fetchAnchoredImpl,
    });
    return JSON.stringify(result);
  } catch (e) {
    const verdict = indeterminateVerdict('verifier', `verification did not complete: ${(e as Error).message}`);
    return JSON.stringify({ apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 });
  }
}

export function tools(config: McpConfig) {
  const policy = effectivePolicy(config);
  return {
    verify_bundle: {
      description: `Verify a DACS attestation bundle (v0.1 bundleVersion "1" or legacy dacs-5-bundle:0.1) under server policy ${policy.name}. Returns pass, fail or indeterminate, never coerced. Offline modes do not claim two-sided anchoring.`,
      inputSchema: {
        type: 'object',
        properties: {
          bundle: { type: 'object', description: 'the AttestationBundle document' },
          offline: { type: 'boolean', description: `compatibility echo only; server policy requires ${String(policy.offline)}` },
          requireSignatures: { type: 'boolean', description: `compatibility echo only; server policy requires ${String(policy.requireSignatures)}` },
        },
        required: ['bundle'],
        additionalProperties: false,
      },
      handler: (args: Json) => toolVerifyBundle(args, config),
    },
    verifier_info: {
      description: 'Name, version, API version, configured Demos RPC and effective server-owned verification policy.',
      inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
      handler: async (args: Json) => {
        const unknown = Object.keys(args);
        if (unknown.length) throw new Error(`unknown argument(s): ${unknown.sort().join(', ')}`);
        return JSON.stringify({
          name: PACKAGE_NAME,
          version: PACKAGE_VERSION,
          apiVersion: VERIFIER_API_VERSION,
          rpc: config.rpc ?? 'https://demosnode.discus.sh/',
          verificationPolicy: policy,
        });
      },
    },
  } as const;
}

export async function handleRequest(request: unknown, config: McpConfig = {}): Promise<Json | null> {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request: not an object' } };
  }
  const req = request as Json;
  const method = typeof req.method === 'string' ? req.method : '';
  const id = req.id ?? null;
  const params = req.params ?? {};
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request: params must be an object' } };
  }
  const p = params as Json;
  const registry = tools(config);
  if (method === 'initialize') {
    return { jsonrpc: '2.0', id, result: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: PACKAGE_NAME, version: PACKAGE_VERSION },
    } };
  }
  if (method === 'notifications/initialized') return null;
  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: Object.entries(registry).map(([name, t]) => ({ name, description: t.description, inputSchema: t.inputSchema })) } };
  }
  if (method === 'tools/call') {
    const name = typeof p.name === 'string' ? p.name : '';
    const tool = (registry as Record<string, { handler: (a: Json) => Promise<string> }>)[name];
    if (!tool) return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
    const args = p.arguments && typeof p.arguments === 'object' && !Array.isArray(p.arguments) ? (p.arguments as Json) : {};
    try {
      const text = await tool.handler(args);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: false } };
    } catch (e) {
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Error: ${(e as Error).message}` }], isError: true } };
    }
  }
  if (req.id !== undefined) return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown method: ${method}` } };
  return null;
}

export async function serve(config: McpConfig = {}, input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): Promise<void> {
  let buffer = '';
  let discarding = false; // an oversized frame is dropped up to its newline, with one error answer
  for await (const chunk of input) {
    buffer += chunk.toString();
    if (discarding) {
      const nl = buffer.indexOf('\n');
      if (nl < 0) { buffer = ''; continue; }
      buffer = buffer.slice(nl + 1);
      discarding = false;
    }
    if (buffer.indexOf('\n') < 0 && Buffer.byteLength(buffer) > MAX_FRAME_BYTES) {
      output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `Invalid request: frame exceeds ${MAX_FRAME_BYTES} bytes` } }) + '\n');
      buffer = '';
      discarding = true;
      continue;
    }
    let nl: number;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      if (Buffer.byteLength(line) > MAX_FRAME_BYTES) {
        output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `Invalid request: frame exceeds ${MAX_FRAME_BYTES} bytes` } }) + '\n');
        continue;
      }
      let response: Json | null;
      try {
        response = await handleRequest(JSON.parse(line), config);
      } catch (e) {
        response = e instanceof SyntaxError
          ? { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }
          : { jsonrpc: '2.0', id: null, error: { code: -32603, message: `Internal error: ${(e as Error).message}` } };
      }
      if (response) output.write(JSON.stringify(response) + '\n');
    }
  }
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
if (isEntry) {
  const requestedPolicy = process.env.DACS_VERIFIER_MCP_POLICY ?? 'live-enforcing';
  if (!MCP_VERIFICATION_POLICIES.includes(requestedPolicy as McpVerificationPolicy)) {
    console.error(`dacs-verifier-mcp: invalid DACS_VERIFIER_MCP_POLICY=${requestedPolicy}; expected ${MCP_VERIFICATION_POLICIES.join(', ')}`);
    process.exitCode = 3;
  } else {
    serve({ rpc: process.env.DACS_VERIFIER_RPC, verificationPolicy: requestedPolicy as McpVerificationPolicy }).catch((e) => {
      console.error(`dacs-verifier-mcp: server failed: ${(e as Error).message}`);
      process.exitCode = 2;
    });
  }
}
