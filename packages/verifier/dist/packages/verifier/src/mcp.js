#!/usr/bin/env node
/**
 * dacs-verifier-mcp — the verifier as an MCP server over stdio (JSON-RPC lines).
 *
 * Tools: `verify_bundle` (bundle object, offline?, requireSignatures?) → VerifyDocumentResult
 * as JSON text; `verifier_info` → name, version, apiVersion, rpc. The Demos RPC is server
 * configuration (DACS_VERIFIER_RPC), never a tool argument.
 */
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERIFIER_API_VERSION, indeterminateVerdict, verifyDocument } from '../../../src/lib/verify-document.js';
import { PACKAGE_NAME, PACKAGE_VERSION } from './index.js';
export const MCP_PROTOCOL_VERSION = '2024-11-05';
/** Largest accepted stdio frame (one JSON-RPC line); the HTTP service has the same body budget. */
export const MAX_FRAME_BYTES = 1_048_576;
async function toolVerifyBundle(args, config) {
    const bundle = args.bundle;
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle))
        throw new Error('bundle must be a JSON object');
    for (const flag of ['offline', 'requireSignatures']) {
        if (args[flag] !== undefined && typeof args[flag] !== 'boolean')
            throw new Error(`${flag} must be a boolean`);
    }
    if (args.rpc !== undefined)
        throw new Error('rpc is server configuration, not a tool argument');
    try {
        const result = await verifyDocument(bundle, {
            rpc: config.rpc,
            offline: args.offline,
            requireSignatures: args.requireSignatures,
            fetchAnchoredImpl: config.fetchAnchoredImpl,
        });
        return JSON.stringify(result);
    }
    catch (e) {
        const verdict = indeterminateVerdict('verifier', `verification did not complete: ${e.message}`);
        return JSON.stringify({ apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 });
    }
}
export function tools(config) {
    return {
        verify_bundle: {
            description: 'Verify a DACS attestation bundle (v0.1 bundleVersion "1" or legacy dacs-5-bundle:0.1). Returns the structured verdict: pass, fail or indeterminate, never coerced; offline=true skips the two-sided anchor lookup (audit only).',
            inputSchema: {
                type: 'object',
                properties: {
                    bundle: { type: 'object', description: 'the AttestationBundle document' },
                    offline: { type: 'boolean', description: 'skip the two-sided anchor lookup (receipt-archive audit only)' },
                    requireSignatures: { type: 'boolean', description: 'v0.1 only: false = fixture mode' },
                },
                required: ['bundle'],
            },
            handler: (args) => toolVerifyBundle(args, config),
        },
        verifier_info: {
            description: 'Name, version, API version and the configured Demos RPC of this verifier.',
            inputSchema: { type: 'object', properties: {}, required: [] },
            handler: async () => JSON.stringify({ name: PACKAGE_NAME, version: PACKAGE_VERSION, apiVersion: VERIFIER_API_VERSION, rpc: config.rpc ?? 'https://demosnode.discus.sh/' }),
        },
    };
}
export async function handleRequest(request, config = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
        return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request: not an object' } };
    }
    const req = request;
    const method = typeof req.method === 'string' ? req.method : '';
    const id = req.id ?? null;
    const params = req.params ?? {};
    if (!params || typeof params !== 'object' || Array.isArray(params)) {
        return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request: params must be an object' } };
    }
    const p = params;
    const registry = tools(config);
    if (method === 'initialize') {
        return { jsonrpc: '2.0', id, result: {
                protocolVersion: MCP_PROTOCOL_VERSION,
                capabilities: { tools: { listChanged: false } },
                serverInfo: { name: PACKAGE_NAME, version: PACKAGE_VERSION },
            } };
    }
    if (method === 'notifications/initialized')
        return null;
    if (method === 'tools/list') {
        return { jsonrpc: '2.0', id, result: { tools: Object.entries(registry).map(([name, t]) => ({ name, description: t.description, inputSchema: t.inputSchema })) } };
    }
    if (method === 'tools/call') {
        const name = typeof p.name === 'string' ? p.name : '';
        const tool = registry[name];
        if (!tool)
            return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
        const args = p.arguments && typeof p.arguments === 'object' && !Array.isArray(p.arguments) ? p.arguments : {};
        try {
            const text = await tool.handler(args);
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: false } };
        }
        catch (e) {
            return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true } };
        }
    }
    if (req.id !== undefined)
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown method: ${method}` } };
    return null;
}
export async function serve(config = {}, input = process.stdin, output = process.stdout) {
    let buffer = '';
    let discarding = false; // an oversized frame is dropped up to its newline, with one error answer
    for await (const chunk of input) {
        buffer += chunk.toString();
        if (discarding) {
            const nl = buffer.indexOf('\n');
            if (nl < 0) {
                buffer = '';
                continue;
            }
            buffer = buffer.slice(nl + 1);
            discarding = false;
        }
        if (buffer.indexOf('\n') < 0 && Buffer.byteLength(buffer) > MAX_FRAME_BYTES) {
            output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `Invalid request: frame exceeds ${MAX_FRAME_BYTES} bytes` } }) + '\n');
            buffer = '';
            discarding = true;
            continue;
        }
        let nl;
        while ((nl = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, nl).trim();
            buffer = buffer.slice(nl + 1);
            if (!line)
                continue;
            if (Buffer.byteLength(line) > MAX_FRAME_BYTES) {
                output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `Invalid request: frame exceeds ${MAX_FRAME_BYTES} bytes` } }) + '\n');
                continue;
            }
            let response;
            try {
                response = await handleRequest(JSON.parse(line), config);
            }
            catch (e) {
                response = e instanceof SyntaxError
                    ? { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }
                    : { jsonrpc: '2.0', id: null, error: { code: -32603, message: `Internal error: ${e.message}` } };
            }
            if (response)
                output.write(JSON.stringify(response) + '\n');
        }
    }
}
/** True when this module is the process entry (argv[1] resolved through symlinks, so npm .bin shims and relative paths both count). */
function isProcessEntry() {
    const arg = process.argv[1];
    if (!arg)
        return false;
    let target = resolve(arg);
    try {
        target = realpathSync(target);
    }
    catch { /* keep the resolved path */ }
    let self = fileURLToPath(import.meta.url);
    try {
        self = realpathSync(self);
    }
    catch { /* keep */ }
    return target === self;
}
const isEntry = isProcessEntry();
if (isEntry)
    serve({ rpc: process.env.DACS_VERIFIER_RPC });
