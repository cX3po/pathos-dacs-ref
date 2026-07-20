import { spawn } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

export const PROTOCOL = 'dacs-adapter/1';

export function encodeProtocolValue(value) {
  if (typeof value === 'bigint') return { $dacsType: 'bigint', decimal: String(value) };
  if (value instanceof Uint8Array) return { $dacsType: 'bytes', hex: Buffer.from(value).toString('hex') };
  if (Array.isArray(value)) return value.map(encodeProtocolValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeProtocolValue(item)]));
  }
  return value;
}

/**
 * Build a runner-side client for a JSONL subprocess adapter and perform the mandatory
 * metadata handshake. Each request uses a fresh process so crashes and state cannot leak
 * between vectors; the wire contract is identical for adapters that choose to stay alive.
 */
export async function startAdapterProcess(command, args = [], { cwd, env } = {}) {
  let sequence = 0;
  async function request(type, body = {}) {
    const id = String(++sequence);
    const message = { protocol: PROTOCOL, id, type, ...encodeProtocolValue(body) };
    // Give the subprocess an ordinary stdin file. This makes EOF an explicit request
    // boundary and supports adapters that buffer stdin until EOF.
    const requestDirectory = mkdtempSync(path.join(tmpdir(), 'dacs-adapter-request-'));
    const requestPath = path.join(requestDirectory, 'request.jsonl');
    const responsePath = path.join(requestDirectory, 'response.jsonl');
    const errorPath = path.join(requestDirectory, 'stderr.txt');
    writeFileSync(requestPath, JSON.stringify(message) + '\n', { mode: 0o600 });
    const inputFd = openSync(requestPath, 'r');
    const outputFd = openSync(responsePath, 'w');
    const errorFd = openSync(errorPath, 'w');
    const child = spawn(command, args, {
      cwd,
      env: env ?? process.env,
      stdio: [inputFd, outputFd, errorFd],
    });
    closeSync(inputFd);
    closeSync(outputFd);
    closeSync(errorFd);
    const status = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => resolve(code));
    });
    const stdout = readFileSync(responsePath, 'utf8');
    const stderr = readFileSync(errorPath, 'utf8');
    rmSync(requestDirectory, { recursive: true, force: true });
    if (status !== 0) throw new Error(`adapter exited ${status}: ${stderr.trim()}`);
    const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
    if (lines.length !== 1) throw new Error(`adapter emitted ${lines.length} response lines; expected 1`);
    let response;
    try { response = JSON.parse(lines[0]); }
    catch { throw new Error('adapter emitted non-JSON stdout'); }
    if (response.protocol !== PROTOCOL || response.id !== id) throw new Error('adapter response envelope mismatch');
    if (!response.ok) throw new Error(response.error?.message ?? 'adapter operation failed');
    return response.result;
  }

  const metadata = await request('metadata');
  validateMetadata(metadata);
  const adapter = { metadata, name: metadata.name };
  for (const operation of metadata.operations) {
    adapter[operation] = (...params) => request('execute', { operation, params });
  }
  adapter.close = async () => {};
  return adapter;
}

export function validateMetadata(metadata) {
  for (const field of ['name', 'version', 'repository', 'revision']) {
    if (typeof metadata?.[field] !== 'string' || metadata[field].length === 0) {
      throw new Error(`adapter metadata.${field} must be a non-empty string`);
    }
  }
  if (!Array.isArray(metadata.operations) || !Array.isArray(metadata.supportedFamilies)) {
    throw new Error('adapter metadata must include operations and supportedFamilies arrays');
  }
}
