import { spawn } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

export const PROTOCOL = 'dacs-adapter/1';

// Blocker 3 — subprocess safety defaults. A broken/hung/flooding adapter must never hang or
// OOM the cross-run; it must be recorded as failed/unavailable (fail-closed), never a silent
// pass. These bound each request's wall-clock and total captured stdout+stderr.
export const DEFAULT_ADAPTER_TIMEOUT_MS = 10_000;
export const DEFAULT_ADAPTER_MAX_OUTPUT_BYTES = 8 * 1024 * 1024; // 8 MiB per request

/** Raised when an adapter subprocess exceeds its wall-clock budget. */
export class AdapterTimeoutError extends Error {
  constructor(message) { super(message); this.name = 'AdapterTimeoutError'; }
}
/** Raised when an adapter subprocess exceeds its output budget. */
export class AdapterOutputLimitError extends Error {
  constructor(message) { super(message); this.name = 'AdapterOutputLimitError'; }
}

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
export async function startAdapterProcess(
  command,
  args = [],
  {
    cwd,
    env,
    timeoutMs = DEFAULT_ADAPTER_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_ADAPTER_MAX_OUTPUT_BYTES,
  } = {},
) {
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

    // Blocker 3 — bounded output. Poll the on-disk stdout/stderr sizes; if a flooding adapter
    // exceeds the budget, kill it and fail-closed rather than filling the disk.
    let outputLimitExceeded = false;
    const outputWatch = setInterval(() => {
      let total = 0;
      try { total += statSync(responsePath).size; } catch { /* not created yet */ }
      try { total += statSync(errorPath).size; } catch { /* not created yet */ }
      if (total > maxOutputBytes) {
        outputLimitExceeded = true;
        child.kill('SIGKILL');
      }
    }, 25);

    // Blocker 3 — per-adapter wall-clock timeout. A hung adapter is SIGKILLed and recorded as
    // a timeout failure; it can never hang the whole cross-run.
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();

    let status;
    let signal;
    try {
      ({ status, signal } = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, sig) => resolve({ status: code, signal: sig }));
      }));
    } finally {
      clearTimeout(timer);
      clearInterval(outputWatch);
    }

    let stdout = '';
    let stderr = '';
    try { stdout = readFileSync(responsePath, 'utf8'); } catch { /* nothing captured */ }
    try { stderr = readFileSync(errorPath, 'utf8'); } catch { /* nothing captured */ }
    rmSync(requestDirectory, { recursive: true, force: true });

    if (timedOut) {
      throw new AdapterTimeoutError(`adapter timed out after ${timeoutMs}ms (signal ${signal ?? 'SIGKILL'})`);
    }
    if (outputLimitExceeded) {
      throw new AdapterOutputLimitError(`adapter exceeded output budget of ${maxOutputBytes} bytes`);
    }
    if (status !== 0) throw new Error(`adapter exited ${status ?? `signal ${signal}`}: ${stderr.trim()}`);
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
