/**
 * rpc-replay-fixture — the SR-2 anchor path under scripted node behaviour, offline.
 *
 * This synthetic corpus uses top-level field types from the sanitized node shape probe (PATH-OS
 * memory/reports/demos-node-shape-probe.json: getStorageProgram {owner, programName, createdByTx, data}, getTxByHash
 * {status, blockNumber, hash, content}, getTransactionStatus {state, blockNumber}). It additionally supplies storageAddress
 * and transaction content.type/from/nonce required by anchorFactsFromNode; those fields are not established by that probe.
 * Pending, failed, and delayed-indexing sequences are scripted. A fake Demos handle replays one sequence per scenario into
 * the REAL anchor() (src/demos/storage.ts). Each scenario checks its expected outcome and elapsed-time bound with settling
 * fake RPCs, typed failure diagnostics carrying the transaction hash, and exactly one broadcastAndWait invocation per
 * anchor. SDK-internal broadcasts and timeout enforcement are outside this corpus.
 * No node, no credential, no DEM. Run: GATEWAY_BROADCAST_TIMEOUT_MS=150 GATEWAY_BROADCAST_GRACE_MS=400 GATEWAY_BROADCAST_POLL_MS=100 node --import tsx src/live/rpc-replay-fixture.mts --json
 */
import { createHash } from 'node:crypto';
import { anchor, Sr2AnchorError } from '../demos/storage.js';

const ADDRESS = '0x' + 'ab'.repeat(32);
const OTHER = '0x' + 'cd'.repeat(32);
const hex64 = (seed: string) => createHash('sha256').update(seed).digest('hex');

interface Step { step: string; outcome: 'pass' | 'fail'; detail: string }
const steps: Step[] = [];
const step = (name: string, ok: boolean, detail: string) => { steps.push({ step: name, outcome: ok ? 'pass' : 'fail', detail }); return ok; };

class BroadcastTimeoutError extends Error { constructor(public txHash: string) { super('broadcast timeout'); this.name = 'BroadcastTimeoutError'; } }

interface Script {
  /** what broadcastAndWait does: 'included' | 'timeout' | 'failed-state' */
  broadcast: 'included' | 'timeout';
  /** node states polled after a timeout, in order; the last repeats */
  nodeAnswers?: string[];
  /** read-back: how many getStorageProgram calls answer 404 before the record appears (delayed indexing) */
  readbackAbsent?: number;
  /** read-back owner (a conflicting writer when it is not ADDRESS) */
  owner?: string;
}

function fakeHandle(script: Script) {
  const counters = { broadcasts: 0, pollCount: 0, readbacks: 0 };
  const txHash = hex64(`tx:${JSON.stringify(script)}`);
  const demos = {
    async getAddressNonce() { return 7; },
    storagePrograms: { async sign(payload: unknown) { return { hash: txHash, content: { from: ADDRESS, nonce: 7, payload } }; } },
    async confirm(tx: unknown) { return { validity: tx }; },
    async broadcastAndWait() {
      counters.broadcasts += 1;
      if (script.broadcast === 'timeout') throw new BroadcastTimeoutError(txHash);
      return { broadcast: { response: { hash: txHash } }, status: { state: 'included' } };
    },
    async call(_m: string, message: string) {
      if (message === 'getTransactionStatus') {
        const list = script.nodeAnswers ?? ['pending'];
        const state = list[Math.min(counters.pollCount, list.length - 1)]; counters.pollCount += 1;
        return { state, blockNumber: state === 'included' ? 249444 : undefined };
      }
      throw new Error(`unexpected call ${message}`);
    },
  };
  const fetchImpl: typeof fetch = (async (_url: unknown, init?: { body?: string }) => {
    const body = JSON.parse(String(init?.body ?? '{}')) as { params?: Array<{ message?: string; data?: Record<string, unknown> }> };
    const message = body.params?.[0]?.message;
    let envelope: unknown;
    if (message === 'getStorageProgram') {
      counters.readbacks += 1;
      if (counters.readbacks <= (script.readbackAbsent ?? 0)) envelope = { result: 404, response: null };
      else envelope = { result: 200, response: { storageAddress: String(body.params?.[0]?.data?.storageAddress), owner: script.owner ?? ADDRESS, programName: 'x', createdByTx: txHash, data: {} } };
    } else if (message === 'getTxByHash') {
      envelope = { result: 200, response: { status: 'included', blockNumber: 249444, hash: txHash, content: { type: 'storageProgram', from: script.owner ?? ADDRESS, nonce: 7 } } };
    } else envelope = { result: 404, response: null };
    return { ok: true, status: 200, json: async () => envelope } as unknown as Response;
  }) as typeof fetch;
  return { handle: { demos: demos as never, address: ADDRESS, rpc: 'https://replay.invalid/' }, counters, txHash, fetchImpl };
}

async function scenario(name: string, script: Script, expect: { ok: boolean; cls?: string; state?: string; polls: number; readbacks: number; minElapsedMs?: number }, boundMs: number) {
  const { handle, counters, txHash, fetchImpl } = fakeHandle(script);
  const started = Date.now();
  let outcome: { ok: true; locator: string } | { ok: false; cls: string; txHash?: string; state?: string; waitMs?: number } | { ok: false; cls: 'untyped'; message: string };
  try {
    const result = await anchor(handle, `replay:${name}`, { v: 'replay-corpus:1', scenario: name }, { fetchImpl, readBackAttempts: 4, readBackDelayMs: 10 });
    const r = result as { storageAddress?: unknown; txHash?: unknown };
    if (typeof r.storageAddress !== 'string' || !r.storageAddress.startsWith('stor-') || r.txHash !== txHash) throw new Error('anchor result lacks storageAddress/txHash');
    outcome = { ok: true, locator: r.storageAddress };
  } catch (error) {
    if (error instanceof Sr2AnchorError) outcome = { ok: false, cls: error.diagnostics.class, txHash: error.diagnostics.txHash, state: error.diagnostics.state, waitMs: error.diagnostics.waitMs };
    else outcome = { ok: false, cls: 'untyped', message: error instanceof Error ? error.message.slice(0, 80) : String(error) };
  }
  const elapsed = Date.now() - started;
  const bounded = elapsed <= boundMs;
  const typed = !outcome.ok && outcome.cls !== 'untyped' ? outcome as { ok: false; cls: string; txHash?: string; state?: string; waitMs?: number } : null;
  const honest = outcome.ok ? expect.ok : (expect.ok === false && typed !== null && typed.cls === expect.cls && typed.txHash === txHash && (expect.state === undefined || typed.state === expect.state));
  const single = counters.broadcasts === 1;
  const paths = counters.pollCount === expect.polls && counters.readbacks === expect.readbacks && elapsed >= (expect.minElapsedMs ?? 0);
  const label = outcome.ok ? 'anchored' : typed ? `${typed.cls}${typed.txHash ? ' tx=' + typed.txHash.slice(0, 8) : ''}${typed.state ? ' state=' + typed.state : ''}` : `untyped: ${(outcome as { message: string }).message}`;
  step(name, honest && bounded && single && paths, `${label} broadcasts=${counters.broadcasts} polls=${counters.pollCount} readbacks=${counters.readbacks} elapsed=${elapsed}ms bound=${boundMs}ms`);
}

async function main(): Promise<number> {
  const json = process.argv.includes('--json');
  process.env.GATEWAY_BROADCAST_TIMEOUT_MS ??= '150';
  process.env.GATEWAY_BROADCAST_GRACE_MS ??= '400';
  process.env.GATEWAY_BROADCAST_POLL_MS ??= '100';
  const eff = (raw: string | undefined, def: number, max: number, min = 1) => { const n = Number(raw); return Number.isFinite(n) && n > 0 ? Math.max(min, Math.min(n, max)) : def; };
  const timeout = eff(process.env.GATEWAY_BROADCAST_TIMEOUT_MS, 240_000, 600_000);
  const grace = eff(process.env.GATEWAY_BROADCAST_GRACE_MS, 180_000, 600_000);
  const poll = eff(process.env.GATEWAY_BROADCAST_POLL_MS, 15_000, 60_000, 100);
  const bound = timeout + grace + poll + 4 * 10 + 1500; // effective windows + read-back attempts + scheduling slack
  await scenario('delayed-indexing', { broadcast: 'included', readbackAbsent: 2 }, { ok: true, polls: 0, readbacks: 3 }, bound);
  await scenario('missing-finality-pending-forever', { broadcast: 'timeout', nodeAnswers: ['pending'] }, { ok: false, cls: 'anchor-not-confirmed', polls: Math.ceil(grace / poll), readbacks: 0, minElapsedMs: grace }, bound);
  await scenario('timeout-after-broadcast-then-included', { broadcast: 'timeout', nodeAnswers: ['pending', 'included'] }, { ok: true, polls: 2, readbacks: 1 }, bound);
  await scenario('failed-on-chain', { broadcast: 'timeout', nodeAnswers: ['failed'] }, { ok: false, cls: 'anchor-failed-on-chain', polls: 1, readbacks: 0 }, bound);
  await scenario('conflicting-writer', { broadcast: 'included', owner: OTHER }, { ok: false, cls: 'anchor-facts-mismatch', polls: 0, readbacks: 1 }, bound);
  const rollup = steps.every((s) => s.outcome === 'pass') ? 'PASS' : 'FAIL';
  const out = { harness: 'rpc-replay-fixture:0.1', mode: 'offline-corpus', corpus: 'demos-node-shape-probe (sanitized shapes)', windows_ms: { timeout, grace, poll }, rollup, steps };
  process.stdout.write((json ? '' : `${rollup} rpc-replay-fixture\n`) + JSON.stringify(out) + '\n');
  return rollup === 'PASS' ? 0 : 1;
}

process.exitCode = await main();
