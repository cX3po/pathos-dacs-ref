#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { config } from 'dotenv';
import type { DemosHandle } from '../demos/connection.js';
import type { FetchResult } from '../demos/storage.js';
import {
  createProofLedger,
  gateVerdictEntryFromCase,
  receiptEntryFromOutboundReceipt,
  type AppendPlan,
  type ReceiptEntry,
} from '../adapters/demos/proof-ledger.js';

type Input = { kind: 'receipt'; path: string } | { kind: 'case'; path: string; event: number };

function parseArgs(argv: string[]): {
  ledgerName: string;
  dryRun: boolean;
  fresh: boolean;
  head?: string;
  inputs: Input[];
} {
  let ledgerName = 'pathos-proof';
  let dryRun = false;
  let fresh = false;
  let head: string | undefined;
  const inputs: Input[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--fresh') {
      fresh = true;
    } else if (arg === '--head') {
      const value = argv[++i]?.trim();
      if (!value || !/^stor-/.test(value)) throw new Error('--head requires a stor- address');
      head = value;
    } else if (arg === '--ledger') {
      const value = argv[++i];
      if (!value) throw new Error('--ledger requires a name');
      ledgerName = value;
    } else if (arg === '--receipt') {
      const path = argv[++i];
      if (!path) throw new Error('--receipt requires a path');
      inputs.push({ kind: 'receipt', path });
    } else if (arg === '--case') {
      const path = argv[++i];
      if (!path) throw new Error('--case requires a path');
      if (argv[++i] !== '--event') throw new Error('--case must be followed by --event <index>');
      const rawIndex = argv[++i];
      if (rawIndex === undefined || !/^\d+$/.test(rawIndex)) {
        throw new Error('--event requires a non-negative integer');
      }
      inputs.push({ kind: 'case', path, event: Number(rawIndex) });
    } else {
      throw new Error(`unknown argument: ${String(arg)}`);
    }
  }
  if (inputs.length === 0) throw new Error('at least one --receipt or --case input is required');
  if (fresh && head !== undefined) throw new Error('--fresh and --head are mutually exclusive');
  if (!fresh && head === undefined) throw new Error('--head stor-… is required unless --fresh is set');
  if (dryRun && head !== undefined) throw new Error('--dry-run cannot fetch a live --head; use --fresh');
  return { ledgerName, dryRun, fresh, ...(head === undefined ? {} : { head }), inputs };
}

async function entriesFromInputs(inputs: Input[]): Promise<ReceiptEntry[]> {
  return Promise.all(inputs.map(async (input) => {
    const parsed: unknown = JSON.parse(await readFile(input.path, 'utf8'));
    return input.kind === 'receipt'
      ? receiptEntryFromOutboundReceipt(parsed)
      : gateVerdictEntryFromCase(parsed, input.event);
  }));
}

function publicPlan(plan: AppendPlan) {
  return {
    address: plan.storageAddress,
    op: plan.op,
    entryCount: plan.entryCount,
    sizeBytes: plan.sizeBytes,
    feeOS: plan.feeOS,
    withinSizeLimit: plan.withinSizeLimit,
  };
}

async function runDry(entries: ReceiptEntry[], ledgerName: string): Promise<void> {
  const stored = new Map<string, FetchResult>();
  const handle = {
    address: `0x${'0'.repeat(64)}`,
    rpc: 'offline:',
    demos: { async getAddressNonce() { return 0; } },
  } as unknown as DemosHandle;
  const fetchImpl = async (_rpc: string, address: string) => stored.get(address) ?? null;
  const broadcastImpl = async (
    _handle: DemosHandle,
    payload: unknown,
  ): Promise<{ txHash: string }> => {
    const planned = payload as { storageAddress: string; data: unknown };
    const result: FetchResult = {
      storageAddress: planned.storageAddress,
      owner: handle.address,
      data: planned.data,
      sizeBytes: 0,
      createdAt: new Date(0).toISOString(),
    };
    stored.set(planned.storageAddress, result);
    return { txHash: 'dry-run' };
  };
  const ledger = await createProofLedger({
    handle,
    rpc: 'offline:',
    ledgerName,
    broadcastImpl,
    fetchAnchoredImpl: fetchImpl,
  });
  const plans = [];
  for (const entry of entries) {
    const plan = await ledger.plan(entry);
    plans.push(publicPlan(plan));
    await ledger.append(entry);
  }
  console.log(JSON.stringify({ mode: 'dry-run', plans }));
}

async function runLive(entries: ReceiptEntry[], ledgerName: string, head?: string): Promise<void> {
  config({ path: process.env.DACS_ENV_PATH ?? '.env' });
  const rpc = process.env.DEMOS_RPC ?? 'https://demosnode.discus.sh/';
  const { connectDemos, mnemonicFromEnv } = await import('../demos/connection.js');
  const mnemonic = mnemonicFromEnv('DEMOS_MNEMONIC');
  const handle = await connectDemos(mnemonic, rpc);
  const ledger = await createProofLedger({
    handle,
    rpc,
    ledgerName,
    ...(head === undefined ? {} : { head: { storageAddress: head } }),
  });
  const appends = [];
  for (const entry of entries) appends.push(await ledger.append(entry));
  const verify = await ledger.verify();
  console.log(JSON.stringify({ mode: 'live', appends, verify }));
  if (verify.outcome !== 'pass') process.exitCode = 1;
}

try {
  const args = parseArgs(process.argv.slice(2));
  const entries = await entriesFromInputs(args.inputs);
  if (args.dryRun) await runDry(entries, args.ledgerName);
  else if (process.env.LIVE === '1') await runLive(entries, args.ledgerName, args.head);
  else throw new Error('refusing to append without LIVE=1 or --dry-run');
} catch (error) {
  // Do not echo errors wholesale: paths and environment-derived SDK errors can contain sensitive
  // material. Surface only a short, plain-text reason with no path, separator, or newline characters.
  const message = error instanceof Error ? error.message : String(error);
  const safe = /^[A-Za-z0-9 .,:;#()'\[\]-]{1,160}$/.test(message) ? message : undefined;
  console.error(JSON.stringify({ ok: false, error: 'proof ledger command failed', ...(safe ? { reason: safe } : {}) }));
  process.exit(1);
}
