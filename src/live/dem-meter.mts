#!/usr/bin/env node

import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { createDemMeter } from '../adapters/demos/dem-meter.js';

export const DEFAULT_DEM_METER_PATH = join(homedir(), '.pathos-dacs-ref', 'dem-meter.jsonl');

type Args = {
  action: 'summary' | 'invoice' | 'verify' | 'repair';
  path: string;
  since?: string;
  until?: string;
  agent?: string;
  from?: string;
  to?: string;
};

function parseArgs(argv: string[], env: Readonly<NodeJS.ProcessEnv>): Args {
  let action: Args['action'] | undefined;
  let path = env.DACS_DEM_METER || DEFAULT_DEM_METER_PATH;
  let since: string | undefined;
  let until: string | undefined;
  let agent: string | undefined;
  let from: string | undefined;
  let to: string | undefined;
  const value = (flag: string, index: number): string => {
    const candidate = argv[index + 1];
    if (candidate === undefined || candidate.startsWith('--')) throw new Error(`${flag} requires a value`);
    return candidate;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--summary' || arg === '--invoice' || arg === '--verify' || arg === '--repair') {
      if (action !== undefined) throw new Error('choose exactly one meter command');
      action = arg.slice(2) as Args['action'];
    } else if (arg === '--path') {
      path = value(arg, i); i += 1;
    } else if (arg === '--since') {
      since = value(arg, i); i += 1;
    } else if (arg === '--until') {
      until = value(arg, i); i += 1;
    } else if (arg === '--agent') {
      agent = value(arg, i); i += 1;
    } else if (arg === '--from') {
      from = value(arg, i); i += 1;
    } else if (arg === '--to') {
      to = value(arg, i); i += 1;
    } else {
      throw new Error('unknown meter argument');
    }
  }
  if (action === undefined) throw new Error('a meter command is required');
  if (action === 'invoice' && (!from || !to || !since || !until)) {
    throw new Error('invoice requires from, to, since, and until');
  }
  if (action !== 'invoice' && (from !== undefined || to !== undefined)) {
    throw new Error('from and to apply only to invoice');
  }
  if (action !== 'summary' && agent !== undefined) throw new Error('agent applies only to summary');
  if ((action === 'verify' || action === 'repair') && (since !== undefined || until !== undefined)) {
    throw new Error('since and until do not apply to verify or repair');
  }
  return { action, path, ...(since ? { since } : {}), ...(until ? { until } : {}),
    ...(agent ? { agent } : {}), ...(from ? { from } : {}), ...(to ? { to } : {}) };
}

export function runDemMeterCli(
  argv: string[],
  env: Readonly<NodeJS.ProcessEnv> = process.env,
): unknown {
  const args = parseArgs(argv, env);
  const meter = createDemMeter({ path: args.path });
  if (args.action === 'summary') {
    return meter.summarize({
      ...(args.since === undefined ? {} : { since: args.since }),
      ...(args.until === undefined ? {} : { until: args.until }),
      ...(args.agent === undefined ? {} : { agent: args.agent }),
    });
  }
  if (args.action === 'invoice') {
    return meter.invoice({
      from: args.from!, to: args.to!, since: args.since!, until: args.until!,
    });
  }
  if (args.action === 'repair') return meter.repair();
  const rows = meter.read();
  return { ok: true, rowCount: rows.length, meterHead: rows.at(-1)?.rowHash ?? null };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const output = runDemMeterCli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(output)}\n`);
  } catch {
    // Do not echo input, paths, environment values, or dependency errors.
    process.stderr.write(`${JSON.stringify({ ok: false, error: 'DEM meter command failed' })}\n`);
    process.exitCode = 1;
  }
}
