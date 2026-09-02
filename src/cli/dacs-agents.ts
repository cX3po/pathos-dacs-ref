#!/usr/bin/env node

import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  claimRefFor,
  loadAgentsConfig,
  resolveAgent,
} from '../adapters/demos/identity.js';

const DEFAULT_CONFIG = 'config/dacs-agents.json';
const EXAMPLE_CONFIG = 'config/dacs-agents.example.json';

type Environment = Readonly<Record<string, string | undefined>>;
type Output = Pick<NodeJS.WritableStream, 'write'>;

function line(stdout: Output, value: string): void {
  stdout.write(`${value}\n`);
}

export function main(
  argv: readonly string[],
  env: Environment = process.env,
  stdout: Output = process.stdout,
): number {
  try {
    const [command, ...args] = argv;
    if (command === 'claim' && args.length === 1) {
      line(stdout, claimRefFor(args[0]!));
      return 0;
    }

    if (command !== 'check') {
      throw new Error('Usage: dacs-agents check [--config path] | dacs-agents claim <address>');
    }

    let configPath = DEFAULT_CONFIG;
    if (args.length === 2 && args[0] === '--config') {
      configPath = args[1]!;
    } else if (args.length !== 0) {
      throw new Error('Usage: dacs-agents check [--config path]');
    }

    if (configPath === DEFAULT_CONFIG && !existsSync(configPath)) {
      configPath = EXAMPLE_CONFIG;
      line(stdout, `Notice: ${DEFAULT_CONFIG} not found; using ${EXAMPLE_CONFIG}`);
    }

    const config = loadAgentsConfig(configPath);
    for (const [name, agent] of Object.entries(config.agents)) {
      const resolved = resolveAgent(config, name, env);
      line(
        stdout,
        `${name} ${agent.role} ${agent.mnemonicEnv} ${resolved.hasSecret ? 'yes' : 'no'} ${agent.claimRef ?? '(derived after first unlock)'}`,
      );
    }
    return 0;
  } catch (error) {
    line(stdout, error instanceof Error ? error.message : String(error));
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
