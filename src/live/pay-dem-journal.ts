import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { appendFile, mkdir, open } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import type { PayDemPreparedTransfer } from '../adapters/dacs/sdk-pay-dem-types.js';

export const DEFAULT_PAY_DEM_JOURNAL = join(
  homedir(),
  '.pathos-dacs-ref',
  'pay-dem-journal.jsonl',
);

function gitWorkTreeRoot(path: string): string | undefined {
  let cursor = path;
  while (true) {
    const marker = join(cursor, '.git');
    if (existsSync(marker)) {
      const stat = lstatSync(marker);
      const isRepositoryDirectory = stat.isDirectory() && existsSync(join(marker, 'HEAD'));
      const isWorkTreeFile = stat.isFile() && /^gitdir:\s*\S/m.test(readFileSync(marker, 'utf8'));
      if (isRepositoryDirectory || isWorkTreeFile) return cursor;
    }
    const parent = dirname(cursor);
    if (parent === cursor) return undefined;
    cursor = parent;
  }
}

function canonicalPotentialPath(path: string): string {
  const missingParts: string[] = [];
  let cursor = path;
  while (!existsSync(cursor)) {
    missingParts.unshift(basename(cursor));
    cursor = dirname(cursor);
  }
  return resolve(realpathSync(cursor), ...missingParts);
}

/** Resolve a journal target and reject any path within a Git working tree. */
export function resolvePayDemJournalPath(path: string): string {
  if (typeof path !== 'string' || path.length === 0 || path.trim() !== path) {
    throw new Error('pay-dem journal path must be a non-empty exact string');
  }
  const absolute = isAbsolute(path) ? resolve(path) : resolve(process.cwd(), path);
  const resolved = canonicalPotentialPath(absolute);
  const workTree = gitWorkTreeRoot(dirname(resolved));
  if (workTree !== undefined) {
    throw new Error(`pay-dem journal path must be outside a Git working tree: ${workTree}`);
  }
  return resolved;
}

/** Create a durable append-only JSONL journal; each invocation writes exactly one record. */
export function createPayDemJsonlJournal(path: string = DEFAULT_PAY_DEM_JOURNAL) {
  const target = resolvePayDemJournalPath(path);
  return async (prepared: Readonly<PayDemPreparedTransfer>): Promise<void> => {
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const handle = await open(target, 'a', 0o600);
    try {
      await appendFile(handle, `${JSON.stringify(prepared)}\n`, { encoding: 'utf8' });
      await handle.sync();
    } finally {
      await handle.close();
    }
  };
}
