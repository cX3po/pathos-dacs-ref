import { randomUUID } from 'node:crypto';
import {
  accessSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { appendFile, mkdir, open } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import type { PayDemPreparedTransfer } from '../adapters/dacs/sdk-pay-dem-types.js';
import { utcDateOrThrow } from './pay-policy.js';

export const DEFAULT_PAY_DEM_JOURNAL = join(
  homedir(),
  '.pathos-dacs-ref',
  'pay-dem-journal.jsonl',
);

const LOCK_STALE_MS = 60 * 60 * 1_000;

interface PayDemLockOwner {
  token: string;
  pid: number;
  hostname: string;
  createdAt: number;
}

export interface PayDemJournalLease {
  release(): void;
}

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
  // Refuse a journal inside any checkout, with one deliberate exception: a dotfiles repository
  // rooted at the home directory itself, which would otherwise make the default path unusable.
  const currentCheckout = gitWorkTreeRoot(process.cwd());
  const homeRoot = (() => { try { return realpathSync(homedir()); } catch { return homedir(); } })();
  if (workTree !== undefined && (workTree === currentCheckout || workTree !== homeRoot)) {
    throw new Error(`pay-dem journal path must be outside a Git working tree: ${workTree}`);
  }
  return resolved;
}

/** Read JSONL, treating only ENOENT as an empty journal. */
export function readPayDemJournalOrEmpty(
  path: string,
  reader: (path: string, encoding: BufferEncoding) => string = readFileSync,
): unknown[] {
  let text: string;
  try {
    text = reader(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  return text.split('\n').filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
}

/** Check the kill switch, treating only ENOENT as absent. */
export function payKillSwitchPresent(
  path: string,
  access: (path: string, mode: number) => void = accessSync,
): boolean {
  try {
    access(path, fsConstants.F_OK);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function processIsAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function readLockOwner(path: string): PayDemLockOwner | undefined {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as Partial<PayDemLockOwner>;
    if (typeof value.token !== 'string' || !Number.isSafeInteger(value.pid) ||
      typeof value.hostname !== 'string' || !Number.isFinite(value.createdAt)) return undefined;
    return value as PayDemLockOwner;
  } catch {
    return undefined;
  }
}

function syncDirectory(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EINVAL' && code !== 'ENOSYS' && code !== 'ENOTSUP') throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function tryCreateLock(path: string, owner: PayDemLockOwner): boolean {
  let fd: number | undefined;
  let created = false;
  try {
    fd = openSync(path, 'wx', 0o600);
    created = true;
    writeFileSync(fd, JSON.stringify(owner), 'utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    syncDirectory(dirname(path));
    return true;
  } catch (error) {
    if (!created && (error as NodeJS.ErrnoException).code === 'EEXIST') return false;
    if (created) {
      try { unlinkSync(path); } catch (cleanupError) {
        if ((cleanupError as NodeJS.ErrnoException).code !== 'ENOENT') throw cleanupError;
      }
    }
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Acquire the journal's cross-process O_EXCL lease or fail closed immediately. */
export function acquirePayDemJournalLock(path: string): PayDemJournalLease {
  const target = resolvePayDemJournalPath(path);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const lockPath = `${target}.lock`;
  const owner: PayDemLockOwner = {
    token: randomUUID(),
    pid: process.pid,
    hostname: hostname(),
    createdAt: Date.now(),
  };

  if (!tryCreateLock(lockPath, owner)) {
    const existing = readLockOwner(lockPath);
    let stale = existing !== undefined
      ? (existing.hostname === hostname() ? !processIsAlive(existing.pid) : Date.now() - existing.createdAt >= LOCK_STALE_MS)
      : false;
    if (existing === undefined) {
      try { stale = Date.now() - statSync(lockPath).mtimeMs >= LOCK_STALE_MS; } catch { stale = false; }
    }
    if (!stale) throw new Error(`payment journal lock is already held: ${lockPath}`);

    const quarantine = `${lockPath}.${randomUUID()}.stale`;
    try {
      renameSync(lockPath, quarantine);
    } catch (error) {
      throw new Error(`payment journal lock could not be acquired: ${(error as Error).message}`);
    }
    try {
      if (!tryCreateLock(lockPath, owner)) throw new Error(`payment journal lock is already held: ${lockPath}`);
    } finally {
      try { unlinkSync(quarantine); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      syncDirectory(dirname(lockPath));
    }
  }

  let released = false;
  return {
    release() {
      if (released) return;
      const current = readLockOwner(lockPath);
      if (current?.token !== owner.token) throw new Error('payment journal lock ownership was lost');
      unlinkSync(lockPath);
      syncDirectory(dirname(lockPath));
      released = true;
    },
  };
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

export interface PayDemJournalOutcome {
  timestamp: string;
  amountOs: string;
  /** `aborted-before-broadcast` records a transfer that never reached broadcast. */
  outcome: string;
  settlementKey?: string;
  txHash?: string;
}

/** A settlement resolution: the prepared transfer for `settlementKey` ended as settled (evidence anchored) or refunded. No amount: it is not spend. */
export interface PayDemJournalResolution {
  timestamp: string;
  resolution: 'settled' | 'refunded';
  settlementKey: string;
  txHash: string;
}

/** Append a policy-accounting outcome to the same durable JSONL journal. */
export function createPayDemOutcomeJournal(path: string = DEFAULT_PAY_DEM_JOURNAL) {
  const target = resolvePayDemJournalPath(path);
  return async (outcome: Readonly<PayDemJournalOutcome | PayDemJournalResolution>): Promise<void> => {
    utcDateOrThrow(outcome.timestamp);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const handle = await open(target, 'a', 0o600);
    try {
      await appendFile(handle, `${JSON.stringify(outcome)}\n`, { encoding: 'utf8' });
      await handle.sync();
    } finally {
      await handle.close();
    }
  };
}
