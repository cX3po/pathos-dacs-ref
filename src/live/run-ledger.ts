import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, hostname } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';

import {
  DEMOS_WRITE_JOURNAL_VERSION,
  type DemosWriteJournal,
  type DemosWriteJournalKey,
  type DemosWriteJournalRecord,
  type DemosWriteJournalSnapshot,
  type DemosWriteStage,
  type SettleResult,
  type SettlementIdempotencyStore,
  type SettlementLog,
} from '../adapters/dacs/sdk-journal-types.js';

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
// An unparsable lock can only be judged by mtime. Keep its stale threshold
// below the default acquisition timeout so crash debris is reclaimable by a
// single acquire attempt.
const DEFAULT_LOCK_STALE_MS = 5_000;
const DEFAULT_LOCK_TIMEOUT_MS = 10_000;
const LOCK_RETRY_MS = 10;

interface LockOwner {
  token: string;
  pid: number;
  hostname: string;
  createdAt: number;
}

export interface ReconcileReport {
  journals: Array<{
    chainIdentity: string;
    wallet: string;
    generation: number;
    byStage: Partial<Record<DemosWriteStage, number>>;
    unresolved: Array<{
      writeId: string;
      stage: DemosWriteStage;
      nonce: number;
      txRef?: string;
    }>;
  }>;
  settlements: { outcomes: number; openIntents: string[] };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.trim() === value;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function validOptionalString(value: unknown): boolean {
  return value === undefined || nonEmpty(value);
}

function gitAncestor(path: string): string | undefined {
  let current = resolve(path);
  for (;;) {
    const marker = join(current, '.git');
    if (existsSync(marker)) {
      // Managed sandboxes can expose an empty sentinel directory named .git;
      // only a file marker or a populated repository directory denotes a tree.
      if (!statSync(marker).isDirectory() || readdirSync(marker).length > 0) return current;
    }
    const parent = dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function realpathWithMissingTail(path: string): string {
  let existing = resolve(path);
  const tail: string[] = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) break;
    tail.push(basename(existing));
    existing = parent;
  }
  return join(realpathSync(existing), ...tail.reverse());
}

function refuseGitLedger(path: string): void {
  const ancestor = gitAncestor(path);
  if (ancestor) {
    throw new Error(
      `DACS run ledger directory ${path} is inside git working tree ${ancestor}; choose DACS_RUN_LEDGER_DIR outside the checkout`,
    );
  }
}

function prepareLedgerRoot(path: string): string {
  const candidate = realpathWithMissingTail(path);
  refuseGitLedger(candidate);
  mkdirSync(candidate, { recursive: true, mode: DIR_MODE });
  const created = realpathSync(candidate);
  refuseGitLedger(created);
  return created;
}

function containedBy(parent: string, child: string): boolean {
  const remainder = relative(parent, child);
  return remainder === '' || (!isAbsolute(remainder) && remainder !== '..' && !remainder.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`));
}

function createContainedDirectory(parent: string, name: string): string {
  const parentReal = realpathSync(parent);
  const path = join(parentReal, name);
  mkdirSync(path, { recursive: true, mode: DIR_MODE });
  const pathReal = realpathSync(path);
  if (!containedBy(parentReal, pathReal)) {
    throw new Error(`Demos write journal directory ${path} resolves outside ${parentReal}`);
  }
  return pathReal;
}

export function resolveRunLedgerDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.DACS_RUN_LEDGER_DIR;
  const dir = realpathWithMissingTail(configured && configured.trim().length > 0
    ? configured
    : join(homedir(), '.pathos-dacs-ref', 'run-ledger'));
  refuseGitLedger(dir);
  return dir;
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

function atomicWriteJson(path: string, value: unknown, beforeRename?: () => void): void {
  mkdirSync(dirname(path), { recursive: true, mode: DIR_MODE });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temporary, 'wx', FILE_MODE);
    writeFileSync(fd, JSON.stringify(value), 'utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    beforeRename?.();
    renameSync(temporary, path);
    syncDirectory(dirname(path));
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temporary, { force: true });
  }
}

const WRITE_KINDS = new Set(['mutable', 'immutable']);
const WRITE_OPERATIONS = new Set(['create', 'update']);
const WRITE_STAGES = new Set<DemosWriteStage>([
  'prepared', 'signed', 'broadcast-intent', 'canonical-confirmed',
  'canonical-failed', 'native-visible', 'index-visible',
]);

function invalidRecord(path: string, index: number, reason: string): never {
  throw new Error(`Demos write journal record ${index} in ${path} ${reason}`);
}

function validateJournalRecord(
  value: unknown,
  snapshotGeneration: number,
  index: number,
  expectedWallet: string,
  path: string,
): DemosWriteJournalRecord {
  if (!isObject(value)) invalidRecord(path, index, 'is not a JSON object');
  const record = value as Record<string, unknown>;
  if (
    !nonEmpty(record.writeId) ||
    !nonNegativeInteger(record.generation) || record.generation === 0 ||
    record.generation > snapshotGeneration ||
    !WRITE_KINDS.has(String(record.kind)) ||
    !WRITE_OPERATIONS.has(String(record.operation)) ||
    !WRITE_STAGES.has(record.stage as DemosWriteStage) ||
    !nonEmpty(record.logicalName) || !nonEmpty(record.programName) ||
    !nonEmpty(record.owner) || record.owner.toLowerCase() !== expectedWallet.toLowerCase() ||
    !nonEmpty(record.nativeAddress) || !nonEmpty(record.valueHash) ||
    !validOptionalString(record.metadataHash) || !nonNegativeInteger(record.nonce) ||
    !nonNegativeInteger(record.updatedAt) || !validOptionalString(record.txRef) ||
    !validOptionalString(record.signedTransaction) ||
    !validOptionalString(record.signedTransactionHash) ||
    (record.blockNumber !== undefined && !nonNegativeInteger(record.blockNumber)) ||
    !validOptionalString(record.blockHash) ||
    (record.blockTimestamp !== undefined && !nonNegativeInteger(record.blockTimestamp)) ||
    !validOptionalString(record.finalityProof) ||
    !validOptionalString(record.finalityProofHash)
  ) invalidRecord(path, index, 'has invalid fields');

  const stage = record.stage as DemosWriteStage;
  if (stage !== 'prepared' && (
    !nonEmpty(record.txRef) || !nonEmpty(record.signedTransaction) ||
    !nonEmpty(record.signedTransactionHash)
  )) invalidRecord(path, index, `at stage ${stage} lacks its signed transaction`);
  if (['canonical-confirmed', 'native-visible', 'index-visible'].includes(stage) && (
    !nonNegativeInteger(record.blockNumber) || !nonEmpty(record.blockHash) ||
    !nonNegativeInteger(record.blockTimestamp) || !nonEmpty(record.finalityProof) ||
    !nonEmpty(record.finalityProofHash)
  )) invalidRecord(path, index, `at stage ${stage} lacks canonical block evidence`);

  if (record.nativeRead !== undefined) {
    if (!isObject(record.nativeRead)) invalidRecord(path, index, 'has invalid native readback');
    const native = record.nativeRead as Record<string, unknown>;
    if (!nonEmpty(native.owner) || native.owner.toLowerCase() !== record.owner.toLowerCase() ||
      native.programName !== record.programName || native.valueHash !== record.valueHash ||
      native.metadataHash !== record.metadataHash || !nonNegativeInteger(native.observedAt)) {
      invalidRecord(path, index, 'has a native readback that does not bind its write');
    }
  }
  if (['native-visible', 'index-visible'].includes(stage) && record.nativeRead === undefined) {
    invalidRecord(path, index, `at stage ${stage} lacks native readback`);
  }
  if (record.indexRead !== undefined) {
    if (!isObject(record.indexRead)) invalidRecord(path, index, 'has invalid index observation');
    const observed = record.indexRead as Record<string, unknown>;
    if (observed.address !== record.nativeAddress || !nonNegativeInteger(observed.observedAt)) {
      invalidRecord(path, index, 'has an index observation that does not bind its native address');
    }
  }
  if (stage === 'index-visible' && record.indexRead === undefined) {
    invalidRecord(path, index, 'at stage index-visible lacks its index observation');
  }
  return structuredClone(value) as unknown as DemosWriteJournalRecord;
}

function readSnapshot(
  path: string,
  key: DemosWriteJournalKey,
): DemosWriteJournalSnapshot | undefined {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`Demos write journal snapshot ${path} contains invalid JSON`);
  }
  if (!isObject(value)) throw new Error(`Demos write journal snapshot ${path} is not a JSON object`);
  if (value.version !== DEMOS_WRITE_JOURNAL_VERSION) {
    throw new Error(`Demos write journal snapshot ${path} has unsupported version ${String(value.version)}`);
  }
  if (value.chainIdentity !== key.chainIdentity || value.wallet !== key.wallet) {
    throw new Error(`Demos write journal snapshot ${path} key does not match its path`);
  }
  if (!nonNegativeInteger(value.generation)) {
    throw new Error(`Demos write journal snapshot ${path} generation is invalid`);
  }
  if (!Array.isArray(value.records)) {
    throw new Error(`Demos write journal snapshot ${path} records are invalid`);
  }
  const records = value.records.map((record, index) =>
    validateJournalRecord(record, value.generation as number, index, key.wallet, path));
  if (new Set(records.map(({ writeId }) => writeId)).size !== records.length) {
    throw new Error(`Demos write journal snapshot ${path} contains duplicate write ids`);
  }
  return {
    version: DEMOS_WRITE_JOURNAL_VERSION,
    chainIdentity: key.chainIdentity,
    wallet: key.wallet,
    generation: value.generation as number,
    records,
  };
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

function readLock(path: string): LockOwner | undefined {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!isObject(value) || !nonEmpty(value.token) || !nonNegativeInteger(value.pid) ||
      !nonEmpty(value.hostname) || !nonNegativeInteger(value.createdAt)) return undefined;
    return value as unknown as LockOwner;
  } catch {
    return undefined;
  }
}

function tryCreateLock(path: string, owner: LockOwner): boolean {
  const temporary = `${path}.${process.pid}.${owner.token}.tmp`;
  let claimFd: number | undefined;
  let ownerFd: number | undefined;
  let claimed = false;
  try {
    claimFd = openSync(path, 'wx', FILE_MODE);
    claimed = true;
    closeSync(claimFd);
    claimFd = undefined;
    ownerFd = openSync(temporary, 'wx', FILE_MODE);
    writeFileSync(ownerFd, JSON.stringify(owner), 'utf8');
    fsyncSync(ownerFd);
    closeSync(ownerFd);
    ownerFd = undefined;
    renameSync(temporary, path);
    syncDirectory(dirname(path));
    return true;
  } catch (error) {
    if (!claimed && (error as NodeJS.ErrnoException).code === 'EEXIST') return false;
    if (claimed) {
      try { unlinkSync(path); } catch (cleanupError) {
        if ((cleanupError as NodeJS.ErrnoException).code !== 'ENOENT') throw cleanupError;
      }
    }
    throw error;
  } finally {
    if (claimFd !== undefined) closeSync(claimFd);
    if (ownerFd !== undefined) closeSync(ownerFd);
    rmSync(temporary, { force: true });
  }
}

function releaseOwnedLock(path: string, token: string): void {
  const quarantine = `${path}.${randomUUID()}.release`;
  try {
    renameSync(path, quarantine);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  if (readLock(quarantine)?.token === token) {
    unlinkSync(quarantine);
    syncDirectory(dirname(path));
    return;
  }
  try {
    // link(2) supplies the no-replace restore that rename(2) lacks on POSIX.
    // If a contender filled the live name, its lock remains untouched.
    linkSync(quarantine, path);
    unlinkSync(quarantine);
    syncDirectory(dirname(path));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    unlinkSync(quarantine);
  }
}

function journalKeyDigest(key: DemosWriteJournalKey): string {
  return createHash('sha256')
    .update(key.chainIdentity)
    .update('\0')
    .update(key.wallet)
    .digest('hex');
}

function wait(ms: number): Promise<void> {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
}

export function createFsDemosWriteJournal(opts: {
  dir: string;
  lockStaleMs?: number;
  lockTimeoutMs?: number;
}): DemosWriteJournal {
  if (!opts || !nonEmpty(opts.dir)) throw new Error('filesystem Demos write journal requires a directory');
  const lockStaleMs = opts.lockStaleMs ?? DEFAULT_LOCK_STALE_MS;
  const lockTimeoutMs = opts.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
  if (!Number.isFinite(lockStaleMs) || lockStaleMs <= 0) {
    throw new Error('Demos write journal lockStaleMs must be positive');
  }
  if (!Number.isFinite(lockTimeoutMs) || lockTimeoutMs <= 0) {
    throw new Error('Demos write journal lockTimeoutMs must be positive');
  }
  if (lockStaleMs > lockTimeoutMs) {
    throw new Error('Demos write journal lockStaleMs must not exceed lockTimeoutMs');
  }
  const rootDir = prepareLedgerRoot(opts.dir);
  const journalDir = createContainedDirectory(rootDir, 'journal');

  return {
    async acquire(input) {
      if (!nonEmpty(input.chainIdentity) || !nonEmpty(input.wallet)) {
        throw new Error('Demos write journal key requires chainIdentity and wallet');
      }
      const key = Object.freeze({ chainIdentity: input.chainIdentity, wallet: input.wallet });
      const digest = journalKeyDigest(key);
      const walletDir = createContainedDirectory(journalDir, digest);
      const snapshotPath = join(walletDir, 'snapshot.json');
      const lockPath = join(walletDir, 'lock.json');
      const token = randomUUID();
      const owner: LockOwner = { token, pid: process.pid, hostname: hostname(), createdAt: Date.now() };
      const deadline = Date.now() + lockTimeoutMs;

      for (;;) {
        if (tryCreateLock(lockPath, owner)) break;
        const existing = readLock(lockPath);
        let reclaim = existing?.hostname === hostname() && !processIsAlive(existing.pid);
        if (!existing) {
          try { reclaim = Date.now() - statSync(lockPath).mtimeMs >= lockStaleMs; } catch { reclaim = false; }
        }
        if (reclaim) {
          const quarantine = `${lockPath}.${randomUUID()}.reclaim`;
          try {
            renameSync(lockPath, quarantine);
            rmSync(quarantine, { force: true });
            syncDirectory(dirname(lockPath));
          } catch (error) {
            const code = (error as NodeJS.ErrnoException).code;
            if (code !== 'ENOENT' && code !== 'EEXIST') throw error;
          }
          continue;
        }
        if (Date.now() >= deadline) {
          throw new Error(`timed out acquiring Demos wallet journal ${key.chainIdentity}/${key.wallet}`);
        }
        await wait(LOCK_RETRY_MS);
      }

      let released = false;
      try {
        const prior = readSnapshot(snapshotPath, key);
        const generation = (prior?.generation ?? 0) + 1;
        const initial: DemosWriteJournalSnapshot = {
          version: DEMOS_WRITE_JOURNAL_VERSION,
          ...key,
          generation,
          records: structuredClone(prior?.records ?? []),
        };
        const noLongerCurrent = (): never => {
          throw new Error(`Demos write journal fence ${generation} is no longer current`);
        };
        const assertFence = (expectedDiskGeneration: number): void => {
          const diskGeneration = readSnapshot(snapshotPath, key)?.generation ?? 0;
          if (diskGeneration !== expectedDiskGeneration || readLock(lockPath)?.token !== token) {
            noLongerCurrent();
          }
        };
        atomicWriteJson(snapshotPath, initial, () => assertFence(prior?.generation ?? 0));
        let current = initial;
        let putTail = Promise.resolve();

        const assertCurrent = async (): Promise<void> => {
          if (released) throw new Error(`Demos write journal fence ${generation} was released`);
          assertFence(generation);
        };

        return {
          key,
          generation,
          get snapshot() { return structuredClone(current); },
          async put(record) {
            const operation = putTail.then(async () => {
              await assertCurrent();
              if (record.generation !== generation) {
                throw new Error(`Demos write record generation ${record.generation} does not match lease ${generation}`);
              }
              const checked = validateJournalRecord(
                record, generation, current.records.length, key.wallet, snapshotPath,
              );
              const records = current.records
                .filter((candidate) => candidate.writeId !== checked.writeId)
                .map((candidate) => structuredClone(candidate));
              records.push(checked);
              const next = { ...current, records };
              atomicWriteJson(snapshotPath, next, () => assertFence(generation));
              current = next;
            });
            putTail = operation.catch(() => undefined);
            await operation;
          },
          assertCurrent,
          async release() {
            if (released) return;
            await putTail;
            released = true;
            releaseOwnedLock(lockPath, token);
          },
        };
      } catch (error) {
        releaseOwnedLock(lockPath, token);
        throw error;
      }
    },
  };
}

function keyHash(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

function validSettlementFinality(value: unknown): boolean {
  if (!isObject(value)) return false;
  if (value.model === 'block-depth') {
    return value.finalityCommitmentLevel === undefined &&
      (value.finalityBlocks === undefined || nonNegativeInteger(value.finalityBlocks));
  }
  if (value.model === 'commitment-level') {
    return value.finalityBlocks === undefined &&
      (value.finalityCommitmentLevel === undefined ||
        ['processed', 'confirmed', 'finalized'].includes(String(value.finalityCommitmentLevel)));
  }
  return ['provider-receipt', 'htlc-reveal', 'liquidity-tank', 'bft-final'].includes(String(value.model)) &&
    value.finalityBlocks === undefined && value.finalityCommitmentLevel === undefined;
}

function validateOutcome(value: unknown, path: string): SettleResult {
  if (!isObject(value) || typeof value.ok !== 'boolean' || typeof value.txHash !== 'string' ||
    typeof value.chainId !== 'string' || typeof value.payer !== 'string' ||
    typeof value.payee !== 'string' ||
    (value.blockNumber !== undefined && !nonNegativeInteger(value.blockNumber)) ||
    (value.txRefKind !== undefined && typeof value.txRefKind !== 'string') ||
    (value.finality !== undefined && !validSettlementFinality(value.finality))) {
    throw new Error(`settlement outcome ${path} is schema-invalid`);
  }
  return structuredClone(value) as unknown as SettleResult;
}

export function createFsSettlementLog(opts: { dir: string }): SettlementLog {
  if (!opts || !nonEmpty(opts.dir)) throw new Error('filesystem settlement log requires a directory');
  const rootDir = prepareLedgerRoot(opts.dir);
  const settlementDir = createContainedDirectory(rootDir, 'settlement');
  const paths = (key: string) => {
    const hash = keyHash(key);
    return {
      hash,
      outcome: join(settlementDir, `${hash}.outcome.json`),
      intent: join(settlementDir, `${hash}.intent`),
    };
  };
  return {
    async getOutcome(key) {
      const path = paths(key).outcome;
      let text: string;
      try { text = readFileSync(path, 'utf8'); } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw error;
      }
      try { return validateOutcome(JSON.parse(text) as unknown, path); } catch (error) {
        if (error instanceof SyntaxError) throw new Error(`settlement outcome ${path} contains invalid JSON`);
        throw error;
      }
    },
    async putOutcome(key, res) {
      const { outcome: path, intent } = paths(key);
      atomicWriteJson(path, validateOutcome(res, path));
      try {
        unlinkSync(intent);
        syncDirectory(settlementDir);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    },
    async claimIntent(key) {
      const { hash, intent } = paths(key);
      let fd: number | undefined;
      try {
        // O_EXCL is the cross-process compare-and-set for the write-ahead intent.
        fd = openSync(intent, 'wx', FILE_MODE);
        writeFileSync(fd, JSON.stringify({ version: 1, keyHash: hash, pid: process.pid, hostname: hostname(), createdAt: Date.now() }), 'utf8');
        fsyncSync(fd);
        closeSync(fd);
        fd = undefined;
        syncDirectory(settlementDir);
        return 'claimed';
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') return 'held';
        throw error;
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
    },
    async releaseIntent(key) {
      try {
        unlinkSync(paths(key).intent);
        syncDirectory(settlementDir);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    },
  };
}

const isDefinitive = (res: SettleResult): boolean => res.ok && res.txHash.trim().length > 0;

export function createIdempotencyStore(log: SettlementLog): SettlementIdempotencyStore {
  const inflight = new Map<string, Promise<SettleResult>>();
  return {
    async once(key, submit, reconcileFn) {
      const recorded = await log.getOutcome(key);
      if (recorded) return recorded;
      const flying = inflight.get(key);
      if (flying) return flying;

      const operation = (async () => {
        if ((await log.claimIntent(key)) === 'held') {
          const now = await log.getOutcome(key);
          if (now) return now;
          if (!reconcileFn) {
            throw new Error(
              `settlement ${key} has an unresolved or in-flight prior attempt and no reconcile capability; refusing to resubmit (double-pay risk)`,
            );
          }
          const found = await reconcileFn(key);
          if (found && isDefinitive(found)) {
            await log.putOutcome(key, found);
            return found;
          }
        }
        const result = await submit();
        if (isDefinitive(result)) {
          await log.putOutcome(key, result);
        } else if (!result.txHash || result.txHash.trim().length === 0) {
          await log.releaseIntent(key);
        }
        return result;
      })();
      inflight.set(key, operation);
      try { return await operation; } finally { inflight.delete(key); }
    },
  };
}

export function openRunLedger(env: NodeJS.ProcessEnv = process.env): {
  dir: string;
  journal: DemosWriteJournal;
  settlementLog: SettlementLog;
  idempotency: SettlementIdempotencyStore;
} {
  const dir = resolveRunLedgerDir(env);
  prepareLedgerRoot(dir);
  const journal = createFsDemosWriteJournal({ dir });
  const settlementLog = createFsSettlementLog({ dir });
  return { dir, journal, settlementLog, idempotency: createIdempotencyStore(settlementLog) };
}

function childDirectories(path: string): string[] {
  try {
    return readdirSync(path, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

export function reconcile(dir: string): ReconcileReport {
  const root = resolve(dir);
  const journals: ReconcileReport['journals'] = [];
  for (const digest of childDirectories(join(root, 'journal'))) {
    const path = join(root, 'journal', digest, 'snapshot.json');
    let identity: unknown;
    try { identity = JSON.parse(readFileSync(path, 'utf8')) as unknown; } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      if (error instanceof SyntaxError) throw new Error(`Demos write journal snapshot ${path} contains invalid JSON`);
      throw error;
    }
    if (!isObject(identity) || !nonEmpty(identity.chainIdentity) || !nonEmpty(identity.wallet)) {
      throw new Error(`Demos write journal snapshot ${path} has invalid key fields`);
    }
    const snapshot = readSnapshot(path, {
      chainIdentity: identity.chainIdentity,
      wallet: identity.wallet,
    });
    if (!snapshot) continue;
    const byStage: Partial<Record<DemosWriteStage, number>> = {};
    const unresolved: ReconcileReport['journals'][number]['unresolved'] = [];
    for (const record of snapshot.records) {
      byStage[record.stage] = (byStage[record.stage] ?? 0) + 1;
      if (record.stage !== 'canonical-failed' && record.stage !== 'index-visible') {
        unresolved.push({
          writeId: record.writeId,
          stage: record.stage,
          nonce: record.nonce,
          ...(record.txRef === undefined ? {} : { txRef: record.txRef }),
        });
      }
    }
    journals.push({ chainIdentity: snapshot.chainIdentity, wallet: snapshot.wallet, generation: snapshot.generation, byStage, unresolved });
  }
  const settlementDir = join(root, 'settlement');
  let names: string[] = [];
  try { names = readdirSync(settlementDir).sort(); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const outcomeNames = names.filter((name) => /^[a-f0-9]{64}\.outcome\.json$/.test(name));
  // A status report must not turn a corrupt durable outcome into a reassuring
  // count; validate each record without including its body in any error.
  for (const name of outcomeNames) {
    const path = join(settlementDir, name);
    let value: unknown;
    try { value = JSON.parse(readFileSync(path, 'utf8')) as unknown; } catch {
      throw new Error(`settlement outcome ${path} contains invalid JSON`);
    }
    validateOutcome(value, path);
  }
  const outcomes = outcomeNames.length;
  const outcomeHashes = new Set(outcomeNames.map((name) => name.slice(0, -'.outcome.json'.length)));
  const openIntents = names
    .filter((name) => /^[a-f0-9]{64}\.intent$/.test(name))
    .map((name) => name.slice(0, -'.intent'.length))
    .filter((hash) => !outcomeHashes.has(hash));
  return { journals, settlements: { outcomes, openIntents } };
}
