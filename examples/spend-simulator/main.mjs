import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm, lstat } from 'node:fs/promises';
import { tmpdir, homedir, userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

export const CAIRN_DID = 'did:demos:agent:6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2';
export const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT || join(process.env.SNAP_REAL_HOME || userInfo().homedir, 'dacs-sdk'));
const authorityModule = await import(pathToFileURL(join(SDK_ROOT, 'src/rails/walletSpendAuthority.ts')));
const fsModule = await import(pathToFileURL(join(SDK_ROOT, 'src/rails/walletSpendAuthorityFs.ts')));
export function validateRpc(input) {
  if (!['https://node2.demos.sh', 'https://demosnode.discus.sh'].includes(input)) throw Error('RPC must be an exact allowlisted testnet endpoint');
  return input;
}
export function validateDid(input) {
  if (typeof input !== 'string' || !/^did:demos:agent:[0-9a-f]{64}$/.test(input)) throw Error('Subject must be a canonical Demos agent DID');
  return input;
}
export async function liveContext(rpc, did) {
  validateRpc(rpc); validateDid(did);
  const { createAgent } = await import(pathToFileURL(join(SDK_ROOT, 'src/index.ts')));
  const agent = await createAgent({ demosRpc: rpc });
  const record = await agent.resolveIdentity(did);
  if (!record || record.primaryClaim !== did || !Array.isArray(record.claims) || record.claims.length > 256) throw Error('Identity subject mismatch or unbounded claims');
  return { rpc, requestedSubject: did, primaryClaim: record.primaryClaim, claimCount: record.claims.length, observedAt: new Date().toISOString(), trust: 'RPC contextual read only; does not authenticate balance, chain binding, or spend authority' };
}
function policy() {
  return { policyVersion: '1', policyId: 'demosspeed-simulation-v1', wallet: 'synthetic-wallet', chainId: 'synthetic:demos-testnet-simulation', maximumConcurrentEffects: 8, maximumRetainedReservations: 16,
    assets: [{ asset: 'SIM-DEM', maximumPerOrderDebit: '100', maximumNetworkFeeDebit: '0', minimumReserve: '100', rollingWindowMs: 86400000, maximumRollingEffects: 8, maximumRollingDebit: '1000', maximumCumulativeDebit: '100', maximumCounterpartyDebit: '1000' }] };
}
function reservation(id, amount) {
  return { reservationVersion: '1', reservationId: id, jobId: `job-${id}`, phaseIndex: 0, phase: 'simulation-only', agreementHash: 'a'.repeat(64), settlementBindingHash: 'b'.repeat(64), railId: 'synthetic-no-rail', railDefinitionHash: 'c'.repeat(64), wallet: 'synthetic-wallet', chainId: 'synthetic:demos-testnet-simulation', payee: 'synthetic-counterparty', finality: { model: 'simulation-no-chain-finality' }, debits: [{ asset: 'SIM-DEM', purpose: 'service', expectedAmount: amount, maximumAmount: amount }] };
}
async function worker(config) {
  if (!['first', 'restart', 'floor'].includes(config.phase)) throw Error('Unknown worker phase');
  const keyPath = join(config.root, 'integrity.key');
  const metadata = await lstat(keyPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600 || metadata.uid !== process.getuid()) throw Error('Integrity key must be a private owned file');
  const key = await readFile(keyPath);
  if (key.length !== 32) throw Error('Invalid integrity key length');
  const store = await fsModule.createFsWalletSpendStateStoreV1({ dir: join(config.root, 'state'), integrityKey: key });
  key.fill(0);
  const authority = authorityModule.createWalletSpendAuthorityV1(policy(), { store,
    readBalance: async ({ wallet, chainId, asset }) => {
      assert.equal(wallet, 'synthetic-wallet'); assert.equal(chainId, 'synthetic:demos-testnet-simulation'); assert.equal(asset, 'SIM-DEM');
      return config.phase === 'floor' ? '150' : '1000';
    },
    // No chain verifier or payment rail is installed. Recovery is always refused.
    authenticateRecovery: async () => false,
    owner: `simulation-process-${process.pid}`,
  });
  const claim = await authority.reserve(reservation(config.phase === 'restart' ? 'second' : 'first', config.phase === 'restart' ? '50' : '60'));
  return { pid: process.pid, status: claim.status, ...(claim.status === 'denied' ? { reason: claim.reason } : {}), inspection: await authority.inspect() };
}
export function runChild(config) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--worker'], { env: { PATH: process.env.PATH, HOME: homedir(), DACS_SDK_ROOT: SDK_ROOT }, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '', errors = '', oversized = false;
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(Error('Worker hard deadline exceeded')); }, 12000);
    child.stdout.on('data', chunk => { output += chunk; if (output.length > 65536) { oversized = true; child.kill('SIGKILL'); } });
    child.stderr.on('data', chunk => { errors = (errors + chunk).slice(0, 4096); });
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('close', code => { clearTimeout(timeout); if (code !== 0 || oversized) reject(Error(`Worker failed (${code}): ${errors}`)); else { try { resolveResult(JSON.parse(output)); } catch { reject(Error('Invalid worker result')); } } });
    child.stdin.end(JSON.stringify(config));
  });
}
export async function withPrivateRun(operation) {
  const root = await mkdtemp(join(tmpdir(), 'demosspeed-spend-'));
  try { await writeFile(join(root, 'integrity.key'), randomBytes(32), { mode: 0o600, flag: 'wx' }); return await operation(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
export async function simulation() {
  return withPrivateRun(async root => {
    const first = await runChild({ root, phase: 'first' });
    assert.equal(first.status, 'reserved');
    const restarted = await runChild({ root, phase: 'restart' });
    assert.notEqual(first.pid, restarted.pid); assert.equal(restarted.status, 'denied'); assert.equal(restarted.reason, 'cumulative-limit');
    return { mode: 'simulation-only', amounts: 'synthetic integer base units', balances: 'synthetic 1000', cumulativeCap: '100', minimumReserve: '100', first, restarted };
  });
}
async function main() {
  if (process.argv[2] === '--worker') {
    let input = ''; for await (const chunk of process.stdin) { input += chunk; if (input.length > 4096) throw Error('Worker input too large'); }
    console.log(JSON.stringify(await worker(JSON.parse(input)))); return;
  }
  if (process.argv.length > 3 || !['--live', '--offline', undefined].includes(process.argv[2])) throw Error('Usage: bun main.mjs [--live|--offline]');
  const context = process.argv[2] === '--live' ? await liveContext(validateRpc(process.env.DEMOS_RPC || 'https://node2.demos.sh'), CAIRN_DID) : null;
  console.log(JSON.stringify({ context, simulation: await simulation() }, null, 2));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const deadline = setTimeout(() => { console.error('Hard deadline exceeded'); process.exit(1); }, 25000);
  main().then(() => { clearTimeout(deadline); process.exit(0); }, error => { clearTimeout(deadline); console.error(error.message); process.exit(1); });
}
