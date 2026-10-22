import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, link, unlink, rm } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { claims, input, JOB, NOW } from './fixture.mjs';

export const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT || join(process.env.SNAP_REAL_HOME || userInfo().homedir, 'dacs-sdk'));
const sdk = await import(pathToFileURL(join(SDK_ROOT, 'src/negotiate/durableRfqLifecycle.ts')));
const { createFsDurableRfqLifecycleStore } = await import(pathToFileURL(join(SDK_ROOT, 'src/negotiate/durableRfqLifecycleStoreFs.ts')));
const { deriveRfqAgreement } = await import(pathToFileURL(join(SDK_ROOT, 'src/negotiate/rfqAgreement.ts')));
const { canonicalize, contentHash } = await import(pathToFileURL(join(SDK_ROOT, 'src/canonical/index.ts')));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const roles = ['buyer', 'seller'];

async function privateRead(path, max = 65536, allowLinked = false) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await fd.stat();
    if (!s.isFile() || (!allowLinked && s.nlink !== 1) || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o600 || s.size > max) throw Error('Unsafe private file');
    const b = await fd.readFile();
    if (b.length > max) throw Error('Oversized private file');
    return b;
  } finally { await fd.close(); }
}
async function checkDir(path) {
  const s = await lstat(path);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o700) throw Error('Unsafe private directory');
}
// Sync a temporary inode, then publish without overwrite. A crash before
// link leaves an ignored temporary inode; retry still uses the same bytes.
async function durableOnce(path, bytes, fault) {
  const temp = `${path}.tmp-${randomUUID()}`;
  const fd = await open(temp, 'wx', 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  if (fault === 'crash-before-link') process.exit(87);
  try {
    try { await link(temp, path); if (fault === 'crash-after-link') process.exit(88); }
    catch (e) { if (e.code !== 'EEXIST') throw e; }
  } finally { await unlink(temp); }
  if (!(await privateRead(path, 65536, true)).equals(Buffer.from(bytes))) throw Error('Durable byte conflict');
  const dir = await open(resolve(path, '..'), 'r');
  try { await dir.sync(); } finally { await dir.close(); }
}
export async function withRun(fn) {
  const root = await mkdtemp(join(tmpdir(), 'demosspeed6-'));
  try {
    const pins = {};
    for (const role of roles) {
      const dir = join(root, role); await mkdir(dir, { mode: 0o700 });
      const integrity = randomBytes(32);
      await durableOnce(join(dir, 'integrity.key'), integrity);
      pins[role] = hash(integrity); integrity.fill(0);
      const keys = generateKeyPairSync('ed25519');
      await durableOnce(join(dir, 'signing.pem'), keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
      await durableOnce(join(root, `${role}.public.pem`), keys.publicKey.export({ type: 'spki', format: 'pem' }));
      await mkdir(join(dir, 'mailbox'), { mode: 0o700 });
    }
    assert.notEqual(pins.buyer, pins.seller);
    await durableOnce(join(root, 'integrity-pins.json'), JSON.stringify(pins));
    return await fn(root);
  } finally { await rm(root, { recursive: true, force: true }); }
}
export async function worker(c) {
  if (!roles.includes(c.role)) throw Error('Unknown role');
  const root = resolve(c.root), dir = join(root, c.role);
  await checkDir(root); await checkDir(dir); await checkDir(join(dir, 'mailbox'));
  const pins = JSON.parse(await privateRead(join(root, 'integrity-pins.json')));
  const key = await privateRead(join(dir, 'integrity.key'));
  if (key.length !== 32 || pins.buyer === pins.seller || hash(key) !== pins[c.role]) throw Error('Role integrity key mismatch');
  const store = await createFsDurableRfqLifecycleStore({ dir: join(dir, 'store'), role: c.role, integrityKey: key, lockTimeoutMs: 500, lockStaleMs: 1000, lockPollMs: 5 });
  key.fill(0);
  const privateKey = await privateRead(join(dir, 'signing.pem'));
  const publicKeys = new Map(await Promise.all(roles.map(async r => [claims[r], await privateRead(join(root, `${r}.public.pem`))])));
  const packetPath = packet => {
    if (!/^[0-9a-f]{64}$/.test(packet.packetId)) throw Error('Invalid packet id');
    return join(dir, 'mailbox', `${packet.packetId}.json`);
  };
  const transport = {
    async publish(packet) {
      if (c.fault === 'hang') await new Promise(() => setInterval(() => {}, 1000));
      if (c.fault === 'throw') throw Error('Injected local transport failure');
      try {
        await durableOnce(packetPath(packet), canonicalize(packet), c.fault);
        if (c.fault === 'crash-after-publish') process.exit(86);
        return { disposition: 'acknowledged' };
      } catch { return { disposition: 'indeterminate', reason: 'Local spool write uncertain' }; }
    },
    async reconcile(packet) {
      try {
        const prior = await privateRead(packetPath(packet), 65536, true);
        return prior.toString() === canonicalize(packet) ? { disposition: 'acknowledged' } : { disposition: 'indeterminate', reason: 'Local spool byte conflict' };
      } catch (e) { return e.code === 'ENOENT' ? { disposition: 'absent' } : { disposition: 'indeterminate', reason: 'Local spool unavailable' }; }
    },
  };
  const client = sdk.createDurableRfqLifecycleClient({
    role: c.role, store, transport,
    reserveChannelId: async reservation => {
      try { await durableOnce(join(dir, 'reservation.json'), canonicalize(reservation)); return 'pass'; }
      catch { return 'indeterminate'; }
    },
    // Local Ed25519 over SDK envelopeHash; NOT a Demos signature wire format.
    signChannelMessage: ({ envelopeHash }) => sign(null, Buffer.from(envelopeHash), privateKey).toString('base64url'),
    verifyChannelMessage: ({ message, envelopeHash }) => {
      try { const pub = publicKeys.get(message.sender); return pub && verify(null, Buffer.from(envelopeHash), pub, Buffer.from(message.signature, 'base64url')) ? 'pass' : 'fail'; }
      catch { return 'fail'; }
    },
    agreementSigner: { party: claims[c.role], algorithm: 'ed25519', sign: bytes => sign(null, bytes, privateKey) },
    verifyAgreementContribution: ({ party, signedBytes, value }) => {
      try { const pub = publicKeys.get(party); return pub && verify(null, signedBytes, pub, Buffer.from(value, 'base64url')) ? 'valid' : 'invalid'; }
      catch { return 'invalid'; }
    },
    nowMs: () => NOW + (c.clockOffset || 0),
  });
  let result;
  const proposal = amount => ({ rfqProposalVersion: '1', price: { amount, currency: 'USDC' } });
  switch (c.action) {
    case 'open': result = await client.open(input(contentHash)); break;
    case 'offer': result = await client.sendOffer(JOB, proposal(c.amount || '9')); break;
    case 'counter': result = await client.sendCounter(JOB, proposal(c.amount || '9.5')); break;
    case 'accept': result = await client.sendAccept(JOB); break;
    case 'receive': result = await client.receive(c.packet); break;
    case 'resume': result = await client.resumeOutbox(JOB); break;
    case 'agreement': result = await client.startAgreement(JOB); break;
    case 'status': result = await client.getStatus(JOB); break;
    default: throw Error('Unknown action');
  }
  const loaded = await client.getStatus(JOB);
  const record = loaded.status === 'ok' ? loaded.record : undefined;
  const packets = record?.outbox.map(e => e.packet) || [];
  const draft = record?.session.status === 'accepted' ? deriveRfqAgreement({ ...record.authority, session: record.session, generatedAt: NOW }) : undefined;
  return { pid: process.pid, role: c.role, action: c.action, status: result.status,
    ...(result.reason ? { reason: result.reason } : {}), loadStatus: loaded.status,
    ...(record ? { revision: record.revision, session: record.session, transcript: record.transcript, packets,
      outboxStates: record.outbox.map(e => e.state), draft, agreement: record.agreement?.finalized } : {}) };
}
export function runChild(config, { timeoutMs = 12000, expectedExit = 0 } = {}) {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--worker'], {
      env: { PATH: process.env.PATH, HOME: userInfo().homedir, DACS_SDK_ROOT: SDK_ROOT }, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = []; let size = 0, timedOut = false, oversized = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', b => { size += b.length; if (size > 262144) { oversized = true; child.kill('SIGKILL'); } else chunks.push(b); });
    // Never propagate arbitrary worker stderr (could contain local secrets).
    child.stderr.resume(); child.stdin.on('error', () => {});
    child.once('error', e => { clearTimeout(timer); rej(e); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (oversized) return rej(Error('Worker output bound exceeded'));
      if (timedOut) return rej(Error('Worker hard deadline exceeded'));
      if (code !== expectedExit) return rej(Error(`Worker failed: exit=${code} signal=${signal}`));
      if (expectedExit !== 0) return res({ pid: child.pid, exit: code });
      try { res(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { rej(Error('Invalid worker result')); }
    });
    child.stdin.end(JSON.stringify(config));
  });
}
export async function storyboard(root) {
  const steps = [];
  const call = async (role, action, extra = {}) => { const r = await runChild({ root, role, action, ...extra }); steps.push({ pid: r.pid, role, action, status: r.status }); return r; };
  for (const role of roles) assert.equal((await call(role, 'open')).status, 'ready');
  const crash = await runChild({ root, role: 'buyer', action: 'offer', fault: 'crash-after-publish' }, { expectedExit: 86 });
  steps.push({ pid: crash.pid, role: 'buyer', action: 'offer/crash-after-durable-publish', status: 'exit86' });
  const recovered = await call('buyer', 'resume'); assert.equal(recovered.status, 'ready');
  const offer = recovered.packets[0];
  assert.equal((await call('seller', 'receive', { packet: offer })).status, 'ready');
  const before = await call('seller', 'status');
  const replay = await call('seller', 'receive', { packet: offer });
  assert.equal(replay.status, 'duplicate'); assert.equal(replay.revision, before.revision); assert.equal(replay.transcript.length, 1);
  const counter = await call('seller', 'counter'); assert.equal(counter.status, 'ready');
  assert.equal((await call('buyer', 'receive', { packet: counter.packets.at(-1) })).status, 'ready');
  const accept = await call('buyer', 'accept'); assert.equal(accept.status, 'ready');
  assert.equal((await call('seller', 'receive', { packet: accept.packets.at(-1) })).status, 'ready');
  const plan = await call('buyer', 'agreement'); assert.equal(plan.status, 'ready');
  const contribution = await call('seller', 'receive', { packet: plan.packets.at(-1) }); assert.equal(contribution.status, 'ready');
  assert.equal((await call('buyer', 'receive', { packet: contribution.packets.at(-1) })).status, 'ready');
  const buyer = await call('buyer', 'status'), seller = await call('seller', 'status');
  assert.equal(buyer.session.status, 'accepted'); assert.equal(seller.session.status, 'accepted');
  assert.equal(buyer.transcript.length, 3); assert.deepEqual(buyer.transcript, seller.transcript);
  assert.deepEqual(buyer.agreement, seller.agreement); assert.equal(buyer.agreement.signatures.length, 2);
  const { signatures, ...unsigned } = buyer.agreement;
  assert.deepEqual(unsigned, buyer.draft); assert.deepEqual(buyer.draft, seller.draft);
  assert.deepEqual(buyer.agreement.terms.price, { amount: '9.5', currency: 'USDC' });
  assert.equal(new Set(steps.map(s => s.pid)).size, steps.length);
  return { mode: 'LOCAL TRANSPORT / SYNTHETIC AUTHORITY / NO CHAIN', clock: 'fixed synthetic SDK time',
    steps, transcript: buyer.transcript, acceptedAgreement: buyer.agreement, agreementHash: contentHash(buyer.agreement),
    proof: { turns: 3, independentProcesses: steps.length, replay: 'duplicate; revision unchanged',
      crashRecovery: 'durable publish reconciled; exact original packet reused', roleStores: 'separate directories and distinct integrity keys' } };
}
if (import.meta.main) {
  try {
    const isWorker = process.argv[2] === '--worker';
    if (isWorker) {
      const chunks = []; let n = 0;
      for await (const b of process.stdin) { n += b.length; if (n > 262144) throw Error('Worker input too large'); chunks.push(b); }
      console.log(JSON.stringify(await worker(JSON.parse(Buffer.concat(chunks).toString('utf8')))));
    } else {
      if (process.argv.length !== 2) throw Error('Usage: bun main.mjs');
      console.log(JSON.stringify(await withRun(storyboard), null, 2));
    }
  } catch (e) { console.error(`RFQ storyboard failed (${e.name})`); process.exitCode = 1; }
}
