import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer, get } from 'node:http';
import test from 'node:test';
import {
  createD402Service,
  amountToOs,
  type D402PaymentRequirement,
  type D402VerificationResult,
  type D402Verifier,
} from '../../src/adapters/demos/d402-service.js';
import {
  createD402OrganHandler,
  createD402ProofStore,
  resourceFor,
} from '../../src/live/d402-organ.mjs';

const HASH = `0x${'ab'.repeat(32)}`;
const RECIPIENT = 'merchant-address';
const RESOURCE = { resourceId: 'organ:nws_alerts:query', amount: 1, description: 'answer' };

class FakeVerifier implements D402Verifier {
  calls = 0;
  lastHash?: string;
  result: D402VerificationResult = {
    valid: true,
    verified_from: 'buyer-address',
    verified_to: RECIPIENT,
    verified_amount: '1000000000',
    verified_memo: `resourceId:${RESOURCE.resourceId} - answer`,
    timestamp: 1,
  };
  error?: Error;

  async verify(txHash: string): Promise<D402VerificationResult> {
    this.calls += 1;
    this.lastHash = txHash;
    if (this.error) throw this.error;
    return this.result;
  }

  validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean {
    if (!v.valid || v.verified_to !== r.recipient || v.verified_amount === undefined) return false;
    try {
      if (amountToOs(v.verified_amount) < amountToOs(r.amount)) return false;
    } catch {
      return false;
    }
    return (v.verified_memo ?? '').startsWith(`resourceId:${r.resourceId}`);
  }
}

function setup(fake = new FakeVerifier()) {
  return {
    fake,
    service: createD402Service({ recipient: RECIPIENT, rpcUrl: 'https://unused.invalid', verifier: fake }),
  };
}

test('missing proof returns 402 and the payment requirement', async () => {
  const { service } = setup();
  const result = await service.gate({ headers: {}, resource: RESOURCE });
  assert.deepEqual(result, {
    status: 402,
    reason: 'missing-proof',
    body: { amount: 1, recipient: RECIPIENT, resourceId: RESOURCE.resourceId, description: 'answer' },
  });
});

test('malformed proof fails before verifier RPC', async () => {
  const { service, fake } = setup();
  const result = await service.gate({ headers: { 'X-Payment-Proof': 'not-a-hash' }, resource: RESOURCE });
  assert.equal(result.status, 402);
  if (result.status === 402) assert.equal(result.reason, 'malformed-proof');
  assert.equal(fake.calls, 0);
});

test('verifier throw fails closed as unverifiable', async () => {
  const fake = new FakeVerifier();
  fake.error = new Error('RPC unavailable');
  const { service } = setup(fake);
  const result = await service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
  assert.equal(result.status, 402);
  if (result.status === 402) assert.equal(result.reason, 'unverifiable');
});

test('valid false fails closed as unverifiable after one verifier call', async () => {
  const fake = new FakeVerifier();
  fake.result = { ...fake.result, valid: false };
  const result = await setup(fake).service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
  assert.equal(result.status, 402);
  if (result.status === 402) assert.equal(result.reason, 'unverifiable');
  assert.equal(fake.calls, 1);
});

test('wrong recipient, amount, or resource id is a mismatch', async (t) => {
  const cases: Array<[string, Partial<D402VerificationResult>]> = [
    ['recipient', { verified_to: 'someone-else' }],
    ['amount', { verified_amount: '999999999' }],
    ['resourceId', { verified_memo: 'resourceId:another-resource' }],
  ];
  for (const [name, change] of cases) {
    await t.test(name, async () => {
      const fake = new FakeVerifier();
      fake.result = { ...fake.result, ...change };
      const result = await setup(fake).service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
      assert.equal(result.status, 402);
      if (result.status === 402) assert.equal(result.reason, 'mismatch');
    });
  }
});

test('valid proof returns normalized OS payment', async () => {
  const { service, fake } = setup();
  const result = await service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
  assert.deepEqual(result, {
    status: 200,
    payment: {
      from: 'buyer-address',
      to: RECIPIENT,
      amount: '1000000000',
      txHash: HASH.slice(2),
    },
  });
  assert.equal(fake.lastHash, HASH);
});

test('case and 0x aliases of a used proof are rejected as replayed', async () => {
  const { service, fake } = setup();
  assert.equal((await service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE })).status, 200);
  const caseAlias = await service.gate({
    headers: { 'x-payment-proof': `0x${HASH.slice(2).toUpperCase()}` },
    resource: RESOURCE,
  });
  assert.equal(caseAlias.status, 402);
  if (caseAlias.status === 402) assert.equal(caseAlias.reason, 'replayed');
  const strippedAlias = await service.gate({
    headers: { 'x-payment-proof': HASH.slice(2) },
    resource: RESOURCE,
  });
  assert.equal(strippedAlias.status, 402);
  if (strippedAlias.status === 402) assert.equal(strippedAlias.reason, 'replayed');
  assert.equal(fake.calls, 1);
});

test('adapter amount normalization equates number DEM and decimal-string OS', () => {
  assert.equal(amountToOs(1), amountToOs('1000000000'));
  assert.equal(amountToOs(1), 1_000_000_000n);
});

test('adapter rejects non-string verified_from even when validatePayment returns true', async () => {
  const fake = new FakeVerifier();
  fake.result = { ...fake.result, verified_from: 123 as unknown as string };
  fake.validatePayment = () => true;
  const result = await setup(fake).service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
  assert.equal(result.status, 402);
  if (result.status === 402) assert.equal(result.reason, 'mismatch');
});

test('overlapping verification reserves the proof and rejects the second request', async () => {
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  const fake = new FakeVerifier();
  fake.verify = async (txHash: string) => {
    fake.calls += 1;
    fake.lastHash = txHash;
    await waiting;
    return fake.result;
  };
  const { service } = setup(fake);
  const first = service.gate({ headers: { 'x-payment-proof': HASH }, resource: RESOURCE });
  await Promise.resolve();
  const second = await service.gate({ headers: { 'x-payment-proof': HASH.slice(2) }, resource: RESOURCE });
  assert.equal(second.status, 402);
  if (second.status === 402) assert.equal(second.reason, 'replayed');
  assert.equal(fake.calls, 1);
  release();
  assert.equal((await first).status, 200);
});

test('payment proof header name is case-insensitive', async () => {
  const result = await setup().service.gate({ headers: { 'X-PaYmEnT-PrOoF': HASH }, resource: RESOURCE });
  assert.equal(result.status, 200);
});

test('organ seller keeps a proof committed when the client aborts after writeHead(200)', async (t) => {
  const committed = new Set<string>();
  const reserved = new Set<string>();
  const fake = new FakeVerifier();
  // The handler derives resourceId from the organ and the query hash; the fake proof must bind that id.
  const abortResource = resourceFor('nws_alerts', 'abort-test', '1000000000');
  fake.result = { ...fake.result, verified_memo: `resourceId:${abortResource.resourceId} - answer` };
  const service = createD402Service({
    recipient: RECIPIENT,
    rpcUrl: 'https://unused.invalid',
    verifier: fake,
    usedProofs: createD402ProofStore(committed, reserved),
  });
  const handler = createD402OrganHandler({
    service,
    allowedOrgans: new Set(['nws_alerts']),
    amountOs: '1000000000',
    committed,
    reserved,
    async runOrgan() { return JSON.stringify({ organ: 'nws_alerts', answer: { alert: true } }); },
  });

  let abortAfterWriteHead = true;
  const server = createServer((request, response) => {
    if (abortAfterWriteHead) {
      abortAfterWriteHead = false;
      const writeHead = response.writeHead;
      response.writeHead = function (...args: any[]) {
        const result = writeHead.apply(this, args as any);
        request.socket.destroy();
        return result;
      };
    }
    void handler(request, response);
  });
  const listening = await new Promise<boolean>((resolve, reject) => {
    server.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EPERM') resolve(false);
      else reject(error);
    });
    server.listen(0, '127.0.0.1', () => resolve(true));
  });
  if (!listening) {
    t.skip('HTTP listening is blocked by this sandbox');
    return;
  }
  t.after(() => server.close());
  const address = server.address();
  assert(address && typeof address === 'object');

  let firstStatus: number | undefined;
  await new Promise<void>((resolve) => {
    const request = get({
      host: '127.0.0.1',
      port: address.port,
      path: '/engines/organ/nws_alerts?q=abort-test',
      headers: { 'x-payment-proof': HASH },
    }, (response) => {
      firstStatus = response.statusCode;
      response.resume();
      response.once('close', resolve);
      response.once('end', resolve);
    });
    request.once('error', resolve);
  });

  // The socket is destroyed inside writeHead, so the client cannot observe the 200; the
  // handler-side commit is the property under test.
  assert.equal(firstStatus, undefined);
  assert.equal(committed.size, 1);
  assert.equal(reserved.size, 0);
  const replayStatus = await new Promise<number | undefined>((resolve, reject) => {
    const request = get({
      host: '127.0.0.1',
      port: address.port,
      path: '/engines/organ/nws_alerts?q=abort-test',
      headers: { 'x-payment-proof': HASH.slice(2) },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
  });
  assert.equal(replayStatus, 402);
  assert.equal(fake.calls, 1);
});

test('organ seller dry-run prints a requirement without making an RPC call', (t) => {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    D402_RECIPIENT: RECIPIENT,
    D402_RPC: 'http://127.0.0.1:1',
  };
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/d402-organ.mts', '--dry-run'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env,
  });
  if ((run.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('process spawning is blocked by this sandbox');
    return;
  }
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), {
    amount: '1000000000',
    recipient: RECIPIENT,
    resourceId: `organ:nws_alerts:${createQueryHash('0,0')}`,
    description: 'Organ answer: nws_alerts',
  });
});

test('organ seller exits 2 when D402_RECIPIENT is absent', (t) => {
  const env = { ...process.env };
  delete env.D402_RECIPIENT;
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/d402-organ.mts', '--dry-run'], {
    cwd: process.cwd(), encoding: 'utf8', env,
  });
  if ((run.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('process spawning is blocked by this sandbox');
    return;
  }
  assert.equal(run.status, 2);
});

function createQueryHash(query: string): string {
  // Kept local so the spawn assertion checks the public resource-id contract.
  return createHash('sha256').update(query).digest('hex').slice(0, 16);
}
