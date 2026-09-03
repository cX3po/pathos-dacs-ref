import { strict as assert } from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { test } from 'node:test';
import * as ed25519 from '@noble/ed25519';
import {
  createPrivateChannel,
  membershipBindingBytes,
  verifyChannelTranscript,
  type ChannelMember,
  type ChannelTranscript,
  type MembershipManifest,
  type PrivateChannelEnvelope,
} from '../../src/adapters/demos/private-channel.js';
import {
  InProcessPrivateChannelTransport,
  L2psPrivateChannelTransport,
} from '../../src/adapters/demos/private-channel-transport.js';
import {
  claimRefFor,
  signDomainHashAsAgent,
  type UnlockedAgent,
} from '../../src/adapters/demos/identity.js';
import {
  DACS_X_EXTENSION_SEPARATORS,
  REVIEWED_DACS_X_EXTENSION_SEPARATORS,
  assertKnownSeparator,
} from '../../src/domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import { generateKeypair, sign } from '../../src/lib/sign.js';

interface TestAgent {
  handle: UnlockedAgent;
  privateKey: Uint8Array;
  member: ChannelMember;
}

function makeAgent(seatId: string): TestAgent {
  const keys = generateKeypair();
  const address = Buffer.from(keys.pubKey).toString('hex');
  const claim = claimRefFor(address);
  const demos = {
    walletConnected: true,
    getEd25519Address: async () => address,
    crypto: {
      sign: async (_algorithm: string, payload: Uint8Array) => ({
        signature: ed25519.sign(payload, keys.privKey),
      }),
    },
  } as unknown as UnlockedAgent['demos'];
  return {
    privateKey: keys.privKey,
    member: { seatId, claim },
    handle: {
      demos,
      address,
      rpc: 'offline:test',
      name: seatId,
      role: seatId === 'buyer' ? 'buyer-reviewer' : 'seller',
      mnemonicEnv: 'NOT_READ_IN_TESTS',
      claim,
    },
  };
}

function makeManifest(agents: readonly TestAgent[]): MembershipManifest {
  const unsigned = {
    v: 'pathos-private-channel-membership:1' as const,
    coordinatorClaim: agents[0]!.member.claim,
    members: agents.map((agent) => ({ ...agent.member, signature: '' })),
  };
  const members = agents.map((agent) => {
    const signature = sign(
      DACS_X_EXTENSION_SEPARATORS.AGENT_IDENTITY,
      membershipBindingBytes(unsigned, agent.member),
      agent.privateKey,
    );
    return Object.freeze({ ...agent.member, signature: Buffer.from(signature).toString('base64') });
  });
  return Object.freeze({
    v: unsigned.v,
    coordinatorClaim: unsigned.coordinatorClaim,
    members: Object.freeze(members),
  });
}

async function openPair() {
  const alice = makeAgent('buyer');
  const bob = makeAgent('seller');
  const manifest = makeManifest([alice, bob]);
  const [aliceTransport, bobTransport] = InProcessPrivateChannelTransport.pair();
  const aliceChannel = createPrivateChannel({ identity: alice.handle, membership: manifest, transport: aliceTransport, mode: 'local' });
  const bobChannel = createPrivateChannel({ identity: bob.handle, membership: manifest, transport: bobTransport, mode: 'local' });
  await Promise.all([aliceChannel.open([alice.member, bob.member]), bobChannel.open([bob.member, alice.member])]);
  return { alice, bob, manifest, aliceTransport, bobTransport, aliceChannel, bobChannel };
}

async function completedTranscript(): Promise<ChannelTranscript> {
  const pair = await openPair();
  await pair.aliceChannel.send(new TextEncoder().encode('private hello'));
  assert.equal(new TextDecoder().decode((await pair.bobChannel.receive()).bytes), 'private hello');
  await pair.bobChannel.send(Uint8Array.of(0, 1, 2, 255));
  assert.deepEqual((await pair.aliceChannel.receive()).bytes, Uint8Array.of(0, 1, 2, 255));
  await Promise.all([pair.aliceChannel.close(), pair.bobChannel.close()]);
  assert.deepEqual(pair.aliceChannel.transcript(), pair.bobChannel.transcript());
  return pair.aliceChannel.transcript();
}

test('two-party local open/send/receive/close and cold transcript verification', async () => {
  const transcript = await completedTranscript();
  assert.equal(transcript.mode, 'local');
  assert.equal(await verifyChannelTranscript(structuredClone(transcript)), true);
});

async function signedFrame(
  agent: TestAgent,
  channelId: string,
  sender: ChannelMember,
  sequence: number,
  payload = Uint8Array.of(9),
): Promise<Uint8Array> {
  const unsigned = {
    v: 'pathos-private-channel-envelope:1' as const,
    channelId,
    kind: 'agent-message' as const,
    sender,
    sequence,
    payloadBase64: Buffer.from(payload).toString('base64'),
    sentAt: new Date().toISOString(),
  };
  const signature = await signDomainHashAsAgent(
    agent.handle,
    REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
    jcsHashHex(unsigned),
  );
  return jcsCanonical({ ...unsigned, signature: Buffer.from(signature).toString('base64') });
}

test('unlisted sender and seat/claim mismatch are refused', async (t) => {
  await t.test('unlisted sender', async () => {
    const pair = await openPair();
    const outsider = makeAgent('outsider');
    pair.bobTransport.injectFrame(await signedFrame(outsider, pair.aliceChannel.transcript().channelId, outsider.member, 1));
    await assert.rejects(pair.bobChannel.receive(), /not a listed seat and claim/);
  });
  await t.test('listed claim in the wrong seat', async () => {
    const pair = await openPair();
    const mismatched = { seatId: pair.bob.member.seatId, claim: pair.alice.member.claim };
    pair.bobTransport.injectFrame(await signedFrame(pair.alice, pair.aliceChannel.transcript().channelId, mismatched, 1));
    await assert.rejects(pair.bobChannel.receive(), /not a listed seat and claim/);
  });
});

test('duplicate sequence and sequence gap are fatal and not buffered', async (t) => {
  await t.test('duplicate', async () => {
    const pair = await openPair();
    await pair.aliceChannel.send(Uint8Array.of(1));
    await pair.bobChannel.receive();
    const envelope = pair.aliceChannel.transcript().envelopes[0]!;
    pair.bobTransport.injectFrame(jcsCanonical(envelope));
    await assert.rejects(pair.bobChannel.receive(), /Duplicate/);
    await assert.rejects(pair.bobChannel.receive(), /not open/);
  });
  await t.test('gap', async () => {
    const pair = await openPair();
    pair.bobTransport.injectFrame(await signedFrame(pair.alice, pair.aliceChannel.transcript().channelId, pair.alice.member, 2));
    await assert.rejects(pair.bobChannel.receive(), /sequence gap/);
    await assert.rejects(pair.bobChannel.receive(), /not open/);
  });
});

test('transcript verification rejects every edited field class and structural edit', async (t) => {
  const original = await completedTranscript();
  const cases: Array<[string, (copy: ChannelTranscript) => void]> = [
    ['top-level binding', (x) => { x.channelId = `${x.channelId.slice(0, -1)}0`; }],
    ['mode', (x) => { x.mode = 'l2ps-live'; }],
    ['membership', (x) => { x.membership = { ...x.membership, coordinatorClaim: x.membership.members[1]!.claim }; }],
    ['envelope version/header', (x) => { (x.envelopes[0] as { v: string }).v = 'changed'; }],
    ['content kind', (x) => { x.envelopes[0]!.kind = 'channel-close'; }],
    ['sender', (x) => { x.envelopes[0]!.sender.seatId = 'changed'; }],
    ['sequence', (x) => { x.envelopes[0]!.sequence += 1; }],
    ['payload', (x) => { x.envelopes[0]!.payloadBase64 = 'AA=='; }],
    ['timestamp', (x) => { x.envelopes[0]!.sentAt = '2020-01-01T00:00:00.000Z'; }],
    ['envelope signature', (x) => { x.envelopes[0]!.signature = Buffer.alloc(64).toString('base64'); }],
    ['counter', (x) => { x.finalCounters[0]!.sequence += 1; }],
    ['closing signature', (x) => { x.closingSignatures[0]!.signature = Buffer.alloc(64).toString('base64'); }],
    ['reordering', (x) => { x.envelopes.reverse(); }],
    ['insertion', (x) => { x.envelopes.push(structuredClone(x.envelopes[0]!)); }],
    ['truncation', (x) => { x.envelopes.pop(); }],
  ];
  for (const [name, edit] of cases) {
    await t.test(name, async () => {
      const copy = structuredClone(original);
      edit(copy);
      assert.equal(await verifyChannelTranscript(copy), false);
    });
  }
});

test('live mode is exact-flag gated and still refuses a missing injected peer', async () => {
  const prior = process.env.PATHOS_L2PS_LIVE;
  const agent = makeAgent('buyer');
  const other = makeAgent('seller');
  const membership = makeManifest([agent, other]);
  const encryptor = Object.freeze({
    encryptBytes: async (bytes: Uint8Array) => bytes.slice(),
    decryptBytes: async (bytes: unknown) => (bytes as Uint8Array).slice(),
  });
  try {
    for (const flag of [undefined, '', '0', 'true', '01']) {
      if (flag === undefined) delete process.env.PATHOS_L2PS_LIVE;
      else process.env.PATHOS_L2PS_LIVE = flag;
      const transport = new L2psPrivateChannelTransport({ encryptor, recipient: other.member.claim });
      const channel = createPrivateChannel({ identity: agent.handle, membership, transport, mode: 'l2ps-live' });
      await assert.rejects(channel.open([agent.member, other.member]), /PATHOS_L2PS_LIVE=1/);
    }
    process.env.PATHOS_L2PS_LIVE = '1';
    const transport = new L2psPrivateChannelTransport({ encryptor, recipient: other.member.claim });
    const channel = createPrivateChannel({ identity: agent.handle, membership, transport, mode: 'l2ps-live' });
    await assert.rejects(channel.open([agent.member, other.member]), /injected messaging peer/);
  } finally {
    if (prior === undefined) delete process.env.PATHOS_L2PS_LIVE;
    else process.env.PATHOS_L2PS_LIVE = prior;
  }
});

test('private-channel local import graph stays inside the non-value boundary', () => {
  const roots = [
    resolve('src/adapters/demos/private-channel.ts'),
    resolve('src/adapters/demos/private-channel-transport.ts'),
  ];
  const visited = new Set<string>();
  const localImport = /(?:from\s+|import\()\s*['"](\.{1,2}\/[^'"]+)['"]/g;
  function visit(file: string): void {
    if (visited.has(file)) return;
    visited.add(file);
    const source = readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /(?:from\s+|import\()\s*['"]@kynesyslabs\/demosdk['"]/);
    assert.doesNotMatch(source, /(?:from\s+|import\()\s*['"][^'"]*(?:pay-dem|escrow|storage(?:\/|\.)anchor|settlement|transaction)[^'"]*['"]/i);
    assert.doesNotMatch(source, /\.(?:anchor|sendTransaction|submitTransaction|createTransaction)\s*\(/i);
    for (const match of source.matchAll(localImport)) {
      const base = resolve(dirname(file), match[1]!);
      const resolved = ['.ts', '.mts', '.js'].map((suffix) => base.replace(/\.js$/, suffix)).find((candidate) => {
        try { return readFileSync(candidate).length >= 0; } catch { return false; }
      });
      if (resolved) visit(resolved);
    }
  }
  roots.forEach(visit);
  assert.ok(visited.size >= 4);
});

test('channel-envelope separator is registered and never appears literally in the adapter', () => {
  assert.doesNotThrow(() => assertKnownSeparator(REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE));
  const adapter = readFileSync(resolve('src/adapters/demos/private-channel.ts'), 'utf8');
  assert.equal(adapter.includes(REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE), false);
  assert.equal(readdirSync(resolve('src/adapters/demos')).filter((name) => extname(name) === '.ts').length > 0, true);
});
