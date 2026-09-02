import { strict as assert } from 'node:assert';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join, resolve } from 'node:path';
import { test } from 'node:test';
import {
  claimRefFor,
  loadAgentsConfig,
  parseClaim,
  resolveAgent,
  signAsAgent,
  unlockAgent,
  verifyAgentSignature,
  type UnlockedAgent,
} from '../../src/adapters/demos/identity.js';
import type { DemosHandle } from '../../src/demos/connection.js';

const EXAMPLE_CONFIG = resolve('config/dacs-agents.example.json');
const FIXED_ADDRESS = '03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8';

function withConfig(raw: unknown, run: (path: string) => void): void {
  const directory = mkdtempSync(join(tmpdir(), 'dacs-identity-'));
  const path = join(directory, 'agents.json');
  try {
    writeFileSync(path, JSON.stringify(raw));
    run(path);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function minimalConfig(agentOverrides: Record<string, unknown> = {}): unknown {
  return {
    schemaVersion: 1,
    network: 'testnet',
    rpc: 'https://demosnode.discus.sh/',
    agents: {
      'test-buyer': {
        role: 'buyer-reviewer',
        mnemonicEnv: 'DACS_TEST_BUYER_MNEMONIC',
        claimRef: null,
        notes: 'Test configuration.',
        ...agentOverrides,
      },
    },
  };
}

test('example agent config loads and resolves without exposing a credential', () => {
  const config = loadAgentsConfig(EXAMPLE_CONFIG);
  assert.equal(config.schemaVersion, 1);
  assert.equal(config.network, 'testnet');
  assert.equal(config.rpc, 'https://demosnode.discus.sh/');
  assert.deepEqual(Object.keys(config.agents).sort(), ['test-buyer', 'test-seller']);
  assert.deepEqual(resolveAgent(config, 'test-buyer', {}), {
    name: 'test-buyer',
    role: 'buyer-reviewer',
    mnemonicEnv: 'DACS_TEST_BUYER_MNEMONIC',
    hasSecret: false,
  });
});

test('example config contains environment variable names, not secret material', () => {
  const raw = readFileSync(EXAMPLE_CONFIG, 'utf8');
  assert.doesNotMatch(raw, /"(?:mnemonic|seed|privateKey)"\s*:/i);
  assert.doesNotMatch(raw, /"(?:[a-z]+\s+){11,}[a-z]+"/);

  const parsed = JSON.parse(raw) as { agents: Record<string, { mnemonicEnv: string }> };
  for (const agent of Object.values(parsed.agents)) {
    assert.match(agent.mnemonicEnv, /^[A-Z][A-Z0-9_]+$/);
  }
});

test('mainnet config is rejected', () => {
  const raw = minimalConfig() as Record<string, unknown>;
  raw.network = 'mainnet';
  withConfig(raw, (path) => {
    assert.throws(() => loadAgentsConfig(path), /network must be "testnet"/);
  });
});

test('testnet config with an unsanctioned RPC host is rejected', () => {
  const raw = minimalConfig() as Record<string, unknown>;
  raw.rpc = 'https://mainnet.example/';
  withConfig(raw, (path) => {
    assert.throws(() => loadAgentsConfig(path), /sanctioned testnet RPC host/);
  });
});

test('inline seed words are rejected without echoing their value', () => {
  const inlineWords = new Array<string>(12).fill('word').join(' ');
  withConfig(minimalConfig({ mnemonic: inlineWords }), (path) => {
    assert.throws(
      () => loadAgentsConfig(path),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /Agent "test-buyer"/);
        assert.match(error.message, /field "mnemonic"/);
        assert.equal(error.message.includes(inlineWords), false);
        return true;
      },
    );
  });

  const claimWords = [
    'Capitalised', 'Amber', 'Birch', 'Cobalt', 'Dahlia', 'Elm',
    'Flint', 'Garnet', 'Hazel', 'Indigo', 'Juniper', 'Kestrel',
  ];
  const claimPhrase = claimWords.join(' ');
  withConfig(minimalConfig({ claimRef: claimPhrase }), (path) => {
    assert.throws(
      () => loadAgentsConfig(path),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message.includes(claimPhrase), false);
        for (const word of claimWords) {
          assert.equal(error.message.toLowerCase().includes(word.toLowerCase()), false);
        }
        return true;
      },
    );
  });
});

test('root-level inline mnemonic is rejected without echoing its value', () => {
  const inlineWords = 'secret value that must remain absent from every error message shown';
  const raw = minimalConfig() as Record<string, unknown>;
  raw.mnemonic = inlineWords;
  withConfig(raw, (path) => {
    assert.throws(
      () => loadAgentsConfig(path),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /Agent "\(config\)"/);
        assert.match(error.message, /field "mnemonic"/);
        assert.equal(error.message.includes(inlineWords), false);
        return true;
      },
    );
  });
});

test('claim references round-trip with SDK lowercase and 0x normalisation', () => {
  const claim = claimRefFor(FIXED_ADDRESS);
  assert.equal(claim, `demos:0x${FIXED_ADDRESS.toLowerCase()}`);
  assert.deepEqual(parseClaim(claim), {
    scheme: 'demos',
    identifier: `0x${FIXED_ADDRESS.toLowerCase()}`,
  });
});

test('unlockAgent rejects a missing mnemonic environment variable before connecting', async () => {
  const config = loadAgentsConfig(EXAMPLE_CONFIG);
  let connectCalls = 0;

  await assert.rejects(
    unlockAgent(config, 'test-buyer', {}, {
      connect: async () => {
        connectCalls += 1;
        throw new Error('connect must not be called');
      },
    }),
    /Environment variable DACS_TEST_BUYER_MNEMONIC is not set/,
  );
  assert.equal(connectCalls, 0);
});

test('unlockAgent passes the mnemonic and RPC to connect and derives a missing claim', async () => {
  const config = loadAgentsConfig(EXAMPLE_CONFIG);
  const mnemonic = new Array<string>(12).fill('disposable').join(' ');
  let received: { mnemonic: string; rpc: string } | undefined;
  const fakeDemos = { marker: 'fake-demos' } as unknown as DemosHandle['demos'];

  const result = await unlockAgent(config, 'test-seller', {
    DACS_TEST_SELLER_MNEMONIC: mnemonic,
  }, {
    connect: async (connectedMnemonic, rpc): Promise<DemosHandle> => {
      received = { mnemonic: connectedMnemonic, rpc };
      return { demos: fakeDemos, address: FIXED_ADDRESS, rpc };
    },
  });

  assert.deepEqual(received, { mnemonic, rpc: config.rpc });
  assert.equal(result.name, 'test-seller');
  assert.equal(result.role, 'seller');
  assert.equal(result.claim, claimRefFor(FIXED_ADDRESS));
});

test('unlockAgent does not retain the mnemonic in its returned object', async () => {
  const config = loadAgentsConfig(EXAMPLE_CONFIG);
  const mnemonic = 'one two three four five six seven eight nine ten eleven twelve';
  let passedMnemonic: string | undefined;

  const result = await unlockAgent(config, 'test-buyer', {
    DACS_TEST_BUYER_MNEMONIC: mnemonic,
  }, {
    connect: async (value, rpc): Promise<DemosHandle> => {
      passedMnemonic = value;
      return {
        demos: { marker: 'fake-demos' } as unknown as DemosHandle['demos'],
        address: FIXED_ADDRESS,
        rpc,
      };
    },
  });

  assert.equal(passedMnemonic, mnemonic);
  assert.equal(JSON.stringify(result).includes(mnemonic), false);
  assert.equal(Object.values(result).includes(mnemonic), false);
});

test('signAsAgent signs the domain-separated payload through a fake Demos handle', async () => {
  const signature = Uint8Array.of(7, 8, 9);
  let signedPayload: Uint8Array | undefined;
  const fakeDemos = {
    walletConnected: true,
    getEd25519Address: async () => FIXED_ADDRESS,
    crypto: {
      sign: async (algorithm: string, payload: Uint8Array) => {
        assert.equal(algorithm, 'ed25519');
        signedPayload = payload;
        return { signature };
      },
    },
  } as unknown as DemosHandle['demos'];
  const handle: UnlockedAgent = {
    demos: fakeDemos,
    address: FIXED_ADDRESS,
    rpc: 'https://demosnode.discus.sh/',
    name: 'test-buyer',
    role: 'buyer-reviewer',
    mnemonicEnv: 'DACS_TEST_BUYER_MNEMONIC',
    claim: claimRefFor(FIXED_ADDRESS),
  };
  const payload = new TextEncoder().encode('fake signer payload');

  assert.deepEqual(await signAsAgent(handle, payload), signature);
  assert.deepEqual(
    signedPayload,
    new TextEncoder().encode('dacs-x-agent-identity:v1:fake signer payload'),
  );
});

test('pinned Ed25519 vector verifies only for the original payload', () => {
  const claim = claimRefFor(FIXED_ADDRESS);
  const payload = new TextEncoder().encode('identity adapter vector');
  const signature = Uint8Array.from(Buffer.from(
    '0ccfa802b35b1686ac4a5e5814fad8ec10a1c11bb93ae2edef8d5c1f92668017' +
    '43c1c30249bd2c62117845f1d583e0953aa3a4290c6024309a1ea67fc3cd0006',
    'hex',
  ));

  // Derived once with Node's Ed25519 primitive and a disposable deterministic
  // test key by signing UTF-8("dacs-x-agent-identity:v1:" || payload). Only the
  // public key and pinned signature are retained, so verification is hermetic.
  assert.equal(verifyAgentSignature(claim, payload, signature), true);
  assert.equal(
    verifyAgentSignature(claim, new TextEncoder().encode('tampered identity adapter vector'), signature),
    false,
  );
});

test('CCI SDK identity import is confined to the adapter boundary', () => {
  const srcRoot = resolve('src');
  const importingFiles: string[] = [];

  function visit(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if (['.ts', '.mts', '.js', '.mjs'].includes(extname(entry.name))) {
        const sdkIdentityImport = /(?:from|import)\s*['"]@kynesyslabs\/demosdk\/identity(?:\/[^'"]*)?['"]/;
        if (sdkIdentityImport.test(readFileSync(path, 'utf8'))) {
          importingFiles.push(path.slice(srcRoot.length + 1));
        }
      }
    }
  }

  visit(srcRoot);
  assert.deepEqual(importingFiles, ['adapters/demos/identity.ts']);
});
