import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { main } from '../../src/cli/dacs-agents.js';

const EXAMPLE_CONFIG = resolve('config/dacs-agents.example.json');
const FIXED_ADDRESS = '03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8';

function capture(argv: string[]): { code: number; output: string } {
  let output = '';
  const code = main(argv, {}, { write: (chunk) => {
    output += String(chunk);
    return true;
  } });
  return { code, output };
}

test('check prints both example agents and reports absent environment variables', () => {
  const result = capture(['check', '--config', EXAMPLE_CONFIG]);

  assert.equal(result.code, 0);
  assert.match(result.output, /test-buyer buyer-reviewer DACS_TEST_BUYER_MNEMONIC no demos:/);
  assert.match(result.output, /test-seller seller DACS_TEST_SELLER_MNEMONIC no \(derived after first unlock\)/);
});

test('check returns 2 for a rejected config without printing its secret', () => {
  const directory = mkdtempSync(join(tmpdir(), 'dacs-agents-cli-'));
  const path = join(directory, 'rejected.json');
  const secret = 'one two three four five six seven eight nine ten eleven twelve';
  try {
    writeFileSync(path, JSON.stringify({
      schemaVersion: 1,
      network: 'testnet',
      rpc: 'https://demosnode.discus.sh/',
      agents: {
        'test-buyer': {
          role: 'buyer-reviewer',
          mnemonicEnv: 'DACS_TEST_BUYER_MNEMONIC',
          mnemonic: secret,
          claimRef: null,
          notes: 'Rejected test configuration.',
        },
      },
    }));

    const result = capture(['check', '--config', path]);
    assert.equal(result.code, 2);
    assert.match(result.output, /forbidden inline secret field "mnemonic"/);
    assert.equal(result.output.includes(secret), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('claim prints the CCI claim reference for a fixed address', () => {
  const result = capture(['claim', FIXED_ADDRESS]);

  assert.equal(result.code, 0);
  assert.equal(result.output, `demos:0x${FIXED_ADDRESS.toLowerCase()}\n`);
});
