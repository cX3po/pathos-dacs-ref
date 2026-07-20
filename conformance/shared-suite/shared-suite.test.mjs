import assert from 'node:assert/strict';
import * as path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { crossRun } from './adapter-contract.mjs';
import { startAdapterProcess } from './adapter-process-client.mjs';
import { referenceAdapter } from './reference-adapter.mjs';
import { loadSeedCorpus } from './seed-corpus.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STANDARD_BASE64 = 'ha0tTYYAS97QPS+r5mNV1/7t6Q4jyMiFITnPnm7dpquQZVCh55ic8B3d4vQ341L0/Hhy+qyMuqLaqyrru7m3Ag==';
const BASE64URL = 'ha0tTYYAS97QPS-r5mNV1_7t6Q4jyMiFITnPnm7dpquQZVCh55ic8B3d4vQ341L0_Hhy-qyMuqLaqyrru7m3Ag';

test('F3 conforming path accepts canonical unpadded Base64URL and rejects standard Base64', () => {
  const adapter = referenceAdapter();
  assert.equal(adapter.signatureValueVerdict(BASE64URL), 'ACCEPT');
  assert.equal(adapter.signatureValueVerdict(STANDARD_BASE64), 'REJECT');
});

test('standard Base64 migration is a separate operation with out-of-band source encoding', () => {
  const adapter = referenceAdapter();
  assert.deepEqual(adapter.legacySignatureValueImport(STANDARD_BASE64, 'base64'), {
    verdict: 'ACCEPT', canonicalValue: BASE64URL,
  });
  assert.deepEqual(adapter.legacySignatureValueImport(STANDARD_BASE64, 'base64url'), { verdict: 'REJECT' });
});

test('reference adapter works through metadata handshake and subprocess execute requests', async () => {
  const adapter = await startAdapterProcess(
    process.execPath,
    [path.join(HERE, 'reference-adapter-process.mjs')],
    { cwd: HERE },
  );
  assert.equal(adapter.metadata.name, 'pathos-dacs-ref');
  assert.match(adapter.metadata.revision, /^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/);
  assert.equal(await adapter.signatureValueVerdict(BASE64URL), 'ACCEPT');
  assert.equal(await adapter.signatureValueVerdict(STANDARD_BASE64), 'REJECT');
  await adapter.close();
});

const vector = {
  id: 'status-vector', family: 'test', fnName: 'op', description: 'status test', expected: 'YES',
  invoke: (adapter) => adapter.op(),
};
const adapter = (name, repository, outcome = 'YES') => ({
  name,
  metadata: {
    name, version: '1', repository, revision: 'a'.repeat(40),
    supportedFamilies: ['test'], operations: ['op'],
  },
  op: () => outcome,
});

test('one adapter is SELF-CHECK; two independent agreeing adapters are INTEROP-AGREE', async () => {
  const one = await crossRun([adapter('one', 'https://example.test/one')], [vector]);
  assert.equal(one.matrix[0].status, 'SELF-CHECK');
  const sameImplementation = await crossRun([
    adapter('one-a', 'https://example.test/one'), adapter('one-b', 'https://example.test/one'),
  ], [vector]);
  assert.equal(sameImplementation.matrix[0].status, 'SELF-CHECK');
  const two = await crossRun([
    adapter('one', 'https://example.test/one'), adapter('two', 'https://example.test/two'),
  ], [vector]);
  assert.equal(two.matrix[0].status, 'INTEROP-AGREE');
});

test('mismatch and divergence remain separate and SPEC-QUESTION requires triage', async () => {
  const mismatch = await crossRun([adapter('one', 'https://example.test/one', 'NO')], [vector]);
  assert.equal(mismatch.matrix[0].status, 'VECTOR-MISMATCH');
  assert.deepEqual(mismatch.matrix[0].resultCategories, ['vector-mismatch']);
  assert.equal(mismatch.specQuestions.length, 0);

  const divergence = await crossRun([
    adapter('one', 'https://example.test/one'), adapter('two', 'https://example.test/two', 'NO'),
  ], [vector]);
  assert.equal(divergence.matrix[0].status, 'IMPLEMENTATION-DIVERGENCE');
  assert.deepEqual(divergence.matrix[0].resultCategories, ['vector-mismatch', 'implementation-divergence']);
  assert.equal(divergence.specQuestions.length, 0);

  const triaged = await crossRun(
    [adapter('one', 'https://example.test/one', 'NO')],
    [vector],
    { triagedSpecQuestions: new Set([vector.id]) },
  );
  assert.deepEqual(triaged.matrix[0].resultCategories, ['vector-mismatch', 'spec-question']);
  assert.equal(triaged.specQuestions.length, 1);
});

test('coverage accounting is exact and F4 is not shipped', () => {
  const corpus = loadSeedCorpus();
  assert.equal(corpus.sourceCounts.partnerKitDeclared, 49);
  assert.equal(corpus.sourceCounts.sig6DeclaredCases, 3);
  assert.equal(corpus.sourceCounts.executedAssertions, 43);
  assert.equal(corpus.sourceCounts.partnerKitNotExecuted, 9);
  assert.equal(corpus.sourceCounts.f4Declared, 0);
  assert.equal(corpus.sourceCounts.f4Executed, 0);
  assert.equal(corpus.vectors.filter((item) => item.fnName === 'verifyBundle').length, 0);
});
