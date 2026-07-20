import assert from 'node:assert/strict';
import * as path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalizeRepository, codebaseIdentity, crossRun } from './adapter-contract.mjs';
import {
  AdapterOutputLimitError,
  AdapterTimeoutError,
  startAdapterProcess,
} from './adapter-process-client.mjs';
import {
  launchAdapters,
  normalizeAdapterSpec,
  parseAdapterArgs,
  tokenizeCommand,
} from './adapter-registry.mjs';
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

// ---------------------------------------------------------------------------------------------
// DACS-Standard#270 steward Blocker 1 — duplicate adapter identity must NOT produce a false
// INTEROP-AGREE. Two adapters that self-report the SAME name must be tracked by distinct
// runner-side identities and can never clobber one another, regardless of registration order.
// ---------------------------------------------------------------------------------------------

test('Blocker 1: two same-name adapters never collide in the results map (per-adapter keyed by runId)', async () => {
  const twoSameName = await crossRun([
    adapter('collide', 'https://example.test/a'),
    adapter('collide', 'https://example.test/b'),
  ], [vector]);
  // Both runs are retained under distinct runIds — no clobber.
  const entries = Object.values(twoSameName.matrix[0].perAdapter);
  assert.equal(entries.length, 2, 'both same-name runs must be present');
  assert.deepEqual([...new Set(entries.map((e) => e.runId))].sort(), ['run-0', 'run-1']);
  assert.deepEqual(twoSameName.matrix[0].duplicateReportedNames, ['collide']);
});

test('Blocker 1: same-name adapters with a WRONG result cannot fake INTEROP-AGREE (order-independent)', async () => {
  // The steward\'s reproduction: a second same-name adapter overwrote a different (wrong) result,
  // yielding a false INTEROP-AGREE from what was really one adapter clobbering another. With
  // runId keying, the wrong result survives and the row is a DIVERGENCE, never INTEROP-AGREE.
  const forward = await crossRun([
    adapter('dup', 'https://example.test/a', 'YES'),
    adapter('dup', 'https://example.test/b', 'NO'),
  ], [vector]);
  const reverse = await crossRun([
    adapter('dup', 'https://example.test/b', 'NO'),
    adapter('dup', 'https://example.test/a', 'YES'),
  ], [vector]);
  for (const run of [forward, reverse]) {
    assert.equal(run.matrix[0].status, 'IMPLEMENTATION-DIVERGENCE');
    assert.notEqual(run.matrix[0].status, 'INTEROP-AGREE');
    assert.equal(Object.values(run.matrix[0].perAdapter).length, 2);
  }
});

test('Blocker 1: same-name AGREEING adapters over the SAME codebase stay SELF-CHECK (not INTEROP)', async () => {
  // Distinct runIds but one canonical codebase → still a self-check, both orders.
  for (const order of [['x', 'y'], ['y', 'x']]) {
    const run = await crossRun([
      adapter('same', 'https://example.test/one', 'YES'),
      adapter('same', 'https://example.test/one', 'YES'),
    ], [vector]);
    void order;
    assert.equal(run.matrix[0].status, 'SELF-CHECK');
    assert.equal(run.matrix[0].independentImplementations, 1);
  }
});

// ---------------------------------------------------------------------------------------------
// DACS-Standard#270 steward Blocker 2 — independence must come from a CANONICALIZED codebase
// identity, not raw self-reported repository strings.
// ---------------------------------------------------------------------------------------------

test('Blocker 2: canonicalizeRepository folds .git / trailing slash / scheme-case / git+ / scp form', () => {
  const base = 'github.com/cx3po/impl';
  assert.equal(canonicalizeRepository('https://github.com/cx3po/impl'), base);
  assert.equal(canonicalizeRepository('https://github.com/cx3po/impl.git'), base);
  assert.equal(canonicalizeRepository('https://github.com/cx3po/impl/'), base);
  assert.equal(canonicalizeRepository('HTTPS://GitHub.com/cx3po/impl'), base);
  assert.equal(canonicalizeRepository('git+https://github.com/cx3po/impl.git'), base);
  assert.equal(canonicalizeRepository('git@github.com:cx3po/impl.git'), base);
  assert.equal(canonicalizeRepository('ssh://git@github.com:22/cx3po/impl'), base);
  assert.equal(canonicalizeRepository(''), null);
  assert.equal(canonicalizeRepository(undefined), null);
});

test('Blocker 2: /impl vs /impl.git are the SAME codebase → self-check, not interop', async () => {
  const run = await crossRun([
    adapter('a', 'https://example.test/impl'),
    adapter('b', 'https://example.test/impl.git'),
  ], [vector]);
  assert.equal(run.matrix[0].independentImplementations, 1);
  assert.equal(run.matrix[0].status, 'SELF-CHECK');
});

test('Blocker 2: two wrappers over ONE impl (same repo) are NOT independent', () => {
  const a = { metadata: { name: 'wrapper-a', repository: 'https://x/impl', revision: 'a'.repeat(40) } };
  const b = { metadata: { name: 'wrapper-b', repository: 'https://x/impl.git', revision: 'c'.repeat(40) } };
  assert.equal(codebaseIdentity(a), codebaseIdentity(b));
});

test('Blocker 2: genuinely distinct canonical repos ARE independent → INTEROP-AGREE', async () => {
  const run = await crossRun([
    adapter('a', 'https://example.test/impl-one'),
    adapter('b', 'https://example.test/impl-two'),
  ], [vector]);
  assert.equal(run.matrix[0].independentImplementations, 2);
  assert.equal(run.matrix[0].status, 'INTEROP-AGREE');
});

test('Blocker 2: explicit provenanceCodebase assertion is honored and overrides URL inference', () => {
  const a = { metadata: { name: 'a', repository: 'https://x/impl', revision: 'a'.repeat(40), provenanceCodebase: 'shared-core' } };
  const b = { metadata: { name: 'b', repository: 'https://y/other', revision: 'c'.repeat(40), provenanceCodebase: 'shared-core' } };
  // Same asserted codebase → same identity even though the URLs differ.
  assert.equal(codebaseIdentity(a), codebaseIdentity(b));
  assert.match(codebaseIdentity(a), /^asserted:/);
});

test('Blocker 2: demo adapters and revision-less adapters contribute no independent codebase', () => {
  assert.equal(codebaseIdentity({ metadata: { name: 'd', repository: 'https://x/i', revision: 'a'.repeat(40), kind: 'demo' } }), null);
  assert.equal(codebaseIdentity({ metadata: { name: 'r', repository: 'https://x/i' } }), null); // no revision
});

// ---------------------------------------------------------------------------------------------
// DACS-Standard#270 steward Blocker 3 — real multi-adapter invocation path + subprocess safety.
// ---------------------------------------------------------------------------------------------

const FIXTURES = path.join(HERE, 'test-fixtures');
const NODE = process.execPath;

test('Blocker 3: tokenizeCommand + spec normalization + arg parsing', () => {
  assert.deepEqual(tokenizeCommand('node adapter.mjs --flag'), ['node', 'adapter.mjs', '--flag']);
  assert.deepEqual(tokenizeCommand('node "a b.mjs" \'c d\''), ['node', 'a b.mjs', 'c d']);
  assert.deepEqual(tokenizeCommand(['node', 'a.mjs']), ['node', 'a.mjs']);
  assert.throws(() => tokenizeCommand('node "unbalanced'), /unbalanced/);

  const spec = normalizeAdapterSpec({ command: 'node a.mjs', provenanceCodebase: 'core', timeoutMs: 500 });
  assert.deepEqual(spec.command, ['node', 'a.mjs']);
  assert.equal(spec.provenanceCodebase, 'core');
  assert.equal(spec.timeoutMs, 500);

  const { specs, rest } = parseAdapterArgs(
    ['--adapter', 'node a.mjs', '--adapter-provenance', 'core-x', '--adapter', 'node b.mjs', '--json'],
  );
  assert.equal(specs.length, 2);
  assert.equal(specs[0].provenanceCodebase, 'core-x');
  assert.deepEqual(rest, ['--json']);
  assert.throws(() => parseAdapterArgs(['--adapter-provenance', 'x']), /must follow an --adapter/);
});

test('Blocker 3: registering 2 real adapters runs both over the subprocess protocol', async () => {
  const { adapters, unavailable } = await launchAdapters([
    { command: [NODE, path.join(HERE, 'reference-adapter-process.mjs')] },
    { command: [NODE, path.join(FIXTURES, 'second-impl-adapter.mjs')] },
  ], { defaultCwd: HERE });
  try {
    assert.equal(unavailable.length, 0);
    assert.equal(adapters.length, 2);
    assert.equal(adapters[0].metadata.name, 'pathos-dacs-ref');
    assert.equal(adapters[1].metadata.name, 'second-impl-fixture');
    // Two genuinely distinct codebases agreeing on F3 → INTEROP-AGREE (fixture-level proof only;
    // Blocker 4\'s second GENUINE impl + manifest pin remains out of scope).
    const BASE64URL = 'ha0tTYYAS97QPS-r5mNV1_7t6Q4jyMiFITnPnm7dpquQZVCh55ic8B3d4vQ341L0_Hhy-qyMuqLaqyrru7m3Ag';
    const f3vector = {
      id: 'f3-accept', family: 'sig-value-encoding', fnName: 'signatureValueVerdict',
      description: 'canonical base64url accepts', expected: 'ACCEPT',
      invoke: (a) => a.signatureValueVerdict(BASE64URL),
    };
    const run = await crossRun(adapters, [f3vector]);
    assert.equal(run.matrix[0].status, 'INTEROP-AGREE');
    assert.equal(run.matrix[0].independentImplementations, 2);
  } finally {
    await Promise.all(adapters.map((a) => a.close?.()));
  }
});

test('Blocker 3: a timing-out adapter is recorded as UNAVAILABLE, never hangs the run', async () => {
  const { adapters, unavailable } = await launchAdapters([
    { command: [NODE, path.join(FIXTURES, 'hanging-adapter.mjs')], timeoutMs: 400 },
  ], { defaultCwd: HERE });
  try {
    assert.equal(adapters.length, 1);
    assert.equal(unavailable.length, 1, 'the hung adapter must be recorded unavailable');
    assert.match(unavailable[0].reason, /AdapterTimeoutError/);
    // It exposes no operations → abstains on every vector (fail-closed, never a silent pass).
    const run = await crossRun(adapters, [vector]);
    assert.equal(run.matrix[0].status, 'ABSTAIN');
    assert.equal(run.matrix[0].independentImplementations, 0);
  } finally {
    await Promise.all(adapters.map((a) => a.close?.()));
  }
});

test('Blocker 3: startAdapterProcess throws AdapterTimeoutError directly on a hung adapter', async () => {
  await assert.rejects(
    () => startAdapterProcess(NODE, [path.join(FIXTURES, 'hanging-adapter.mjs')], { cwd: HERE, timeoutMs: 300 }),
    (error) => error instanceof AdapterTimeoutError,
  );
});

test('Blocker 3: bounded output is enforced — a flooding adapter is killed, not OOM/hang', async () => {
  await assert.rejects(
    () => startAdapterProcess(NODE, [path.join(FIXTURES, 'flooding-adapter.mjs')], {
      cwd: HERE, timeoutMs: 5000, maxOutputBytes: 256 * 1024,
    }),
    (error) => error instanceof AdapterOutputLimitError || error instanceof AdapterTimeoutError,
  );
});

test('Blocker 3: a flooding adapter registered via launchAdapters becomes UNAVAILABLE (fail-closed)', async () => {
  const { adapters, unavailable } = await launchAdapters([
    { command: [NODE, path.join(FIXTURES, 'flooding-adapter.mjs')], maxOutputBytes: 256 * 1024, timeoutMs: 5000 },
  ], { defaultCwd: HERE });
  try {
    assert.equal(unavailable.length, 1);
    assert.match(unavailable[0].reason, /AdapterOutputLimitError|AdapterTimeoutError/);
    const run = await crossRun(adapters, [vector]);
    assert.equal(run.matrix[0].status, 'ABSTAIN'); // no silent pass
  } finally {
    await Promise.all(adapters.map((a) => a.close?.()));
  }
});

test('Blocker 3: two reference adapters (same codebase) still SELF-CHECK — no false interop via multi-adapter path', async () => {
  const { adapters } = await launchAdapters([
    { command: [NODE, path.join(HERE, 'reference-adapter-process.mjs')] },
    { command: [NODE, path.join(HERE, 'reference-adapter-process.mjs')] },
  ], { defaultCwd: HERE });
  try {
    const corpus = loadSeedCorpus();
    const run = await crossRun(adapters, corpus.vectors);
    const interop = run.matrix.filter((r) => r.status === 'INTEROP-AGREE').length;
    const selfCheck = run.matrix.filter((r) => r.status === 'SELF-CHECK').length;
    assert.equal(interop, 0, 'same-codebase duplicates must never be INTEROP-AGREE');
    assert.equal(selfCheck, 43);
    assert.deepEqual(run.duplicateReportedNames, ['pathos-dacs-ref']);
  } finally {
    await Promise.all(adapters.map((a) => a.close?.()));
  }
});
