/** Regression for the stale source lock left after the upstream member-name repair. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
function probe(source: string): any {
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: root, encoding: 'utf8', timeout: 30_000,
  }));
}

test('shared seed pins the published upstream kit and executes every mapped assertion', () => {
  const result = probe(`
    import { loadSeedCorpus } from './conformance/shared-suite/seed-corpus.mjs';
    import { referenceAdapter } from './conformance/shared-suite/reference-adapter.mjs';
    const corpus = loadSeedCorpus(), adapter = referenceAdapter();
    const failures = [];
    for (const v of corpus.vectors) {
      const actual = await v.invoke(adapter);
      if (actual !== v.expected) failures.push({ id: v.id, actual, expected: v.expected });
    }
    console.log(JSON.stringify({ failures, counts: corpus.sourceCounts, ids: corpus.vectors.map(v => v.id) }));
  `);
  assert.deepEqual(result.failures, []);
  assert.equal(result.counts.partnerKitDeclared, 49);
  assert.ok(result.counts.executedAssertions > 0);
  assert.ok(result.ids.includes('ca-unicode-key-nfd'));
  assert.ok(result.ids.includes('ca-nfc-nfd-key-pair-distinct'));
  assert.ok(!result.ids.includes('cr-nfc-key-collision'));
});

test('both upstream canonicalizers preserve member names and NFC normalize values', () => {
  const result = probe(`
    import { jcsCanonical } from './conformance/partner-kit/jcs.mjs';
    import { referenceAdapter } from './conformance/shared-suite/reference-adapter.mjs';
    const input = {'caf\\u00e9':1,'cafe\\u0301':2, value:'e\\u0301'};
    console.log(JSON.stringify({ kit: Buffer.from(jcsCanonical(input)).toString('utf8'),
      adapter: Buffer.from(referenceAdapter().canonicalize(input).hex, 'hex').toString('utf8') }));
  `);
  assert.equal(result.kit, '{"cafe\u0301":2,"caf\u00e9":1,"value":"\u00e9"}');
  assert.equal(result.adapter, result.kit);
});

for (const target of ['source', 'lock'] as const) {
test(`${target} tampering still refuses without changing this checkout`, () => {
  const result = probe(`
    import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
    import { tmpdir } from 'node:os';
    import { join } from 'node:path';
    const temp = mkdtempSync(join(tmpdir(), 's245-seed-'));
    try {
      cpSync('conformance/shared-suite', join(temp, 'shared-suite'), { recursive:true });
      cpSync('conformance/partner-kit', join(temp, 'partner-kit'), { recursive:true });
      cpSync('conformance/vectors', join(temp, 'vectors'), { recursive:true });
      const target = '${target}';
      if (target === 'source') {
        const path = join(temp, 'partner-kit/vectors.json');
        writeFileSync(path, readFileSync(path, 'utf8')+' ');
      } else {
        const path = join(temp, 'shared-suite/PINNED-SOURCES.json');
        const lock = JSON.parse(readFileSync(path, 'utf8'));
        lock.sources.partnerKit.sha256 = '0'.repeat(64);
        writeFileSync(path, JSON.stringify(lock));
      }
      let refused=false;
      try { const { loadSeedCorpus } = await import('file://'+join(temp,'shared-suite/seed-corpus.mjs')); loadSeedCorpus(); }
      catch (e) { refused = String(e).includes('pinned source hash mismatch'); }
      console.log(JSON.stringify({refused}));
    } finally { rmSync(temp, {recursive:true, force:true}); }
  `);
  assert.equal(result.refused, true);
});

}
