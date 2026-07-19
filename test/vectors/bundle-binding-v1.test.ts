import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolveBundleBinding } from '../../src/lib/bundle-binding-v1.js';

const corpus = JSON.parse(readFileSync(
  new URL('../../conformance/cross-run-corpus/dacs248/bundle-binding-v0.1.json', import.meta.url),
  'utf8',
));

function run(name: string) {
  const vector = corpus.vectors.find((candidate: { name: string }) => candidate.name === name);
  assert.ok(vector, `missing corpus vector ${name}`);
  return resolveBundleBinding(
    { ...vector.request, publicKeys: corpus.publicKeys, partyMap: vector.partyMap },
    vector.bindings,
    (nativeAddress) => vector.anchored[nativeAddress],
  );
}

test('BB-5 resolves the representative valid binding to a present copy', () => {
  const result = run('bb-valid-resolution');
  assert.equal(result.disposition, 'present');
  assert.equal(result.resolvedRole, 'seller');
  assert.equal(result.resolvedNativeAddress, 'stor-1fc0e2d23470eed53e0c361208786794dd7cef8e');
});

test('BB-6 equal-standing authorized divergence is indeterminate', () => {
  const result = run('bb-equal-standing-divergence');
  assert.equal(result.disposition, 'indeterminate');
  assert.match(result.detail, /equal-standing/);
});
