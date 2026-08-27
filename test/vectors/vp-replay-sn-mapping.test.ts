import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

type Vector = { name: string; sn: string };
type Corpus = {
  hash: string;
  count: number;
  snCoverage: {
    exercised: string[];
    notEnforcedHere: Record<string, string>;
    sn3Scope: string;
    hashDivergence: string;
  };
  vectors: Vector[];
};

const corpusPath = new URL(
  '../../conformance/security-vectors/vp-replay/vectors/vp-replay-v0.1.json',
  import.meta.url,
);
const corpus = JSON.parse(readFileSync(corpusPath, 'utf8')) as Corpus;

test('VP-replay SN mapping hash and count reproduce', () => {
  const hash = createHash('sha256')
    .update(JSON.stringify(corpus.vectors))
    .digest('hex');
  assert.equal(hash, corpus.hash);
  assert.equal(corpus.vectors.length, corpus.count);
});

test('nonce mismatch and omission cases map to SN-3, never SN-4', () => {
  const tags = new Map(corpus.vectors.map((vector) => [vector.name, vector.sn]));
  for (const name of [
    'cross-session-nonce-replay',
    'challenge-omits-session-nonce',
    'empty-challenge-nonce',
  ]) {
    assert.equal(tags.get(name), 'SN-3', name);
  }
  assert.deepEqual(corpus.snCoverage.exercised, ['SN-3']);
  assert.equal(corpus.vectors.some((vector) => vector.sn === 'SN-4'), false);
});

test('coverage records settled SN-1, SN-2, and stateful SN-4 boundaries', () => {
  assert.match(corpus.snCoverage.notEnforcedHere['SN-1'] ?? '', /not exercised/);
  assert.match(corpus.snCoverage.notEnforcedHere['SN-2'] ?? '', /issuer obligations/);
  assert.match(corpus.snCoverage.notEnforcedHere['SN-4'] ?? '', /not exercised/);
  assert.match(corpus.snCoverage.sn3Scope, /assuming.*authenticated current-job issuance state/);
  assert.match(corpus.snCoverage.hashDivergence, /1cebf46c4b1007d29989996eef23b1ac26de534ea052e43727e8e3aa89eb9c74/);
  assert.match(corpus.snCoverage.hashDivergence, /not byte-identical/);
  assert.equal('sn4Scope' in corpus.snCoverage, false);
});
