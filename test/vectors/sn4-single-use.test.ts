import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  verifySN4SingleUse,
  type SN4Input,
} from '../../conformance/security-vectors/sn4-single-use/validate.js';

type CorpusVector = {
  name: string;
  expected: 'accept' | 'reject' | 'indeterminate' | 'error';
  expectedConsumedOnAttempt: boolean;
  input: SN4Input;
};

type Corpus = {
  hash: string;
  count: number;
  vectors: CorpusVector[];
};

const corpusPath = new URL(
  '../../conformance/security-vectors/sn4-single-use/vectors/sn4-single-use-v0.1.json',
  import.meta.url,
);
const corpus = JSON.parse(readFileSync(corpusPath, 'utf8')) as Corpus;

test('SN-4 corpus hash and every declared decision/effect reproduce', () => {
  const hash = createHash('sha256')
    .update(JSON.stringify(corpus.vectors))
    .digest('hex');
  assert.equal(hash, corpus.hash);
  assert.equal(corpus.vectors.length, corpus.count);

  for (const vector of corpus.vectors) {
    const result = verifySN4SingleUse(vector.input);
    assert.equal(result.decision, vector.expected, vector.name);
    assert.equal(
      result.consumedOnAttempt,
      vector.expectedConsumedOnAttempt,
      `${vector.name}: consumption effect`,
    );
  }
});

test('SN-4 failed presentation consumes the issued nonce before retry', () => {
  const input = corpus.vectors.find(
    (vector) => vector.name === 'later-presentation-failure-still-consumes',
  );
  assert.ok(input);

  const failed = verifySN4SingleUse(input.input);
  assert.equal(failed.decision, 'reject');
  assert.equal(failed.consumedOnAttempt, true);
  assert.ok(failed.consumedAfter);

  const retry = verifySN4SingleUse({
    ...input.input,
    presentationOtherwiseValid: true,
    consumedBefore: failed.consumedAfter,
  });
  assert.equal(retry.decision, 'reject');
  assert.equal(retry.consumedOnAttempt, false);
});

test('SN-4 malformed consumed state never becomes a fresh empty ledger', () => {
  const baseline = corpus.vectors.find((vector) => vector.name === 'first-use');
  assert.ok(baseline);

  for (const consumedBefore of [undefined, {}, [['job-only']], [[42, 'nonce']]]) {
    const result = verifySN4SingleUse({ ...baseline.input, consumedBefore });
    assert.equal(result.decision, 'error');
    assert.equal(result.consumedAfter, null);
    assert.equal(result.consumedOnAttempt, false);
  }
});
