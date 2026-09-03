import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

type Expected = 'pass' | 'fail' | 'indeterminate' | 'error';
type Entry = { path: string; sha256: string; bytes: number; origin: { repo: string; commit?: string; path: string } };
type Expectation = { path: string; vectorName?: string; expected: Expected; source: string };
type Index = { files: Entry[]; expectations: Expectation[] };

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const packageRoot = join(root, 'packages', 'fixtures');
const index = JSON.parse(readFileSync(join(packageRoot, 'index.json'), 'utf8')) as Index;

function filesBelow(directory: string, current = directory): string[] {
  return readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const path = join(current, entry.name);
    return entry.isDirectory() ? filesBelow(directory, path) : [relative(directory, path).split(sep).join('/')];
  }).sort();
}

test('index hashes and byte counts match every packaged data file', () => {
  const dataFiles = filesBelow(join(packageRoot, 'data')).map((path) => `data/${path}`);
  assert.deepEqual(index.files.map((entry) => entry.path), dataFiles);
  for (const entry of index.files) {
    const bytes = readFileSync(join(packageRoot, entry.path));
    assert.equal(bytes.length, entry.bytes, entry.path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256, entry.path);
  }
});

test('two post-commit rebuilds and the committed package are byte-identical', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'fixtures-rebuild-test-'));
  try {
    const first = join(temporary, 'first');
    const second = join(temporary, 'second');
    for (const output of [first, second]) {
      const run = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/build-fixtures-package.mts', '--output', output], { cwd: root, encoding: 'utf8' });
      assert.equal(run.status, 0, run.stderr);
    }
    assert.deepEqual(filesBelow(first), filesBelow(second));
    assert.deepEqual(filesBelow(first), filesBelow(packageRoot));
    for (const path of filesBelow(first)) {
      assert.deepEqual(readFileSync(join(first, path)), readFileSync(join(second, path)), `rebuild: ${path}`);
      assert.deepEqual(readFileSync(join(first, path)), readFileSync(join(packageRoot, path)), `committed: ${path}`);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('DACS-Standard origins use real pinned upstream paths', () => {
  const pinReadme = readFileSync(join(root, 'test/fixtures/dacs-standard-63793a39/README.md'), 'utf8');
  const recordedPaths = new Set([...pinReadme.matchAll(/\| `([^`]+)` \|/g)].map((match) => `conformance/${match[1]}`));
  const standardEntries = index.files.filter((entry) => entry.origin.repo === 'https://github.com/DACS-Agent-commerce/DACS-Standard');
  assert.ok(standardEntries.length > 0);
  for (const entry of standardEntries) {
    assert.ok(entry.origin.path.startsWith('conformance/'), entry.origin.path);
    assert.ok(recordedPaths.has(entry.origin.path), entry.origin.path);
  }
});

test('--check accepts the committed package', () => {
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/build-fixtures-package.mts', '--check'], { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
});

test('expectations reproduce their named source fields', () => {
  for (const expectation of index.expectations) {
    const document = JSON.parse(readFileSync(join(packageRoot, expectation.path), 'utf8')) as { vectors?: Array<Record<string, unknown>> };
    assert.ok(Array.isArray(document.vectors), expectation.path);
    const vector = document.vectors.find((candidate) => candidate.name === expectation.vectorName || candidate.id === expectation.vectorName);
    assert.ok(vector, `${expectation.path}: ${expectation.vectorName ?? '<unnamed>'}`);
    const match = /^field (expected|verdict|decision) in file$/.exec(expectation.source);
    assert.ok(match, expectation.source);
    assert.equal(vector[match[1]!], expectation.expected, expectation.vectorName);
  }
});

test('npm package is data-only and contains exactly the declared payload', (t) => {
  const temporary = mkdtempSync(join(tmpdir(), 'fixtures-npm-pack-test-'));
  try {
    const run = spawnSync('npm', ['pack', '--cache', join(temporary, 'cache'), '--dry-run', '--json', packageRoot], { cwd: root, encoding: 'utf8' });
    if (run.status !== 0 || run.stdout.trim() === '') {
      t.skip(`npm pack is unavailable in this sandbox: ${run.error?.message ?? `exit ${run.status ?? 'unknown'}`}`);
      return;
    }
    const report = JSON.parse(run.stdout) as Array<{ files: Array<{ path: string }> }>;
    const packed = report[0]?.files.map((file) => file.path).sort();
    const expected = [...index.files.map((entry) => entry.path), 'index.json', 'package.json', 'README.md', 'LICENSE', 'NOTICE'].sort();
    assert.deepEqual(packed, expected);
    assert.equal(packed?.some((path) => /\.(?:ts|js|mjs)$/.test(path)), false);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('package contains no TypeScript or JavaScript files', () => {
  assert.equal(filesBelow(packageRoot).some((path) => /\.(?:ts|js|mjs)$/.test(path)), false);
  assert.equal(statSync(join(packageRoot, 'index.json')).isFile(), true);
});
