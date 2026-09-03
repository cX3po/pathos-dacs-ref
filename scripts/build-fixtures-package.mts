import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

type Group = 'c1' | 'settlement' | 'htlc';
type Expected = 'pass' | 'fail' | 'indeterminate' | 'error';

type Source = {
  source: string;
  destination: string;
  group: Group;
  repo?: string;
  commit?: string;
  originPath?: string;
};

type IndexFile = {
  path: string;
  sha256: string;
  bytes: number;
  group: Group;
  origin: { repo: string; commit?: string; path: string };
};

type Expectation = {
  path: string;
  vectorName?: string;
  expected: Expected;
  source: string;
};

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), '..');
const defaultOutput = join(repoRoot, 'packages', 'fixtures');
const repository = 'https://github.com/cX3po/pathos-dacs-ref';
const standardRepository = 'https://github.com/DACS-Agent-commerce/DACS-Standard';
const standardCommit = '63793a39';
const compareText = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;

const sources = ([
  { source: 'conformance/implementation-manifests/pathos-dacs-ref.json', destination: 'data/c1/conformance/implementation-manifests/pathos-dacs-ref.json', group: 'c1' },
  { source: 'conformance/partner-kit/MANIFEST.json', destination: 'data/c1/conformance/partner-kit/MANIFEST.json', group: 'c1' },
  { source: 'conformance/partner-kit/vectors.json', destination: 'data/c1/conformance/partner-kit/vectors.json', group: 'c1' },
  { source: 'conformance/partner-kit/README.md', destination: 'data/c1/conformance/partner-kit/README.md', group: 'c1' },
  { source: 'conformance/partner-kit/LICENSE', destination: 'data/c1/conformance/partner-kit/LICENSE', group: 'c1' },
  { source: 'docs/c1-conformance-bridge.md', destination: 'data/c1/docs/c1-conformance-bridge.md', group: 'c1' },
  { source: 'conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json', destination: 'data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json', group: 'settlement' },
  { source: 'conformance/security-vectors/sb2-settlement-uniqueness/vectors/sb2-settlement-uniqueness-v0.1.json', destination: 'data/settlement/conformance/security-vectors/sb2-settlement-uniqueness/vectors/sb2-settlement-uniqueness-v0.1.json', group: 'settlement' },
  { source: 'conformance/security-vectors/convergence-harness/corpus/attestation-bundle-htlc9.json', destination: 'data/htlc/conformance/security-vectors/convergence-harness/corpus/attestation-bundle-htlc9.json', group: 'htlc' },
  { source: 'test/fixtures/dacs-standard-63793a39/fixtures/settlement-evidence-payment-success.json', destination: 'data/settlement/dacs-standard/fixtures/settlement-evidence-payment-success.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'fixtures/settlement-evidence-payment-success.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/fixtures/settlement-evidence-delivery-success.json', destination: 'data/settlement/dacs-standard/fixtures/settlement-evidence-delivery-success.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'fixtures/settlement-evidence-delivery-success.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/vectors/security/bundle-settlement-evidence-bijection-v0.4.json', destination: 'data/settlement/dacs-standard/vectors/security/bundle-settlement-evidence-bijection-v0.4.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'vectors/security/bundle-settlement-evidence-bijection-v0.4.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/README.md', destination: 'data/settlement/dacs-standard/README.md', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'README.md' },
] satisfies Source[]).sort((a, b) => compareText(a.destination, b.destination));

function gitHead(): string {
  const result = spawnSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error('Could not determine git HEAD');
  return result.stdout.trim();
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

// The index contains only JSON-compatible values. Sorting member names recursively and
// emitting JSON without whitespace produces its RFC 8785/JCS representation.
function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error('Index contains a non-JSON value');
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${jcs(record[key])}`).join(',')}}`;
}

function extractExpectations(bytes: Buffer, path: string): Expectation[] {
  if (!path.endsWith('.json')) return [];
  const document = JSON.parse(bytes.toString('utf8')) as { vectors?: unknown };
  if (!Array.isArray(document.vectors)) return [];
  const allowed = new Set<Expected>(['pass', 'fail', 'indeterminate', 'error']);
  const result: Expectation[] = [];
  for (const item of document.vectors) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) continue;
    const vector = item as Record<string, unknown>;
    for (const field of ['expected', 'verdict', 'decision'] as const) {
      const value = vector[field];
      if (typeof value !== 'string' || !allowed.has(value as Expected)) continue;
      const expectation: Expectation = {
        path,
        expected: value as Expected,
        source: `field ${field} in file`,
      };
      const name = typeof vector.name === 'string' ? vector.name : typeof vector.id === 'string' ? vector.id : undefined;
      if (name !== undefined) expectation.vectorName = name;
      result.push(expectation);
      break;
    }
  }
  return result;
}

function packageJson(): string {
  return `${JSON.stringify({
    name: '@pathos-labs/dacs-fixtures',
    version: '0.1.0',
    description: 'Deterministic data-only C1, settlement, and HTLC fixtures for DACS interoperability',
    license: 'MIT',
    private: false,
    files: ['data', 'index.json', 'README.md', 'LICENSE'],
  }, null, 2)}\n`;
}

function packageReadme(head: string): string {
  const rows = sources.map((source) => {
    const repo = source.repo ?? repository;
    const commit = source.commit ?? head;
    const originPath = source.originPath ?? source.source;
    return `| \`${source.destination}\` | ${source.group} | \`${originPath}\` | [${repo}](${repo}) @ \`${commit}\` |`;
  }).join('\n');
  return `# @pathos-labs/dacs-fixtures

A deterministic, data-only package of PATH-OS C1 materials and settlement/HTLC fixtures for implementations that do not clone this repository.

This package is **not a DACS-Standard publication**. It includes non-normative PATH-OS material and byte-for-byte copies of the pinned inputs identified below.

## Contents and origins

| Packaged file | Group | Upstream path | Repository and pin |
| --- | --- | --- | --- |
${rows}

The two settlement-named security-vector sets included from \`conformance/security-vectors\` are \`settlement-v1\` and \`sb2-settlement-uniqueness\`; no other directory name there contains \`settlement\` or \`htlc\`. The HTLC convergence corpus file is included separately because it is an explicitly selected fixture.

The copied DACS-Standard README records the source fixture hashes and the short commit pin \`63793a39\`. The C1 implementation manifest and partner-kit manifest also retain their own embedded provenance pins.

## Index

\`index.json\` is JCS-canonical JSON with version \`pathos-dacs-fixtures-index:0.1\`. \`generatedFrom\` is the PATH-OS git commit used to build the package. Each \`files\` entry gives a package-relative path, SHA-256, byte count, group, and origin. Each \`expectations\` entry is copied only from a vector's own case-level \`expected\`, \`verdict\`, or \`decision\` field; \`vectorName\` is the case's \`name\` or \`id\` when present. Files without such a field have no expectation entry.

To verify the bytes, hash a data file directly and compare both values with its index entry, for example:

\`sha256sum data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json\`

\`wc -c data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json\`

From a checkout of the source repository, rebuild or check the complete package with:

\`node --import tsx scripts/build-fixtures-package.mts\`

\`node --import tsx scripts/build-fixtures-package.mts --check\`
`;
}

async function listFiles(root: string, current = root): Promise<string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(root, path));
    else if (entry.isFile()) files.push(relative(root, path).split(sep).join('/'));
  }
  return files;
}

async function build(output: string): Promise<void> {
  const resolvedOutput = resolve(output);
  if (resolvedOutput === repoRoot || !dirname(resolvedOutput)) throw new Error(`Refusing unsafe output path: ${resolvedOutput}`);
  await rm(resolvedOutput, { recursive: true, force: true });
  await mkdir(resolvedOutput, { recursive: true });
  const head = gitHead();
  const files: IndexFile[] = [];
  const expectations: Expectation[] = [];
  for (const source of sources) {
    const bytes = await readFile(join(repoRoot, source.source));
    const destination = join(resolvedOutput, source.destination);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, bytes);
    const origin: IndexFile['origin'] = {
      repo: source.repo ?? repository,
      commit: source.commit ?? head,
      path: source.originPath ?? source.source,
    };
    files.push({ path: source.destination, sha256: sha256(bytes), bytes: bytes.length, group: source.group, origin });
    expectations.push(...extractExpectations(bytes, source.destination));
  }
  expectations.sort((a, b) => compareText(a.path, b.path) || compareText(a.vectorName ?? '', b.vectorName ?? ''));
  await writeFile(join(resolvedOutput, 'index.json'), jcs({ v: 'pathos-dacs-fixtures-index:0.1', generatedFrom: head, files, expectations }));
  await writeFile(join(resolvedOutput, 'package.json'), packageJson());
  await writeFile(join(resolvedOutput, 'README.md'), packageReadme(head));
  await writeFile(join(resolvedOutput, 'LICENSE'), await readFile(join(repoRoot, 'conformance/partner-kit/LICENSE')));
}

async function compareDirectories(expected: string, actual: string): Promise<string[]> {
  const [expectedFiles, actualFiles] = await Promise.all([listFiles(expected), listFiles(actual)]);
  const differences: string[] = [];
  const all = [...new Set([...expectedFiles, ...actualFiles])].sort();
  for (const path of all) {
    if (!expectedFiles.includes(path)) differences.push(`unexpected ${path}`);
    else if (!actualFiles.includes(path)) differences.push(`missing ${path}`);
    else {
      const [a, b] = await Promise.all([readFile(join(expected, path)), readFile(join(actual, path))]);
      if (!a.equals(b)) differences.push(`different ${path}`);
    }
  }
  return differences;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const outputAt = args.indexOf('--output');
  if (args.some((arg, index) => arg !== '--check' && arg !== '--output' && index !== outputAt + 1)) {
    throw new Error('Usage: build-fixtures-package.mts [--check] [--output DIRECTORY]');
  }
  const output = outputAt >= 0 ? args[outputAt + 1] : defaultOutput;
  if (output === undefined) throw new Error('--output requires a directory');
  if (!check) {
    await build(output);
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), 'pathos-fixtures-check-'));
  try {
    const rebuilt = join(temporary, 'fixtures');
    await build(rebuilt);
    const differences = await compareDirectories(resolve(output), rebuilt);
    if (differences.length > 0) throw new Error(`Fixture package is stale:\n${differences.join('\n')}`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

await main();
