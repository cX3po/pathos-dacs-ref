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

type SourceManifestEntry = { sourcePath: string; sha256: string };

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
const repository = 'cX3po/pathos-dacs-ref';
const standardRepository = 'https://github.com/DACS-Agent-commerce/DACS-Standard';
const standardCommit = '63793a39';
const dacsSdkCommit = '12c5ad358800b4ddc6e732405366035b6a2ac955';
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
  { source: 'test/fixtures/dacs-standard-63793a39/fixtures/settlement-evidence-payment-success.json', destination: 'data/settlement/dacs-standard/fixtures/settlement-evidence-payment-success.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'conformance/fixtures/settlement-evidence-payment-success.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/fixtures/settlement-evidence-delivery-success.json', destination: 'data/settlement/dacs-standard/fixtures/settlement-evidence-delivery-success.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'conformance/fixtures/settlement-evidence-delivery-success.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/vectors/security/bundle-settlement-evidence-bijection-v0.4.json', destination: 'data/settlement/dacs-standard/vectors/security/bundle-settlement-evidence-bijection-v0.4.json', group: 'settlement', repo: standardRepository, commit: standardCommit, originPath: 'conformance/vectors/security/bundle-settlement-evidence-bijection-v0.4.json' },
  { source: 'test/fixtures/dacs-standard-63793a39/README.md', destination: 'data/settlement/dacs-standard/README.md', group: 'settlement' },
] satisfies Source[]).sort((a, b) => compareText(a.destination, b.destination));

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
    files: ['data', 'index.json', 'README.md', 'LICENSE', 'NOTICE'],
  }, null, 2)}\n`;
}

function packageReadme(): string {
  const rows = sources.map((source) => {
    const repo = source.repo ?? repository;
    const originPath = source.originPath ?? source.source;
    const repositoryAndPin = source.commit === undefined
      ? `\`${repo}\``
      : `[${repo}](${repo}) @ \`${source.commit}\``;
    return `| \`${source.destination}\` | ${source.group} | \`${originPath}\` | ${repositoryAndPin} |`;
  }).join('\n');
  return `# @pathos-labs/dacs-fixtures

A deterministic, data-only package of PATH-OS C1 materials and settlement/HTLC fixtures for implementations that do not clone this repository.

This package is **not a DACS-Standard publication**. It includes non-normative PATH-OS material and byte-for-byte copies of the pinned inputs identified below.

## Contents and origins

| Packaged file | Group | Upstream path | Repository and pin |
| --- | --- | --- | --- |
${rows}

The two settlement-named security-vector sets included from \`conformance/security-vectors\` are \`settlement-v1\` and \`sb2-settlement-uniqueness\`; no other directory name there contains \`settlement\` or \`htlc\`. The HTLC convergence corpus file is included separately because it is an explicitly selected fixture.

The packaged \`data/settlement/dacs-standard/README.md\` is the PATH-OS pin record for the copied DACS-Standard files. It records source fixture hashes and the short commit pin \`63793a39\`; it is not the upstream DACS-Standard README. The C1 implementation manifest and partner-kit manifest also retain their own embedded provenance pins.

The top-level \`LICENSE\` reproduces the PATH-OS MIT notice and the DACS-Standard MIT notice from DACS-Standard commit \`63793a39\`. \`NOTICE\` maps packaged files to the applicable notice.

## Index

\`index.json\` is JCS-canonical JSON with version \`pathos-dacs-fixtures-index:0.1\`. \`generatedFrom.sourceManifestSha256\` hashes the JCS list of source paths and content hashes, so it is independent of the checkout's current commit. Top-level \`pins\` names only the upstream DACS-Standard and dacs-sdk commits already recorded by the copied sources. Each \`files\` entry gives a package-relative path, SHA-256, byte count, group, and origin. Each \`expectations\` entry is copied only from a vector's own case-level \`expected\`, \`verdict\`, or \`decision\` field; \`vectorName\` is the case's \`name\` or \`id\` when present. Files without such a field have no expectation entry.

To verify the bytes, hash a data file directly and compare both values with its index entry, for example:

\`sha256sum data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json\`

\`wc -c data/settlement/conformance/security-vectors/settlement-v1/vectors/settlement-v1-v0.1.json\`

From a checkout of the source repository, rebuild or check the complete package with:

\`node --import tsx scripts/build-fixtures-package.mts\`

\`node --import tsx scripts/build-fixtures-package.mts --check\`
`;
}

function packageLicense(pathosLicense: string): string {
  const standardLicense = `MIT License

Copyright (c) 2026 KyneSys Labs and the DACS authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;
  return `PATH-OS MATERIAL
================

${pathosLicense.trimEnd()}

DACS-STANDARD MATERIAL (commit ${standardCommit})
===============================================

${standardLicense}`;
}

function packageNotice(): string {
  const standardFiles = sources.filter((source) => source.repo === standardRepository).map((source) => `- ${source.destination}`).join('\n');
  const pathosFiles = sources.filter((source) => source.repo !== standardRepository).map((source) => `- ${source.destination}`).join('\n');
  return `THIRD-PARTY AND PROJECT NOTICES

The following files are covered by the PATH-OS MIT notice in LICENSE:

- README.md
- NOTICE
- index.json
- package.json
${pathosFiles}

The following files are covered by the DACS-Standard MIT notice in LICENSE:

${standardFiles}
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
  const files: IndexFile[] = [];
  const expectations: Expectation[] = [];
  const sourceManifest: SourceManifestEntry[] = [];
  for (const source of sources) {
    const bytes = await readFile(join(repoRoot, source.source));
    const destination = join(resolvedOutput, source.destination);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, bytes);
    const sourceSha256 = sha256(bytes);
    sourceManifest.push({ sourcePath: source.source, sha256: sourceSha256 });
    const origin: IndexFile['origin'] = {
      repo: source.repo ?? repository,
      path: source.originPath ?? source.source,
    };
    if (source.commit !== undefined) origin.commit = source.commit;
    files.push({ path: source.destination, sha256: sourceSha256, bytes: bytes.length, group: source.group, origin });
    expectations.push(...extractExpectations(bytes, source.destination));
  }
  expectations.sort((a, b) => compareText(a.path, b.path) || compareText(a.vectorName ?? '', b.vectorName ?? ''));
  sourceManifest.sort((a, b) => compareText(a.sourcePath, b.sourcePath));
  const generatedFrom = { sourceManifestSha256: sha256(Buffer.from(jcs(sourceManifest))) };
  const pins = { dacsSdk: dacsSdkCommit, dacsStandard: standardCommit };
  await writeFile(join(resolvedOutput, 'index.json'), jcs({ v: 'pathos-dacs-fixtures-index:0.1', generatedFrom, pins, files, expectations }));
  await writeFile(join(resolvedOutput, 'package.json'), packageJson());
  await writeFile(join(resolvedOutput, 'README.md'), packageReadme());
  const pathosLicense = await readFile(join(repoRoot, 'conformance/partner-kit/LICENSE'), 'utf8');
  await writeFile(join(resolvedOutput, 'LICENSE'), packageLicense(pathosLicense));
  await writeFile(join(resolvedOutput, 'NOTICE'), packageNotice());
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
