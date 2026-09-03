import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

type ManifestEntry = { sourcePath: string; sha256: string };

const run = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), '..');
const packageRoot = join(repoRoot, 'packages', 'jcs');
const compareText = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;

const staticFiles = ['LICENSE', 'NOTICE', 'README.md', 'package.json', 'src/index.ts', 'tsconfig.json'] as const;
const implementationSources = [
  { source: 'src/domain-sep.ts', destination: 'src/domain-sep.ts' },
  { source: 'src/jcs.ts', destination: 'src/jcs.ts' },
  { source: 'src/lib/sign.ts', destination: 'src/lib/sign.ts' },
] as const;
const vectorSources = [
  { source: 'conformance/partner-kit/vectors.json', destination: 'vectors/canonical-form-v0.1.json' },
] as const;

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error('Manifest contains a non-JSON value');
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort(compareText).map((key) => `${JSON.stringify(key)}:${jcs(record[key])}`).join(',')}}`;
}

async function copy(source: string, destination: string): Promise<void> {
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(source, destination);
}

async function buildAt(output: string): Promise<void> {
  await mkdir(output, { recursive: true });
  for (const path of staticFiles) {
    await copy(join(packageRoot, path), join(output, path));
  }

  const sourceManifest: ManifestEntry[] = [];
  for (const item of implementationSources) {
    const bytes = await readFile(join(repoRoot, item.source));
    await copy(join(repoRoot, item.source), join(output, item.destination));
    sourceManifest.push({ sourcePath: item.source, sha256: sha256(bytes) });
  }
  const indexBytes = await readFile(join(packageRoot, 'src/index.ts'));
  sourceManifest.push({ sourcePath: 'packages/jcs/src/index.ts', sha256: sha256(indexBytes) });
  sourceManifest.sort((a, b) => compareText(a.sourcePath, b.sourcePath));

  const sourceManifestSha256 = sha256(Buffer.from(jcs(sourceManifest)));
  await writeFile(join(output, 'provenance.json'), jcs({
    v: 'pathos-dacs-jcs-provenance:0.1',
    generatedFrom: { sourceManifestSha256 },
    compiledSources: sourceManifest,
  }));

  const vectorFiles = [];
  for (const item of vectorSources) {
    const bytes = await readFile(join(repoRoot, item.source));
    await copy(join(repoRoot, item.source), join(output, item.destination));
    vectorFiles.push({
      path: item.destination,
      bytes: bytes.length,
      sha256: sha256(bytes),
      origin: { repo: 'cX3po/pathos-dacs-ref', path: item.source },
    });
  }
  vectorFiles.sort((a, b) => compareText(a.path, b.path));
  await writeFile(join(output, 'vectors', 'index.json'), jcs({
    v: 'pathos-dacs-jcs-vectors-index:0.1',
    files: vectorFiles,
  }));

  const compiler = join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc');
  try {
    await run(process.execPath, [compiler, '--project', join(output, 'tsconfig.json'), '--pretty', 'false'], { cwd: repoRoot });
  } catch (error) {
    const failure = error as Error & { stdout?: string; stderr?: string };
    const diagnostics = `${failure.stdout ?? ''}${failure.stderr ?? ''}`.trim();
    throw new Error(diagnostics.length > 0 ? `TypeScript package build failed:\n${diagnostics}` : 'TypeScript package build failed');
  }
}

async function listFiles(root: string, current = root): Promise<string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  const result: string[] = [];
  for (const entry of entries.sort((a, b) => compareText(a.name, b.name))) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) result.push(...await listFiles(root, path));
    else if (entry.isFile()) result.push(relative(root, path).split(sep).join('/'));
  }
  return result;
}

async function compareDirectories(expected: string, actual: string): Promise<string[]> {
  const [expectedFiles, actualFiles] = await Promise.all([listFiles(expected), listFiles(actual)]);
  const differences: string[] = [];
  const paths = [...new Set([...expectedFiles, ...actualFiles])].sort(compareText);
  for (const path of paths) {
    if (!expectedFiles.includes(path)) differences.push(`unexpected ${path}`);
    else if (!actualFiles.includes(path)) differences.push(`missing ${path}`);
    else {
      const [expectedBytes, actualBytes] = await Promise.all([
        readFile(join(expected, path)),
        readFile(join(actual, path)),
      ]);
      if (!expectedBytes.equals(actualBytes)) differences.push(`different ${path}`);
    }
  }
  return differences;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== '--check') || args.filter((arg) => arg === '--check').length > 1) {
    throw new Error('Usage: build-jcs-package.mts [--check]');
  }
  const check = args.includes('--check');
  const temporary = await mkdtemp(join(repoRoot, '.jcs-build-'));
  try {
    const rebuilt = join(temporary, 'jcs');
    await buildAt(rebuilt);
    if (check) {
      const differences = await compareDirectories(packageRoot, rebuilt);
      if (differences.length > 0) throw new Error(`JCS package is stale:\n${differences.join('\n')}`);
      return;
    }
    await rm(packageRoot, { recursive: true, force: true });
    await rename(rebuilt, packageRoot);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

await main();
