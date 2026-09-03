/**
 * build-verifier-package — compile packages/verifier deterministically and record provenance.
 *
 * The package's four entry files import the repository's verifier (src/lib/verify-document.ts
 * and its closure). tsc is run with rootDir = the repository root so the emitted tree keeps
 * source paths (dist/src/lib/..., dist/packages/verifier/src/...); every emitted file is a
 * compile of a repository source, never a copy. provenance.json fingerprints the exact source
 * set (paths + SHA-256) and the emitted file set; no git revision or timestamp is embedded, so
 * `--check` on the committed tree compares bytes against a fresh build.
 *
 *   node --import tsx scripts/build-verifier-package.mts          # (re)build packages/verifier/dist + provenance.json
 *   node --import tsx scripts/build-verifier-package.mts --check  # exit 1 if the committed output differs
 *
 * The temporary build directory is created UNDER the repository root (.verifier-build-*, gitignored)
 * because tsc resolves node_modules relative to the sources; an os.tmpdir() location breaks that.
 */
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), '..');
const packageRoot = join(repoRoot, 'packages', 'verifier');
const distRoot = join(packageRoot, 'dist');
const compareText = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full));
    else out.push(full);
  }
  return out.sort(compareText);
}

/** The exact source set tsc compiles for the package entries (tsc --listFilesOnly, repo-relative, node_modules excluded). */
async function listSources(): Promise<string[]> {
  const { stdout } = await run(process.execPath, [join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(packageRoot, 'tsconfig.json'), '--listFilesOnly'], { cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 });
  return stdout.split('\n').map((l) => l.trim()).filter(Boolean)
    .map((abs) => relative(repoRoot, abs).split(sep).join('/'))
    .filter((rel) => !rel.startsWith('node_modules/') && !rel.startsWith('../'))
    .sort(compareText);
}

async function compileInto(outDir: string): Promise<void> {
  await run(process.execPath, [join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(packageRoot, 'tsconfig.json'), '--outDir', outDir], { cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 });
}

async function build(): Promise<{ dist: Map<string, Uint8Array>; provenance: string }> {
  const sources = await listSources();
  const sourceManifest = [] as { sourcePath: string; sha256: string }[];
  for (const rel of sources) sourceManifest.push({ sourcePath: rel, sha256: sha256(await readFile(join(repoRoot, rel))) });
  const temp = await mkdtemp(join(repoRoot, '.verifier-build-'));
  try {
    await compileInto(temp);
    const files = new Map<string, Uint8Array>();
    for (const abs of await walk(temp)) files.set(relative(temp, abs).split(sep).join('/'), await readFile(abs));
    const emitted = [...files.entries()].map(([path, bytes]) => ({ path, sha256: sha256(bytes) })).sort((a, b) => compareText(a.path, b.path));
    const provenance = JSON.stringify({
      v: 'pathos-dacs-verifier-provenance:0.1',
      package: '@pathos-labs/dacs-verifier',
      builtBy: 'scripts/build-verifier-package.mts',
      entries: ['packages/verifier/src/index.ts', 'packages/verifier/src/cli.ts', 'packages/verifier/src/http.ts', 'packages/verifier/src/mcp.ts'],
      compiledSources: sourceManifest,
      sourceManifestSha256: sha256(Buffer.from(JSON.stringify(sourceManifest))),
      emitted,
      emittedSha256: sha256(Buffer.from(JSON.stringify(emitted))),
    }, null, 2) + '\n';
    return { dist: files, provenance };
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

async function readCommitted(): Promise<{ dist: Map<string, Uint8Array>; provenance: string | null }> {
  const files = new Map<string, Uint8Array>();
  try {
    await stat(distRoot);
    for (const abs of await walk(distRoot)) files.set(relative(distRoot, abs).split(sep).join('/'), await readFile(abs));
  } catch { /* no dist yet */ }
  let provenance: string | null = null;
  try { provenance = await readFile(join(packageRoot, 'provenance.json'), 'utf8'); } catch { /* none */ }
  return { dist: files, provenance };
}

async function main(): Promise<number> {
  const check = process.argv.includes('--check');
  const fresh = await build();
  if (check) {
    const committed = await readCommitted();
    const problems: string[] = [];
    for (const [path, bytes] of fresh.dist) {
      const have = committed.dist.get(path);
      if (!have) problems.push(`missing in committed dist: ${path}`);
      else if (Buffer.compare(have, bytes) !== 0) problems.push(`differs: dist/${path}`);
    }
    for (const path of committed.dist.keys()) if (!fresh.dist.has(path)) problems.push(`stale file in committed dist: ${path}`);
    if (committed.provenance !== fresh.provenance) problems.push('differs: provenance.json');
    if (problems.length) {
      console.error(`verifier package is NOT reproducible from the committed sources:\n  ${problems.slice(0, 20).join('\n  ')}${problems.length > 20 ? `\n  … ${problems.length - 20} more` : ''}`);
      return 1;
    }
    console.log(`verifier package reproducible: ${fresh.dist.size} files, provenance sourceManifestSha256 ${JSON.parse(fresh.provenance).sourceManifestSha256.slice(0, 16)}…`);
    return 0;
  }
  await rm(distRoot, { recursive: true, force: true });
  for (const [path, bytes] of fresh.dist) {
    await mkdir(dirname(join(distRoot, path)), { recursive: true });
    await writeFile(join(distRoot, path), bytes);
  }
  await writeFile(join(packageRoot, 'provenance.json'), fresh.provenance);
  console.log(`built packages/verifier/dist (${fresh.dist.size} files) + provenance.json`);
  return 0;
}

main().then((code) => process.exit(code), (err) => { console.error(err); process.exit(1); });
