/**
 * dacs_conformance — CORE 1: deterministic test-corpus generator.
 *
 * For each verification predicate the verifier enforces, emit:
 *   - one VALID case  (predicate satisfied)        → expected ACCEPT
 *   - N NEGATIVE cases (each violates exactly one)  → expected REJECT, reason: <predicate>
 *
 * The corpus is a deterministic enumeration (no model, no network, no randomness). It is written to
 *   conformance/predicate-suite/vectors/<set>.json
 * and snapshotted to a content-hashed golden file
 *   conformance/predicate-suite/golden/<set>.json   ({ hash, count, generatedFrom })
 * so DRIFT (the corpus changed unexpectedly) is a single sha256 comparison.
 *
 * Usage:
 *   npx tsx conformance/predicate-suite/vectorgen.mts            # generate; FAIL (exit 1) on drift
 *   npx tsx conformance/predicate-suite/vectorgen.mts --update   # accept current corpus as the golden
 *   npx tsx conformance/predicate-suite/vectorgen.mts --json     # machine-readable summary
 *
 * Exit: 0 = generated, golden matches (or --update) · 1 = drift vs golden · 2 = usage error.
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import { FAMILIES } from './families/index.js';
import type { ConformanceCase } from './types.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(HERE, 'vectors');
const GOLDEN_DIR = path.join(HERE, 'golden');

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** Canonical, stable serialisation of a corpus → the bytes the golden hash is taken over. */
function canonicalJson(cases: ConformanceCase[]): string {
  return JSON.stringify(cases, null, 2) + '\n';
}

export interface GoldenManifest {
  set: string;
  hash: string;
  count: number;
  predicates: string[];
}

export interface GenResult {
  set: string;
  count: number;
  hash: string;
  drift: boolean;
  previousHash: string | null;
}

/** Generate the corpus for one family, write vectors, return the drift verdict vs golden. */
export function generateSet(set: string, cases: ConformanceCase[], update: boolean): GenResult {
  mkdirSync(VECTORS_DIR, { recursive: true });
  mkdirSync(GOLDEN_DIR, { recursive: true });

  const body = canonicalJson(cases);
  const hash = toHex(sha256(new TextEncoder().encode(body)));
  writeFileSync(path.join(VECTORS_DIR, `${set}.json`), body);

  const goldenPath = path.join(GOLDEN_DIR, `${set}.json`);
  let previousHash: string | null = null;
  if (existsSync(goldenPath)) {
    previousHash = (JSON.parse(readFileSync(goldenPath, 'utf8')) as GoldenManifest).hash ?? null;
  }
  const drift = previousHash !== null && previousHash !== hash;

  if (update || previousHash === null) {
    const manifest: GoldenManifest = { set, hash, count: cases.length, predicates: cases.map((c) => c.predicate) };
    writeFileSync(goldenPath, JSON.stringify(manifest, null, 2) + '\n');
  }
  return { set, count: cases.length, hash, drift, previousHash };
}

/** Generate every family's corpus. */
export function generateAll(update: boolean): GenResult[] {
  return FAMILIES.map((f) => generateSet(f.name, f.buildCases(), update));
}

function main(): number {
  const argv = process.argv.slice(2);
  const update = argv.includes('--update');
  const json = argv.includes('--json');
  const unknown = argv.find((a) => a.startsWith('--') && a !== '--update' && a !== '--json');
  if (unknown) {
    process.stderr.write(`error: unknown flag ${unknown}\n`);
    return 2;
  }

  const results = generateAll(update);
  const drifted = results.filter((r) => r.drift);

  if (json) {
    process.stdout.write(JSON.stringify({ results, drift: drifted.length > 0, updated: update }, null, 2) + '\n');
  } else {
    process.stdout.write(`# dacs_conformance vectorgen — ${results.length} set(s)\n\n`);
    for (const r of results) {
      const status = update ? 'golden updated' : r.previousHash === null ? 'golden created' : r.drift ? '⚠️ DRIFT vs golden' : '✅ matches golden';
      process.stdout.write(`- ${r.set.padEnd(12)} ${String(r.count).padStart(3)} case(s)  ${r.hash.slice(0, 16)}…  ${status}\n`);
    }
    if (drifted.length && !update) {
      process.stdout.write(`\n⚠️ ${drifted.length} set(s) drifted from golden. If the change is intended, re-run with --update.\n`);
      for (const r of drifted) process.stdout.write(`   ${r.set}: golden ${r.previousHash?.slice(0, 16)}… → now ${r.hash.slice(0, 16)}…\n`);
    }
  }
  return drifted.length && !update ? 1 : 0;
}

// Run as CLI only when invoked directly (importable as a module otherwise).
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exit(main());
}
