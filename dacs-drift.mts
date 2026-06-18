/**
 * dacs-drift — cross-impl conformance / drift runner for DACS v0.1 AttestationBundles (CLI).
 *
 * Operationalises the "conformance partner" role: point it at ANY implementation's bundle
 * fixtures and get back the #99-format divergence table — does each artifact (a) structurally
 * conform to v0.1, and (b) reproduce its expected signed-scope bundleHash under the v0.1 R5-1
 * exclude rule. One tool serving the upstream standard (DACS-Standard) and any DACS implementer.
 *
 * Core logic lives in src/lib/dacs-drift.ts (unit-tested); this file is the thin I/O wrapper.
 * Sibling to pathos-conformance-harness.mts (that one is the JCS/ed25519 crypto oracle).
 *
 * Usage:
 *   npx tsx dacs-drift.mts <fixtures-dir> [--expect <manifest.json>] [--json]
 *   npx tsx dacs-drift.mts <fixtures-dir> --emit-manifest > expected.json
 *     <fixtures-dir>     directory of *.json AttestationBundle fixtures (any impl's)
 *     --expect <file>    JSON manifest { "<basename.json>": "<expectedHashHex>", ... }; enables
 *                        MATCH/DRIFT comparison and non-zero exit on drift / struct-fail / missing.
 *     --emit-manifest    print an expected-hash manifest for the valid bundles in <dir> (the
 *                        bootstrap for --expect mode) to stdout, then exit 0. Mutually exclusive
 *                        with --expect.
 *     --json             machine-readable JSON instead of the markdown table.
 *
 * Exit: 0 = all conform (and match, if --expect); 1 = drift/struct-fail/missing; 2 = bad usage.
 */
import { readFileSync, readdirSync } from 'node:fs';
import * as path from 'node:path';
import { evaluateArtifact, summarise, buildManifest, normHash, type DriftRow } from './src/lib/dacs-drift.js';

function parseArgs(argv: string[]): { dir?: string; expect?: string; json: boolean; emitManifest: boolean; error?: string } {
  const out: { dir?: string; expect?: string; json: boolean; emitManifest: boolean; error?: string } = { json: false, emitManifest: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') out.json = true;
    else if (a === '--emit-manifest') out.emitManifest = true;
    else if (a === '--expect') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) return { ...out, error: '--expect requires a manifest path' };
      out.expect = v;
    } else if (a.startsWith('--')) return { ...out, error: `unknown flag: ${a}` };
    else if (!out.dir) out.dir = a;
    else return { ...out, error: `unexpected extra argument: ${a}` };
  }
  // --emit-manifest GENERATES the expected hashes; comparing against an existing manifest at the
  // same time is contradictory.
  if (out.emitManifest && out.expect) return { ...out, error: '--emit-manifest cannot be combined with --expect' };
  return out;
}

function loadExpected(file: string): Record<string, string> {
  const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('manifest must be a JSON object of { fixture: hash }');
  const m: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    // A conformance manifest must not silently drop entries — a non-string value is a hard error.
    if (typeof v !== 'string') throw new Error(`manifest value for "${k}" is not a string hash`);
    const h = normHash(v);
    // Reject malformed hashes up front so a typo'd manifest fails clearly, not as a confusing "drift".
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`manifest hash for "${k}" is not a 64-char sha256 hex: "${v}"`);
    m[k] = h;
  }
  return m;
}

function readRow(dir: string, file: string, expected: Record<string, string> | null): DriftRow {
  const full = path.join(dir, file);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(full, 'utf8'));
  } catch (e) {
    return { fixture: file, ourHash: '', expected: null, hashStatus: 'computed',
      structurallyValid: false, decision: 'reject', notes: `not valid JSON: ${(e as Error).message}` };
  }
  return evaluateArtifact(parsed, file, expected ? (expected[file] ?? null) : null);
}

function main(): number {
  const { dir, expect, json, emitManifest, error } = parseArgs(process.argv);
  if (error || !dir) {
    if (error) process.stderr.write(`error: ${error}\n`);
    process.stderr.write('usage: npx tsx dacs-drift.mts <fixtures-dir> [--expect <manifest.json>] [--emit-manifest] [--json]\n');
    return 2;
  }
  let expected: Record<string, string> | null;
  let files: string[];
  try {
    expected = expect ? loadExpected(expect) : null;
    files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 2;
  }
  const rows = files.map((f) => readRow(dir, f, expected));
  const s = summarise(rows);
  const missing = expected ? Object.keys(expected).filter((k) => !files.includes(k)) : [];

  // --emit-manifest: print the bootstrap expected-hash manifest (valid bundles only) and exit 0.
  // Diagnostics go to stderr so stdout is a clean, redirectable manifest.
  if (emitManifest) {
    const manifest = buildManifest(rows);
    const included = Object.keys(manifest).length;
    process.stdout.write(JSON.stringify(manifest, null, 2) + '\n');
    process.stderr.write(`# dacs-drift --emit-manifest: ${included} valid bundle(s) pinned · ` +
      `${s.structFail} struct-fail + ${s.skipped} non-bundle excluded (of ${rows.length} file(s))\n`);
    return 0;
  }

  if (json) {
    process.stdout.write(JSON.stringify({ rows, summary: { ...s, missing } }, null, 2) + '\n');
  } else {
    const cell = (str: string, n: number) => (str.length > n ? str.slice(0, n - 1) + '…' : str).padEnd(n);
    process.stdout.write(`# DACS v0.1 drift report — ${rows.length} file(s) in ${dir}\n\n`);
    process.stdout.write(`| fixture | kind | our hash (signed-scope) | expected | status | verify |\n|---|---|---|---|---|---|\n`);
    for (const r of rows) {
      const status = !r.structurallyValid ? '❌ fail'
        : r.hashStatus === 'match' ? '✅ match'
        : r.hashStatus === 'drift' ? '⚠️ DRIFT'
        : r.hashStatus === 'skipped' ? '⏭ skipped' : '— (computed)';
      const struct = r.decision === 'skipped' ? '— not a DACS artifact' : r.structurallyValid ? r.decision : '❌ struct-fail';
      const kind = r.hashStatus === 'skipped' ? '—' : (r.kind === 'settlement' ? 'DACS-4 evidence' : 'DACS-5 bundle');
      const hashCell = r.ourHash ? `\`${r.ourHash.slice(0, 16)}…\`` : '—';
      process.stdout.write(`| ${cell(r.fixture, 36)} | ${kind} | ${hashCell} | ${r.expected ? '`' + r.expected.slice(0, 16) + '…`' : '—'} | ${status} | ${struct} |\n`);
    }
    const notes = rows.filter((r) => r.notes);
    if (notes.length) {
      process.stdout.write(`\n**Notes:**\n`);
      for (const r of notes) process.stdout.write(`- \`${r.fixture}\`: ${r.notes}\n`);
    }
    if (missing.length) process.stdout.write(`\n⚠️ expected fixtures not found in dir: ${missing.join(', ')}\n`);
    process.stdout.write(`\n**Summary:** ${s.checked} artifact(s) checked · ${s.drift} drift · ${s.structFail} struct-fail · ${s.skipped} skipped (non-DACS)` +
      (expected ? ` · ${missing.length} expected-but-missing` : ' · discovery mode (no --expect)') + `\n`);
  }
  return s.drift > 0 || s.structFail > 0 || missing.length > 0 ? 1 : 0;
}

process.exit(main());
