/**
 * dacs_conformance — CORE 2: runner + assertions.
 *
 * For every generated case, run the input through the REAL verifier predicate and assert
 * actual == expected. Any mismatch is a CONFORMANCE BUG — either the verifier accepted an input that
 * violates a predicate / rejected a valid one (verifier wrong), or the generated case is wrong (case
 * wrong). Both are surfaced: the report names each failing case, its expected vs actual verdict, and
 * the verifier's own reason text so a human can tell which side is at fault.
 *
 * Reads the corpus from conformance/predicate-suite/vectors/<set>.json when present; otherwise builds
 * cases in-memory from the families (so it runs even before vectorgen has written anything).
 *
 * Usage:
 *   npx tsx conformance/predicate-suite/verifycore.mts            # verify all sets
 *   npx tsx conformance/predicate-suite/verifycore.mts bundle-v1  # verify one set
 *   npx tsx conformance/predicate-suite/verifycore.mts --json
 *
 * Exit: 0 = every case conforms · 1 = >=1 conformance bug · 2 = usage error.
 */
import { readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FAMILIES, familyByName } from './families/index.js';
import type { ConformanceCase, Decision, Family } from './types.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(HERE, 'vectors');

export interface CaseResult {
  name: string;
  family: string;
  predicate: string;
  expected: Decision;
  /** 'ERROR' = the verifier's run() threw — a "never throws" contract violation, recorded (not crashed). */
  actual: Decision | 'ERROR';
  conforms: boolean;
  detail: string;
}

export interface SetReport {
  set: string;
  total: number;
  pass: number;
  fail: number;
  results: CaseResult[];
}

/** Load a set's cases from disk if vectorgen wrote them; else build them in-memory. */
function loadCases(family: Family): ConformanceCase[] {
  const file = path.join(VECTORS_DIR, `${family.name}.json`);
  if (existsSync(file)) {
    return JSON.parse(readFileSync(file, 'utf8')) as ConformanceCase[];
  }
  return family.buildCases();
}

/** Run every case of one family and assert actual == expected. */
export function verifySet(family: Family): SetReport {
  const cases = loadCases(family);
  const results: CaseResult[] = cases.map((c) => {
    // The Family contract says run() never throws. If it does anyway, that is
    // itself a conformance failure — capture it as actual='ERROR' so the suite
    // records the misbehaving case instead of crashing mid-set (a throw on a
    // negative case is exactly when the harness must keep reporting).
    let decision: Decision | 'ERROR';
    let detail: string;
    try {
      ({ decision, detail } = family.run(c.input));
    } catch (e) {
      decision = 'ERROR';
      detail = `run() threw (Family "never throws" contract violation): ${e instanceof Error ? e.message : String(e)}`;
    }
    return {
      name: c.name,
      family: c.family,
      predicate: c.predicate,
      expected: c.expected,
      actual: decision,
      conforms: decision === c.expected, // 'ERROR' never equals a Decision → counts as fail
      detail,
    };
  });
  const pass = results.filter((r) => r.conforms).length;
  return { set: family.name, total: results.length, pass, fail: results.length - pass, results };
}

export function verifyAll(only?: string): SetReport[] {
  const fams = only ? [familyByName(only)].filter((f): f is Family => !!f) : FAMILIES;
  return fams.map(verifySet);
}

function main(): number {
  const argv = process.argv.slice(2);
  const json = argv.includes('--json');
  const only = argv.find((a) => !a.startsWith('--'));
  if (only && !familyByName(only)) {
    process.stderr.write(`error: unknown set "${only}". Known: ${FAMILIES.map((f) => f.name).join(', ')}\n`);
    return 2;
  }

  const reports = verifyAll(only);
  const totalFail = reports.reduce((n, r) => n + r.fail, 0);
  const totalCases = reports.reduce((n, r) => n + r.total, 0);

  if (json) {
    process.stdout.write(JSON.stringify({ reports, totalCases, totalFail, conforms: totalFail === 0 }, null, 2) + '\n');
    return totalFail === 0 ? 0 : 1;
  }

  process.stdout.write(`# dacs_conformance verifycore — ${totalCases} case(s) across ${reports.length} set(s)\n\n`);
  for (const r of reports) {
    const mark = r.fail === 0 ? '✅' : '❌';
    process.stdout.write(`${mark} ${r.set.padEnd(12)} ${r.pass}/${r.total} conform\n`);
    for (const c of r.results.filter((x) => !x.conforms)) {
      process.stdout.write(`     ✗ ${c.name}: expected ${c.expected}, got ${c.actual} — ${c.detail}\n`);
    }
  }
  process.stdout.write(`\n**Summary:** ${totalCases - totalFail}/${totalCases} conform · ${totalFail} conformance bug(s)\n`);
  return totalFail === 0 ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exit(main());
}
