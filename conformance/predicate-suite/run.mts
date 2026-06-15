/**
 * dacs_conformance — the loop, in one command.
 *
 *   vectorgen → verifycore → report → diff golden → on drift or non-conformance, surface + non-zero exit.
 *
 * Deterministic, $0, no LLM / no API / no network. This is the "DACS check": a deterministic pass/fail
 * across every enumerated predicate. Runs unattended; the only signals are CONFORMANCE BUG (a verifier
 * verdict disagreed with the expected verdict) and CORPUS DRIFT (the generated corpus no longer matches
 * its content-hashed golden — the predicate set changed).
 *
 * Usage:
 *   npx tsx conformance/predicate-suite/run.mts            # generate, verify, drift-check
 *   npx tsx conformance/predicate-suite/run.mts --update   # accept the current corpus as golden, then verify
 *   npx tsx conformance/predicate-suite/run.mts --json
 *
 * Exit: 0 = all conform AND no undeclared drift · 1 = conformance bug OR drift · 2 = usage error.
 */
import { generateAll } from './vectorgen.mjs';
import { verifyAll } from './verifycore.mjs';

function main(): number {
  const argv = process.argv.slice(2);
  const update = argv.includes('--update');
  const json = argv.includes('--json');
  const unknown = argv.find((a) => a.startsWith('--') && a !== '--update' && a !== '--json');
  if (unknown) {
    process.stderr.write(`error: unknown flag ${unknown}\n`);
    return 2;
  }

  const gen = generateAll(update);
  const reports = verifyAll();

  const drifted = gen.filter((g) => g.drift);
  const totalCases = reports.reduce((n, r) => n + r.total, 0);
  const totalFail = reports.reduce((n, r) => n + r.fail, 0);
  const driftFail = drifted.length > 0 && !update;
  const ok = totalFail === 0 && !driftFail;

  if (json) {
    process.stdout.write(JSON.stringify({ gen, reports, totalCases, totalFail, drift: driftFail, ok }, null, 2) + '\n');
    return ok ? 0 : 1;
  }

  process.stdout.write(`# dacs_conformance — deterministic DACS check\n\n`);
  process.stdout.write(`## corpus (vectorgen)\n`);
  for (const g of gen) {
    const s = update ? 'golden updated' : g.previousHash === null ? 'golden created' : g.drift ? '⚠️ DRIFT' : '✅ golden match';
    process.stdout.write(`- ${g.set.padEnd(12)} ${String(g.count).padStart(3)} case(s)  ${g.hash.slice(0, 16)}…  ${s}\n`);
  }
  process.stdout.write(`\n## conformance (verifycore)\n`);
  for (const r of reports) {
    const mark = r.fail === 0 ? '✅' : '❌';
    process.stdout.write(`${mark} ${r.set.padEnd(12)} ${r.pass}/${r.total} conform\n`);
    for (const c of r.results.filter((x) => !x.conforms)) {
      process.stdout.write(`     ✗ ${c.name}: expected ${c.expected}, got ${c.actual} — ${c.detail}\n`);
    }
  }
  process.stdout.write(`\n**Result:** ${totalCases - totalFail}/${totalCases} conform`);
  if (driftFail) process.stdout.write(` · ⚠️ ${drifted.length} set(s) drifted (re-run with --update if intended)`);
  process.stdout.write(`\n`);
  return ok ? 0 : 1;
}

process.exit(main());
