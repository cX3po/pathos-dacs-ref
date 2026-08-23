#!/usr/bin/env node
/**
 * conformance/shared-suite/demo-divergent-adapter.mjs — DEMO ONLY.
 *
 * Proves the implementation-divergence classification. Registers the reference
 * adapter PLUS a deliberately-WRONG stub adapter, then runs the same seed corpus that
 * `cross-run.mjs` runs. The stub is NOT part of the reference adapter and is NEVER
 * registered by `cross-run.mjs`'s default (real) invocation — it exists only here.
 *
 * The stub's bug: `signatureValueVerdict` accepts ANY 86-char base64/base64url-alphabet
 * string as canonical, skipping the decode/re-encode canonical-form check. That is a
 * realistic SIG-6 implementation mistake (a permissive decoder that folds the 4 unused
 * padding bits in the final base64 char instead of rejecting a non-canonical spelling) —
 * exactly the failure mode DACS-Standard#263/#265 exists to catch. Run against the
 * dacs-263 seed vector, it wrongly ACCEPTs the `noncanonical_base64url` case, which the
 * reference adapter correctly REJECTs — that mismatch is the proof.
 *
 * Usage: node demo-divergent-adapter.mjs [--json]
 * Exit: 0 = the demo worked (>=1 divergence produced) · 1 = the demo is broken.
 */
import { crossRun } from './adapter-contract.mjs';
import { loadSeedCorpus } from './seed-corpus.mjs';
import { referenceAdapter } from './reference-adapter.mjs';
import { printHuman, printJson, run } from './cross-run.mjs';

/**
 * A deliberately-divergent stub adapter — NOT a real DACS implementation. Registered only
 * in this demo file, per the build spec ("put the stub in the demo invocation, not in the
 * reference adapter").
 */
function divergentStubAdapter() {
  return {
    name: 'divergent-stub-demo (INTENTIONALLY WRONG — demo only)',
    // BUG (deliberate): treats alphabet + length as sufficient for "canonical" — no
    // decode/re-encode check, so it accepts non-canonical padding-bit spellings.
    signatureValueVerdict(value) {
      if (typeof value !== 'string') return 'REJECT';
      if (/^[A-Za-z0-9+/]{86}==$/.test(value) || /^[A-Za-z0-9_-]{86}$/.test(value)) return 'ACCEPT';
      return 'REJECT';
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes('--json');

  const adapters = [referenceAdapter(), divergentStubAdapter()];
  const corpus = loadSeedCorpus();
  const report = await run(adapters, corpus);

  // Sanity: crossRun() itself must directly confirm a divergence exists, so this demo can
  // never silently succeed merely by printing nothing.
  const { matrix } = await crossRun(adapters, corpus.vectors);
  const divergences = matrix.filter((row) => row.status === 'IMPLEMENTATION-DIVERGENCE');

  if (wantJson) {
    // Keep stdout pure JSON when --json is passed; the proof line goes to stderr instead.
    printJson(report);
  } else {
    printHuman(report, {
      title: 'DACS Shared Conformance Suite — DEMO (proves divergence classification)',
    });
    process.stdout.write(
      'NOTE: "divergent-stub-demo" above is a deliberately-wrong adapter that exists ONLY in ' +
      'this demo file, to prove divergence is classified without creating an automatic ' +
      'SPEC-QUESTION. It is never registered by cross-run.mjs\'s default invocation.\n\n'
    );
  }

  const proofLine = divergences.length > 0
    ? `DEMO PROOF: ${divergences.length} IMPLEMENTATION-DIVERGENCE row(s) produced; 0 automatic SPEC-QUESTION rows.\n`
    : 'DEMO FAILURE: 0 IMPLEMENTATION-DIVERGENCE rows — the demo is broken.\n';
  (wantJson ? process.stderr : process.stdout).write(proofLine);
  return divergences.length > 0 ? 0 : 1;
}

process.exitCode = await main();
