#!/usr/bin/env node
/**
 * dacs-verifier — the packaged DACS attestation-bundle verifier CLI.
 *
 * Same verdicts and exit codes as the repository CLI (src/cli/verify.ts): both call
 * verifyDocument() and loadBundleSource() from src/lib/verify-document.ts.
 *
 * Exit codes: 0 pass, 1 fail, 2 indeterminate, 3 usage error.
 */
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { VERIFIER_API_VERSION, indeterminateVerdict, isLoadError, loadBundleSource, verifyDocument, type VerifyDocumentResult } from '../../../src/lib/verify-document.js';
import { PACKAGE_VERSION } from './index.js';

const USAGE = `
dacs-verifier ${PACKAGE_VERSION} — DACS attestation-bundle verifier

Usage:
  dacs-verifier --bundle-file <path> [--offline] [--rpc <url>] [--json]
  dacs-verifier --stdin [--offline] [--rpc <url>] [--json]
  dacs-verifier --bundle-anchor <stor-...> [--rpc <url>] [--json]
  dacs-verifier --jobId <uuid> [--rpc <url>] [--json]

Options:
  --bundle-file <path>   Local AttestationBundle JSON file
  --stdin                Read the bundle JSON from standard input
  --bundle-anchor <id>   stor-<hex> anchor address fetched from a Demos node
  --jobId <uuid>         Compute both party anchors for the job and fetch them
  --rpc <url>            Demos node RPC URL (default https://demosnode.discus.sh/)
  --offline              Skip the two-sided anchor lookup (receipt-archive audit only);
                         without it an unanchored bundle is indeterminate, never a pass
  --fixture-signatures   v0.1 fixture mode: placeholder signatures are not enforced
  --json                 Print only the JSON result (no human-readable preamble)
  --help                 Show this message

Exit codes: 0 = pass, 1 = fail, 2 = indeterminate, 3 = usage error
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf-8');
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let values: Record<string, unknown>;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        'bundle-file': { type: 'string' },
        'stdin': { type: 'boolean', default: false },
        'bundle-anchor': { type: 'string' },
        'jobId': { type: 'string' },
        'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
        'offline': { type: 'boolean', default: false },
        'fixture-signatures': { type: 'boolean', default: false },
        'json': { type: 'boolean', default: false },
        'help': { type: 'boolean', default: false },
      },
      strict: true,
    }));
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    console.error(USAGE);
    return 3;
  }
  if (values.help) { console.log(USAGE); return 0; }
  const sources = ['bundle-file', 'stdin', 'bundle-anchor', 'jobId'].filter((k) => values[k]);
  if (sources.length !== 1) {
    console.error('Error: give exactly one of --bundle-file, --stdin, --bundle-anchor, --jobId');
    console.error(USAGE);
    return 3;
  }
  const rpc = values.rpc as string;
  const json = values.json as boolean;
  const loaded = await loadBundleSource({
    file: values['bundle-file'] as string | undefined,
    text: values.stdin ? await readStdin() : undefined,
    anchor: values['bundle-anchor'] as string | undefined,
    jobId: values.jobId as string | undefined,
    rpc,
  });
  if (isLoadError(loaded)) {
    const verdict = indeterminateVerdict('source', loaded.error, (values.jobId as string | undefined) ?? 'unknown');
    const result: VerifyDocumentResult = { apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 };
    if (!json) console.error(`dacs-verifier ${PACKAGE_VERSION}\n  ? source: ${loaded.error}\n\nverdict: INDETERMINATE\n`);
    console.log(JSON.stringify(result, null, 2));
    return 2;
  }
  const result = await verifyDocument(loaded, {
    rpc,
    offline: values.offline as boolean,
    requireSignatures: (values['fixture-signatures'] as boolean) ? false : undefined,
    jobId: values.jobId as string | undefined,
  });
  if (!json) {
    console.error(`dacs-verifier ${PACKAGE_VERSION} — bundle kind: ${result.bundleKind}\n`);
    for (const s of result.verdict.steps) {
      const marker = s.outcome === 'pass' ? '✓' : s.outcome === 'fail' ? '✗' : s.outcome === 'skipped' ? '⊘' : '?';
      console.error(`  ${marker} [${s.outcome}] ${s.step}: ${s.detail}`);
    }
    console.error(`\nverdict: ${result.verdict.decision.toUpperCase()}\n`);
  }
  console.log(JSON.stringify(result, null, 2));
  return result.exitCode;
}

/** True when this module is the process entry (argv[1] resolved through symlinks, so npm .bin shims and relative paths both count). */
function isProcessEntry(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  let target = resolve(arg);
  try { target = realpathSync(target); } catch { /* keep the resolved path */ }
  let self = fileURLToPath(import.meta.url);
  try { self = realpathSync(self); } catch { /* keep */ }
  return target === self;
}
const isEntry = isProcessEntry();
if (isEntry) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.error(`dacs-verifier: unhandled error (treated as indeterminate): ${(err as Error).message}`);
    process.exit(2);
  });
}
