#!/usr/bin/env tsx
/**
 * DACS-5 envelope-receipt verifier CLI — the load-bearing artifact of v0.1.
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1 §10.4
 *
 * What this tool does (§10.4.1 normative MUST):
 *   1. Locate the AttestationBundle (from `stor-` anchor OR local file)
 *   2. Recompute the JCS canonical form of the payload (sans signature)
 *   3. Recompute bundleHash = SHA-256(canonical_payload)
 *   4. Recompute signed_bytes = "dacs-bundle:v1:" || bundleHash
 *   5. Verify each signature against the signer's DACS-1 primary-claim public key
 *   6. For two-sided anchoring (§10.4.2 / §10.4.3): verify BOTH party anchors are populated;
 *      unilateral ⇒ mark as `aborted-by-self` for the non-signing party
 *   7. For every AttestationRef in the bundle: fetch from anchor.locator, hash the bytes,
 *      compare to AttestationRef.contentHash. Mismatch ⇒ reject (§7.5.2 normative MUST)
 *   8. Return structured verdict — pass / fail / indeterminate, NEVER coerced (§7.5.1)
 *
 * Exit codes (distinct, so shell pipelines can branch):
 *   0 = pass — all signatures verified, all attestations content-matched
 *   1 = fail — at least one signature or content-hash failed verification
 *   2 = indeterminate — verifier could not reach a definitive conclusion
 *                       (e.g., AttestationRef anchor unreachable, key unresolvable)
 *   3 = usage error (bad CLI args)
 *
 * THIS IS THE GAP DACS v0.7 §11.3 ACKNOWLEDGES AS REMAINING WORK.
 */

import { parseArgs } from 'node:util';
import type { VerifyVerdict } from '../types/index.js';
import { indeterminateVerdict, isLoadError, loadBundleSource, verifyDocument } from '../lib/verify-document.js';

const USAGE = `
pathos-dacs-verify — DACS-5 envelope-receipt verifier (v0.1)

Dual-accept (§10.4.2 backwards-compat): the DEFAULT verify path is the v0.1
AttestationBundle verifier (bundleVersion:"1"); legacy bundles (v:"dacs-5-bundle:0.1")
are still READ via the legacy verification walk.

Usage:
  pathos-dacs-verify --bundle-file <path> [--offline] [--rpc <url>]
  pathos-dacs-verify --bundle-anchor <stor-...> [--rpc <demos-node-url>]
  pathos-dacs-verify --jobId <uuid> [--rpc <demos-node-url>]

Options:
  --bundle-file <path>   Path to a local AttestationBundle JSON file
  --bundle-anchor <id>   stor-<hex> anchor address (fetched from Demos chain)
  --jobId <uuid>         jobId — verifier will compute both party-specific anchors and fetch both
  --rpc <url>            Demos node RPC URL (default: https://demosnode.discus.sh/)
  --offline              Skip §10.4.2 two-sided anchor lookup (BOTH the v0.1 and legacy paths).
                         Use ONLY for receipt-archive audit where the chain is not available.
                         Default (no flag) attempts the two-sided lookup even for --bundle-file
                         inputs and binds the local file to one of the two chain anchors. Without
                         --offline, an UNANCHORED bundle is indeterminate, never a default pass.
  --json                 Output JSON only (suppress human-readable preamble)
  --help                 Show this message

Exit codes:
  0 = pass    1 = fail    2 = indeterminate    3 = usage error

DACS spec sections enforced: §6.3.2, §7.5.1, §7.5.2, §10.4.1, §10.4.2, §10.4.3
`;

interface CliArgs {
  bundleFile?: string;
  bundleAnchor?: string;
  jobId?: string;
  rpc: string;
  json: boolean;
  offline: boolean;
}

function parseCliArgs(): CliArgs {
  // Codex M2 round-8 #2: parseArgs throws on bad flags / missing values. Catch and
  // exit 3 (usage error) so main().catch() doesn't classify these as indeterminate.
  let values: Record<string, unknown>;
  try {
    ({ values } = parseArgs({
      options: {
        'bundle-file': { type: 'string' },
        'bundle-anchor': { type: 'string' },
        'jobId': { type: 'string' },
        'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
        'json': { type: 'boolean', default: false },
        'offline': { type: 'boolean', default: false },
        'help': { type: 'boolean', default: false },
      },
      strict: true,
    }));
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    console.error(USAGE);
    process.exit(3);
  }
  if (values.help) {
    console.log(USAGE);
    process.exit(0);
  }
  if (!values['bundle-file'] && !values['bundle-anchor'] && !values['jobId']) {
    console.error('Error: must provide one of --bundle-file, --bundle-anchor, or --jobId');
    console.error(USAGE);
    process.exit(3);
  }
  return {
    bundleFile: values['bundle-file'] as string | undefined,
    bundleAnchor: values['bundle-anchor'] as string | undefined,
    jobId: values['jobId'] as string | undefined,
    rpc: values['rpc'] as string,
    json: values['json'] as boolean,
    offline: values['offline'] as boolean,
  };
}

async function loadBundle(args: CliArgs): Promise<unknown | { error: string }> {
  // Source resolution is shared with packages/verifier (src/lib/verify-document.ts).
  return loadBundleSource({ file: args.bundleFile, anchor: args.bundleAnchor, jobId: args.jobId, rpc: args.rpc });
}

async function main(): Promise<void> {
  const args = parseCliArgs();

  const loaded = await loadBundle(args);
  const loadError = isLoadError(loaded) ? loaded.error : null;
  if (loadError !== null) {
    // Missing-file / unreachable-anchor is "verifier could not reach a verdict" — indeterminate,
    // so the JSON stays internally consistent (no fail-step under an indeterminate verdict).
    const verdict = indeterminateVerdict('source', loadError, args.jobId ?? 'unknown');
    if (!args.json) {
      console.error(`pathos-dacs-verify — DACS-5 verifier v0.2\n`);
      console.error(`  ? source: ${loadError}`);
      console.error(`\nverdict: INDETERMINATE\n`);
    }
    console.log(JSON.stringify(verdict, null, 2));
    process.exit(2);
  }

  // Dual-accept dispatch (§10.4.2), verdict normalisation and the exit-code mapping live in
  // src/lib/verify-document.ts, shared with packages/verifier. Without --offline an unanchored
  // local bundle is indeterminate, never a default pass.
  const result = await verifyDocument(loaded, {
    rpc: args.rpc,
    offline: args.offline,
    jobId: args.jobId,
  });
  const verdict: VerifyVerdict = result.verdict;
  if (result.bundleKind === 'unrecognised' && !args.json) {
    console.error(`pathos-dacs-verify — DACS verifier v0.1\n`);
    console.error(`  ? classify: ${verdict.steps[0]?.detail ?? 'unrecognised bundle'}`);
    console.error(`\nverdict: INDETERMINATE\n`);
    console.log(JSON.stringify(verdict, null, 2));
    process.exit(2);
  }

  if (!args.json) {
    console.error(`pathos-dacs-verify — DACS-5 verifier v0.2\n`);
    for (const s of verdict.steps) {
      const marker =
        s.outcome === 'pass' ? '✓' :
        s.outcome === 'fail' ? '✗' :
        s.outcome === 'skipped' ? '⊘' : '?';
      console.error(`  ${marker} [${s.outcome}] ${s.step}: ${s.detail}`);
    }
    console.error('');
    console.error(`verdict: ${verdict.decision.toUpperCase()}`);
    console.error(`  bundleHash:         ${verdict.canonicalBundleHash}`);
    console.error(`  signersVerified:    ${verdict.signersVerified.length}`);
    console.error(`  attestationsVerified: ${verdict.attestationsVerified}`);
    console.error(`  attestationsFailed:   ${verdict.attestationsFailed}`);
    console.error('');
  }
  console.log(JSON.stringify(verdict, null, 2));

  // §7.5.1 — exit codes distinguish pass / fail / indeterminate
  process.exit(verdict.decision === 'pass' ? 0 : verdict.decision === 'fail' ? 1 : 2);
}

main().catch((err) => {
  // Codex M2 round-7 #2: unhandled errors from main() (e.g. RPC exceptions that escaped
  // loadBundle's try/catch) should surface as indeterminate (exit 2), not usage error (exit 3).
  // Exit 3 is reserved for clear caller-side problems (bad flags, missing required args).
  console.error(`pathos-dacs-verify: unhandled error (treated as indeterminate per §7.5.1): ${err.message}`);
  process.exit(2);
});
