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
 *   4. Recompute signed_bytes = "dacs5-bundle:v1:" || bundleHash
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

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { AttestationBundle, VerifyVerdict, VerifyStep } from '../types/index.js';
import { jcsCanonical, jcsHash } from '../jcs.js';
import { verify as edVerify } from '../lib/sign.js';
import { sha256 } from '@noble/hashes/sha2';

const USAGE = `
pathos-dacs-verify — DACS-5 envelope-receipt verifier

Usage:
  pathos-dacs-verify --bundle-file <path>
  pathos-dacs-verify --bundle-anchor <stor-...> [--rpc <demos-node-url>]
  pathos-dacs-verify --jobId <uuid> [--rpc <demos-node-url>]

Options:
  --bundle-file <path>   Path to a local AttestationBundle JSON file
  --bundle-anchor <id>   stor-<hex> anchor address (fetched from Demos chain)
  --jobId <uuid>         jobId — verifier will compute both party-specific anchors and fetch both
  --rpc <url>            Demos node RPC URL (default: https://demosnode.discus.sh/)
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
}

function parseCliArgs(): CliArgs {
  const { values } = parseArgs({
    options: {
      'bundle-file': { type: 'string' },
      'bundle-anchor': { type: 'string' },
      'jobId': { type: 'string' },
      'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
      'json': { type: 'boolean', default: false },
      'help': { type: 'boolean', default: false },
    },
    strict: true,
  });
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
  };
}

/** Step recorder — accumulates the verify walk for the final verdict. */
class StepLog {
  steps: VerifyStep[] = [];
  add(step: string, outcome: 'pass' | 'fail' | 'indeterminate', detail: string): void {
    this.steps.push({ step, outcome, detail });
  }
  hasFailure(): boolean { return this.steps.some(s => s.outcome === 'fail'); }
  hasIndeterminate(): boolean { return this.steps.some(s => s.outcome === 'indeterminate'); }
}

/**
 * Walk per §10.4.1 — STUB.
 * v0.1 scaffold returns `indeterminate` until the body is implemented.
 * The §7.5.1 invariant — NEVER coerce indeterminate to pass — applies even here.
 */
async function verifyBundle(bundle: AttestationBundle, log: StepLog): Promise<VerifyVerdict> {
  log.add('parse-bundle', 'pass', `bundle.v=${bundle.v}, jobId=${bundle.jobId}, role=${bundle.role}`);

  // Step 1: canonical form + hash
  const canonical = jcsCanonical({ ...bundle, signature: undefined, orchestratorSignature: undefined });
  const bundleHash = jcsHash({ ...bundle, signature: undefined, orchestratorSignature: undefined });
  const bundleHashHex = Array.from(bundleHash, (b) => b.toString(16).padStart(2, '0')).join('');
  log.add('canonicalize', 'pass', `JCS canonical bytes=${canonical.length}, bundleHash=${bundleHashHex}`);

  // Step 2: signature verification — STUB (needs DACS-1 key resolution)
  log.add('verify-signature', 'indeterminate',
    'TODO v0.2: resolve DACS-1 primary-claim public key via Demos CCI or ERC-8004, then ed25519-verify');
  log.add('two-sided-anchoring', 'indeterminate',
    'TODO v0.2: fetch both party-specific anchors per §10.4.2 + check for unilateral');
  log.add('attestation-refs', 'indeterminate',
    'TODO v0.2: walk every AttestationRef, fetch + content-hash compare per §7.5.2');

  const decision: VerifyVerdict['decision'] =
    log.hasFailure() ? 'fail' :
    log.hasIndeterminate() ? 'indeterminate' : 'pass';

  return {
    decision,
    jobId: bundle.jobId,
    steps: log.steps,
    canonicalBundleHash: bundleHashHex,
    signersVerified: [],
    attestationsVerified: 0,
    attestationsFailed: 0,
  };
}

/** Compute the §10.4.2 two-sided anchors. */
export function computeAnchorPair(jobId: string): { buyer: string; seller: string } {
  const buyer = 'stor-' + bytesToHex(sha256(new TextEncoder().encode(jobId + '-bundle-buyer')));
  const seller = 'stor-' + bytesToHex(sha256(new TextEncoder().encode(jobId + '-bundle-seller')));
  return { buyer, seller };
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const log = new StepLog();

  let bundle: AttestationBundle | undefined;
  try {
    if (args.bundleFile) {
      bundle = JSON.parse(readFileSync(args.bundleFile, 'utf-8')) as AttestationBundle;
      log.add('source', 'pass', `loaded from file: ${args.bundleFile}`);
    } else if (args.bundleAnchor) {
      log.add('source', 'indeterminate', `TODO v0.2: fetch ${args.bundleAnchor} via Demos RPC ${args.rpc}`);
    } else if (args.jobId) {
      const pair = computeAnchorPair(args.jobId);
      log.add('source', 'indeterminate',
        `TODO v0.2: jobId=${args.jobId} resolves to anchors buyer=${pair.buyer}, seller=${pair.seller}; verifier MUST fetch BOTH per §10.4.3`);
    }
  } catch (e) {
    log.add('source', 'fail', `failed to load bundle: ${(e as Error).message}`);
  }

  let verdict: VerifyVerdict;
  if (bundle) {
    verdict = await verifyBundle(bundle, log);
  } else {
    verdict = {
      decision: log.hasFailure() ? 'fail' : 'indeterminate',
      jobId: args.jobId ?? 'unknown',
      steps: log.steps,
      canonicalBundleHash: '',
      signersVerified: [],
      attestationsVerified: 0,
      attestationsFailed: 0,
    };
  }

  if (!args.json) {
    console.error(`pathos-dacs-verify — DACS-5 verifier v0.1 (scaffold)\n`);
    for (const s of verdict.steps) {
      const marker = s.outcome === 'pass' ? '✓' : s.outcome === 'fail' ? '✗' : '?';
      console.error(`  ${marker} [${s.outcome}] ${s.step}: ${s.detail}`);
    }
    console.error('');
    console.error(`verdict: ${verdict.decision.toUpperCase()}`);
    console.error('');
  }
  console.log(JSON.stringify(verdict, null, 2));

  // §7.5.1 — exit codes distinguish pass / fail / indeterminate
  process.exit(verdict.decision === 'pass' ? 0 : verdict.decision === 'fail' ? 1 : 2);
}

main().catch((err) => {
  console.error(`pathos-dacs-verify: ${err.message}`);
  process.exit(3);
});
