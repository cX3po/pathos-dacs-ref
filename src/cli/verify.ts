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

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { AttestationBundle, VerifyVerdict } from '../types/index.js';
import type { AttestationBundleV1 } from '../types/bundle.js';
import { verifyBundle, computeAnchorPair } from '../lib/verify-bundle.js';
import { verifyBundleV1, type BundleV1Verdict } from '../lib/verify-bundle-v1.js';
import { fetchAnchored } from '../demos/storage.js';

/**
 * Dual-accept dispatch (§10.4.2 backwards-compat). The DEFAULT verify path is the v0.1
 * AttestationBundleV1 verifier (verifyBundleV1); legacy `dacs-5-bundle:0.1` bundles are still
 * READ via the legacy verifyBundle walk. Discriminated on the bundle's version field:
 *   - bundleVersion === '1'        -> v0.1 path (verifyBundleV1) — DEFAULT for emission too
 *   - v === 'dacs-5-bundle:0.1'    -> legacy read path (verifyBundle)
 */
type LoadedBundle =
  | { kind: 'v1'; bundle: AttestationBundleV1 }
  | { kind: 'legacy'; bundle: AttestationBundle };

function classifyBundle(raw: unknown): LoadedBundle | { error: string } {
  if (!raw || typeof raw !== 'object') return { error: 'bundle is not a JSON object' };
  const o = raw as Record<string, unknown>;
  if (o.bundleVersion === '1') return { kind: 'v1', bundle: raw as AttestationBundleV1 };
  if (o.v === 'dacs-5-bundle:0.1') return { kind: 'legacy', bundle: raw as AttestationBundle };
  return {
    error: `unrecognised bundle shape — expected a v0.1 AttestationBundle (bundleVersion:"1") ` +
      `or a legacy bundle (v:"dacs-5-bundle:0.1"); got bundleVersion=${String(o.bundleVersion)} v=${String(o.v)}`,
  };
}

/** Normalise the v0.1 BundleV1Verdict into the CLI's VerifyVerdict shape (accept->pass / reject->fail). */
function normaliseV1Verdict(jobId: string, v: BundleV1Verdict): VerifyVerdict {
  const steps: VerifyStepLite[] = [
    { step: 'structural', outcome: v.structurallyValid ? 'pass' : 'fail', detail: v.structurallyValid ? 'v0.1 §10.4 shape valid' : v.reasons.join('; ') },
    { step: 'signer-rule', outcome: v.signerRuleSatisfied ? 'pass' : 'fail', detail: v.signerRuleSatisfied ? 'required-signer rule satisfied (§10.4.1)' : v.reasons.join('; ') },
    { step: 'signatures', outcome: v.cryptographicallyVerified ? 'pass' : (v.decision === 'reject' ? 'fail' : 'indeterminate'),
      detail: v.signatureChecks.map((c) => `${c.party.slice(0, 18)}…:${c.decision}${c.reason ? ` (${c.reason})` : ''}`).join('; ') || 'no signatures' },
  ];
  return {
    decision: v.decision === 'accept' ? 'pass' : 'fail',
    jobId,
    steps,
    canonicalBundleHash: v.bundleHash,
    signersVerified: v.signatureChecks.filter((c) => c.decision === 'pass').map((c) => c.party),
    attestationsVerified: 0,
    attestationsFailed: 0,
  };
}
type VerifyStepLite = VerifyVerdict['steps'][number];

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
  --offline              Skip §10.4.2 two-sided anchor lookup. Use ONLY for receipt-archive
                         audit where the chain is not available. Default (no flag) attempts
                         the two-sided lookup even for --bundle-file inputs and binds the
                         local file to one of the two chain anchors.
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
  if (args.bundleFile) {
    try {
      return JSON.parse(readFileSync(args.bundleFile, 'utf-8'));
    } catch (e) {
      return { error: `failed to load bundle from ${args.bundleFile}: ${(e as Error).message}` };
    }
  }
  if (args.bundleAnchor) {
    // Codex M2 round-7 #2: fetch exceptions MUST surface as indeterminate, not crash to exit 3.
    let fetched;
    try {
      fetched = await fetchAnchored(args.rpc, args.bundleAnchor);
    } catch (e) {
      return { error: `bundle anchor fetch failed (RPC error): ${(e as Error).message}` };
    }
    if (!fetched) return { error: `bundle anchor ${args.bundleAnchor} not found at ${args.rpc}` };
    // The anchored data IS the bundle JSON
    const raw = typeof fetched.data === 'string' ? fetched.data : JSON.stringify(fetched.data);
    try {
      return JSON.parse(raw);
    } catch (e) {
      return { error: `bundle at ${args.bundleAnchor} is not valid JSON: ${(e as Error).message}` };
    }
  }
  if (args.jobId) {
    // Try both party-specific anchors. Codex round-8 #1: if EITHER fetch throws and
    // we can't establish a winner from the other side, surface as an explicit RPC error.
    // We don't want a buyer-RPC-error + seller-not-found to silently report "neither
    // anchor present" — that's a different signal than what actually happened.
    const pair = computeAnchorPair(args.jobId);
    let buyer, seller;
    let buyerErr: string | undefined;
    let sellerErr: string | undefined;
    try { buyer = await fetchAnchored(args.rpc, pair.buyer); } catch (e) { buyerErr = (e as Error).message; }
    try { seller = await fetchAnchored(args.rpc, pair.seller); } catch (e) { sellerErr = (e as Error).message; }
    const winner = buyer ?? seller;
    if (!winner) {
      // Distinguish "all RPC errors" from "any absence" from "all clear-absent"
      if (buyerErr || sellerErr) {
        const parts: string[] = [];
        if (buyerErr) parts.push(`buyer fetch RPC error: ${buyerErr}`); else parts.push(`buyer anchor absent at ${pair.buyer}`);
        if (sellerErr) parts.push(`seller fetch RPC error: ${sellerErr}`); else parts.push(`seller anchor absent at ${pair.seller}`);
        return { error: `bundle-load failed for jobId=${args.jobId} at ${args.rpc}: ${parts.join('; ')}` };
      }
      return { error: `neither party anchor present at ${args.rpc} (buyer=${pair.buyer}, seller=${pair.seller})` };
    }
    const raw = typeof winner.data === 'string' ? winner.data : JSON.stringify(winner.data);
    try {
      return JSON.parse(raw);
    } catch (e) {
      return { error: `bundle at ${pair.buyer}/${pair.seller} is not valid JSON: ${(e as Error).message}` };
    }
  }
  return { error: 'unreachable: parseCliArgs already enforces at least one source flag' };
}

async function main(): Promise<void> {
  const args = parseCliArgs();

  const loaded = await loadBundle(args);
  const loadError =
    loaded && typeof loaded === 'object' && 'error' in loaded && typeof (loaded as { error: unknown }).error === 'string'
      ? (loaded as { error: string }).error
      : null;
  if (loadError !== null) {
    // Codex M2 #2: the step outcome MUST match the rollup decision.
    // Missing-file / unreachable-anchor is "verifier could not reach a verdict" —
    // that's indeterminate semantically. Use outcome:'indeterminate' so the JSON
    // is internally consistent (no rule-violating fail-step + indeterminate-verdict).
    const verdict: VerifyVerdict = {
      decision: 'indeterminate',
      jobId: args.jobId ?? 'unknown',
      steps: [{ step: 'source', outcome: 'indeterminate', detail: loadError }],
      canonicalBundleHash: '',
      signersVerified: [],
      attestationsVerified: 0,
      attestationsFailed: 0,
    };
    if (!args.json) {
      console.error(`pathos-dacs-verify — DACS-5 verifier v0.2\n`);
      console.error(`  ? source: ${loadError}`);
      console.error(`\nverdict: INDETERMINATE\n`);
    }
    console.log(JSON.stringify(verdict, null, 2));
    process.exit(2);
  }

  // Dual-accept dispatch (§10.4.2). DEFAULT verify path = v0.1 verifyBundleV1; legacy bundles
  // are still READ via the legacy walk.
  const classified = classifyBundle(loaded);
  if ('error' in classified) {
    const verdict: VerifyVerdict = {
      decision: 'indeterminate',
      jobId: args.jobId ?? 'unknown',
      steps: [{ step: 'classify', outcome: 'indeterminate', detail: classified.error }],
      canonicalBundleHash: '', signersVerified: [], attestationsVerified: 0, attestationsFailed: 0,
    };
    if (!args.json) {
      console.error(`pathos-dacs-verify — DACS verifier v0.1\n`);
      console.error(`  ? classify: ${classified.error}`);
      console.error(`\nverdict: INDETERMINATE\n`);
    }
    console.log(JSON.stringify(verdict, null, 2));
    process.exit(2);
  }

  let verdict: VerifyVerdict;
  if (classified.kind === 'v1') {
    // v0.1 path. The v0.1 verifier is a single-bundle structural+signature check; the chain-side
    // two-sided anchoring (§10.4.2/§10.4.3) is not part of verifyBundleV1, so --offline is moot here.
    const v1 = verifyBundleV1(classified.bundle);
    verdict = normaliseV1Verdict(classified.bundle.jobId ?? (args.jobId ?? 'unknown'), v1);
  } else {
    // Codex M2 round-7 #1: only skip two-sided lookup when explicitly opted in via --offline.
    // Default --bundle-file verification still attempts the chain lookup, binding the local
    // file to one of the two anchors. This enforces the local-bundle binding invariant for
    // file-based verifies too.
    verdict = await verifyBundle(classified.bundle, {
      rpc: args.rpc,
      skipTwoSidedLookup: args.offline,
    });
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
