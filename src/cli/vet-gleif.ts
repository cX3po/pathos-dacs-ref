#!/usr/bin/env tsx
/**
 * DACS-2 Vet CLI — runs the `consensus-backed-proxy` recipe against GLEIF
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1 §7.3.5, §7.5.1, §7.5.2
 *
 * What this tool does:
 *   1. Take an LEI (or list of LEIs) as input
 *   2. Fetch the LEI record via the open GLEIF public API (no key required)
 *      https://api.gleif.org/api/v1/lei-records/{LEI}
 *   3. Convert the response into a §7.5.1 VerifyResult with:
 *        decision = "pass"  iff entity exists AND registration is ISSUED (active)
 *        decision = "fail"  iff entity not found OR registration LAPSED/RETIRED/ANNULLED
 *        decision = "indeterminate" iff the record parses but its status is non-binary
 *                                   (authority answered; answer not conclusive — §7.5.1)
 *        decision = "error" iff verification could not complete: transport failure,
 *                                   timeout, or a response the parser cannot consume (§7.5.1).
 *                                   error ≠ indeterminate: the verifier never got an answer
 *                                   (per §7.5.1; CM-4 requires classifying into this 4-value enum).
 *   4. Produce an AttestationRef (DAHR-attested response hash) — STUB in v0.1
 *      (Demos SDK DAHR proxy will wire in v0.2)
 *   5. Print the structured VerifyResult to stdout
 *
 * Initial scope is GLEIF only because it's the cleanest live public API the spec
 * maps (open, no key, deterministic). Future recipes compose the same way.
 */

import { parseArgs } from 'node:util';
import type { VerifyResult, VerifyDecision } from '../types/index.js';
import { connectDemos, mnemonicFromEnv, dahrFetch } from '../demos/index.js';

const USAGE = `
pathos-dacs-vet-gleif — DACS-2 Vet via GLEIF consensus-backed-proxy

Usage:
  pathos-dacs-vet-gleif --lei <LEI> --jobId <uuid> [--mnemonic-env DEMOS_MNEMONIC] [--dry-run]

Options:
  --lei <LEI>            The ISO 17442 LEI to vet (20 hex characters)
  --jobId <uuid>         The job/session id (per §7.5.1 VerifyResult schema)
  --mnemonic-env <name>  Env var with Demos mnemonic for SR-2 anchoring (default: DEMOS_MNEMONIC)
  --dry-run              Skip SR-2 anchoring (still fetches GLEIF live)
  --rpc <url>            Demos node RPC URL (default: https://demosnode.discus.sh/)
  --recipe-version <v>   Recipe version pin (default: "gleif-cbp:1")
  --help                 Show this message

Exit codes:
  0 = pass    1 = fail    2 = indeterminate    3 = usage error    4 = error (§7.5.1)

DACS spec sections: §7.3.5 (consensus-backed-proxy), §7.5.1 (VerifyResult), §7.5.2 (AttestationRef)
`;

interface CliArgs {
  lei: string;
  jobId: string;
  recipeVersion: string;
  mnemonicEnv: string;
  rpc: string;
  dryRun: boolean;
}

function parseCliArgs(): CliArgs {
  const { values } = parseArgs({
    options: {
      'lei': { type: 'string' },
      'jobId': { type: 'string' },
      'recipe-version': { type: 'string', default: 'gleif-cbp:1' },
      'mnemonic-env': { type: 'string', default: 'DEMOS_MNEMONIC' },
      'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
      'dry-run': { type: 'boolean', default: false },
      'help': { type: 'boolean', default: false },
    },
    strict: true,
  });
  if (values.help) { console.log(USAGE); process.exit(0); }
  if (!values.lei || !values.jobId) {
    console.error('Error: --lei and --jobId are required');
    console.error(USAGE);
    process.exit(3);
  }
  const lei = (values.lei as string).toUpperCase();
  if (!/^[A-Z0-9]{20}$/.test(lei)) {
    console.error(`Error: LEI "${lei}" is not a valid 20-character alphanumeric`);
    process.exit(3);
  }
  return {
    lei,
    jobId: values.jobId as string,
    recipeVersion: values['recipe-version'] as string,
    mnemonicEnv: values['mnemonic-env'] as string,
    rpc: values['rpc'] as string,
    dryRun: values['dry-run'] as boolean,
  };
}

interface GleifLeiResponse {
  data?: {
    id?: string;
    attributes?: {
      entity?: { legalName?: { name?: string } };
      registration?: { status?: string; nextRenewalDate?: string };
    };
  };
  errors?: { detail?: string }[];
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const runAt = new Date().toISOString();
  const gleifUrl = `https://api.gleif.org/api/v1/lei-records/${args.lei}`;

  // Connect to Demos for SR-2 anchoring unless --dry-run is set.
  // Per Codex review #2: a failed connection MUST NOT silently degrade to stub
  // anchoring. Either the operator asked for --dry-run (explicit stub), or we
  // refuse to produce a misleading "anchored"-looking AttestationRef on a
  // connection failure.
  let handle: Awaited<ReturnType<typeof connectDemos>> | undefined;
  if (!args.dryRun) {
    try {
      const mn = mnemonicFromEnv(args.mnemonicEnv);
      handle = await connectDemos(mn, args.rpc);
      console.error(`✓ Demos handle connected: address=${handle.address.slice(0, 10)}…`);
    } catch (e) {
      console.error(`Error: Demos connection failed (${(e as Error).message})`);
      console.error('Pass --dry-run to explicitly skip anchoring, or fix the connection (DEMOS_MNEMONIC env, RPC URL).');
      process.exit(4); // §7.5.1 error — verifier could not complete (transport/setup failure), NOT indeterminate
    }
  }

  // DAHR-fetch the GLEIF endpoint. Even if anchoring is skipped, the AttestationRef
  // is still produced with a stub locator (skipAnchor=true).
  let decision: VerifyDecision;
  let reason: string;
  let entityName: string | undefined;
  let regStatus: string | undefined;
  let attestation: VerifyResult['attestation'];

  try {
    const dahr = await dahrFetch(handle, gleifUrl, {
      headers: { Accept: 'application/vnd.api+json' },
      recipe: args.recipeVersion,
      skipAnchor: args.dryRun || !handle,
      anchorProgramName: `dacs2:gleif:${args.lei}`,
    });
    attestation = dahr.attestation;
    const body = dahr.responseBody as GleifLeiResponse;

    if (dahr.responseStatus === 404 || (body.errors && body.errors.length > 0)) {
      decision = 'fail';
      reason = `LEI not found at GLEIF: ${body.errors?.[0]?.detail ?? 'HTTP 404'}`;
    } else if (!body.data) {
      // §7.5.1 error: a response the parser cannot consume / unexpected authority API
      // shape — the verifier never obtained an authority decision. NOT indeterminate
      // (which is reserved for a parseable record the authority left non-binary).
      decision = 'error';
      reason = 'GLEIF response had neither data nor errors — parser could not consume it (unexpected shape)';
    } else {
      entityName = body.data.attributes?.entity?.legalName?.name;
      regStatus = body.data.attributes?.registration?.status;
      if (regStatus === 'ISSUED') {
        decision = 'pass';
        reason = `LEI active (ISSUED), entity="${entityName ?? 'unknown'}"`;
      } else if (regStatus === 'LAPSED' || regStatus === 'RETIRED' || regStatus === 'ANNULLED') {
        decision = 'fail';
        reason = `LEI registration status=${regStatus}`;
      } else {
        decision = 'indeterminate';
        reason = `LEI registration status=${regStatus ?? '(absent)'} — neither ISSUED nor a known failure value`;
      }
    }
  } catch (e) {
    // §7.5.1 error: transport failure / SR-3 fetch timeout / anchor failure — verification
    // could not complete, so the verifier never received an authority decision. This is
    // error, NOT indeterminate (and certainly never coerced to pass).
    decision = 'error';
    reason = `DAHR fetch + anchor failed: ${(e as Error).message}`;
  }

  const result: VerifyResult = {
    v: 'dacs-2-verify-result:0.1',
    jobId: args.jobId,
    claim: { scheme: 'lei', identifier: args.lei },
    recipe: args.recipeVersion,
    decision,
    reason,
    runAt,
    freshnessSec: 60 * 60 * 24,
    attestation,
    supplementarySignals: { entityName, registrationStatus: regStatus },
  };

  console.error(`pathos-dacs-vet-gleif — DACS-2 v0.2`);
  console.error(`  LEI: ${args.lei}`);
  console.error(`  decision: ${decision.toUpperCase()} — ${reason}`);
  if (entityName) console.error(`  entity: ${entityName}`);
  if (attestation) {
    console.error(`  attestation: ${attestation.type} @ ${attestation.anchor.locator}`);
    console.error(`  contentHash: ${attestation.contentHash}`);
  }
  console.error('');

  console.log(JSON.stringify(result, null, 2));
  // §7.5.1 exit codes: pass 0 · fail 1 · indeterminate 2 · error 4 (3 reserved for usage)
  process.exit(decision === 'pass' ? 0 : decision === 'fail' ? 1 : decision === 'indeterminate' ? 2 : 4);
}

main().catch((err) => {
  console.error(`pathos-dacs-vet-gleif: ${err.message}`);
  process.exit(3);
});
