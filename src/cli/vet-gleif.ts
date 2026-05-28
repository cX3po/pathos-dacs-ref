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
 *        decision = "pass" iff entity exists AND registration is ISSUED (active)
 *        decision = "fail" iff entity not found OR registration LAPSED/RETIRED
 *        decision = "indeterminate" iff network error / unparseable response (CM-4: MUST NOT coerce)
 *   4. Produce an AttestationRef (DAHR-attested response hash) — STUB in v0.1
 *      (Demos SDK DAHR proxy will wire in v0.2)
 *   5. Print the structured VerifyResult to stdout
 *
 * Initial scope is GLEIF only because it's the cleanest live public API the spec
 * maps (open, no key, deterministic). Future recipes compose the same way.
 */

import { parseArgs } from 'node:util';
import type { VerifyResult, VerifyDecision } from '../types/index.js';

const USAGE = `
pathos-dacs-vet-gleif — DACS-2 Vet via GLEIF consensus-backed-proxy

Usage:
  pathos-dacs-vet-gleif --lei <LEI> --jobId <uuid>

Options:
  --lei <LEI>      The ISO 17442 LEI to vet (20 hex characters)
  --jobId <uuid>   The job/session id (per §7.5.1 VerifyResult schema)
  --recipe-version <v>  Recipe version pin (default: "gleif-cbp:1")
  --help           Show this message

Exit codes:
  0 = pass    1 = fail    2 = indeterminate    3 = usage error

DACS spec sections: §7.3.5 (consensus-backed-proxy), §7.5.1 (VerifyResult), §7.5.2 (AttestationRef)
`;

interface CliArgs { lei: string; jobId: string; recipeVersion: string }

function parseCliArgs(): CliArgs {
  const { values } = parseArgs({
    options: {
      'lei': { type: 'string' },
      'jobId': { type: 'string' },
      'recipe-version': { type: 'string', default: 'gleif-cbp:1' },
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
  return { lei, jobId: values.jobId as string, recipeVersion: values['recipe-version'] as string };
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

async function fetchGleifLei(lei: string): Promise<{ ok: true; body: GleifLeiResponse } | { ok: false; error: string }> {
  const url = `https://api.gleif.org/api/v1/lei-records/${lei}`;
  try {
    const res = await fetch(url, { headers: { Accept: 'application/vnd.api+json' } });
    if (res.status === 404) {
      const body = await res.json().catch(() => ({})) as GleifLeiResponse;
      return { ok: true, body };
    }
    if (!res.ok) {
      return { ok: false, error: `GLEIF HTTP ${res.status}` };
    }
    const body = await res.json() as GleifLeiResponse;
    return { ok: true, body };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function main(): Promise<void> {
  const args = parseCliArgs();
  const runAt = new Date().toISOString();

  let decision: VerifyDecision;
  let reason: string;
  let entityName: string | undefined;
  let regStatus: string | undefined;

  const fetched = await fetchGleifLei(args.lei);
  if (!fetched.ok) {
    // §7.5.1 — CM-4: network error MUST NOT coerce to pass; map to indeterminate
    decision = 'indeterminate';
    reason = `GLEIF fetch failed: ${fetched.error}`;
  } else if (fetched.body.errors && fetched.body.errors.length > 0) {
    decision = 'fail';
    reason = `LEI not found at GLEIF: ${fetched.body.errors[0]?.detail ?? 'no detail'}`;
  } else if (!fetched.body.data) {
    decision = 'indeterminate';
    reason = 'GLEIF response had neither data nor errors — unparseable';
  } else {
    entityName = fetched.body.data.attributes?.entity?.legalName?.name;
    regStatus = fetched.body.data.attributes?.registration?.status;
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

  const result: VerifyResult = {
    v: 'dacs-2-verify-result:0.1',
    jobId: args.jobId,
    claim: { scheme: 'lei', identifier: args.lei },
    recipe: args.recipeVersion,
    decision,
    reason,
    runAt,
    freshnessSec: 60 * 60 * 24, // 24 h — same cadence GLEIF refreshes
    // attestation: STUB — v0.2 will DAHR-anchor the GLEIF response on Demos
    supplementarySignals: { entityName, registrationStatus: regStatus },
  };

  console.error(`pathos-dacs-vet-gleif — DACS-2 v0.1 (scaffold)`);
  console.error(`  LEI: ${args.lei}`);
  console.error(`  decision: ${decision.toUpperCase()} — ${reason}`);
  if (entityName) console.error(`  entity: ${entityName}`);
  console.error('');

  console.log(JSON.stringify(result, null, 2));
  process.exit(decision === 'pass' ? 0 : decision === 'fail' ? 1 : 2);
}

main().catch((err) => {
  console.error(`pathos-dacs-vet-gleif: ${err.message}`);
  process.exit(3);
});
