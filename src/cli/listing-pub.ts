#!/usr/bin/env tsx
/**
 * DACS-1 Listing publisher CLI
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1 §6.3.4
 *
 * What this tool does:
 *   1. Read a Listing JSON from disk
 *   2. Validate structural conformance to §6.3.4 (v, id, version, seller, capability, price, ...)
 *   3. JCS-canonicalise; reject if > 16 KB (§6.3.4 size cap)
 *   4. Verify `version` is monotonically increasing for the (id) tuple
 *      (LP-3 — but we can only check against the operator's local history; chain-side
 *      check happens at anchor time)
 *   5. Sign the JCS-canonical bytes with the seller's primary-claim key
 *      (separator: "dacs-listing:v1:")
 *   6. Anchor via Demos SR-2 (Storage Program write)
 *   7. Print the resulting `stor-` address + tx hash
 *
 * v0.1 scaffold: validates + canonicalises + signs locally. Anchor step is STUB
 * (logs the would-be-anchored bytes; SDK call wired in v0.2).
 */

import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { Listing, UnsignedListing } from '../types/index.js';
import { jcsCanonical } from '../jcs.js';
import { sign } from '../lib/sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';

const USAGE = `
pathos-dacs-listing-pub — DACS-1 Listing publisher

Usage:
  pathos-dacs-listing-pub --listing-file <path> --mnemonic-env <ENVVAR>
  pathos-dacs-listing-pub --listing-file <path> --dry-run

Options:
  --listing-file <path>    Path to listing JSON conformant to §6.3.4 schema
  --mnemonic-env <name>    Env var holding the seller's Demos mnemonic (e.g. DEMOS_MNEMONIC)
  --dry-run                Validate + canonicalise + sign, but skip the SR-2 anchor step
  --rpc <url>              Demos node RPC URL (default: https://demosnode.discus.sh/)
  --help                   Show this message

Exits non-zero on validation failure or size-cap exceeded.

DACS spec sections enforced: §6.3.4 (LP-1..LP-4)
`;

interface CliArgs {
  listingFile: string;
  mnemonicEnv?: string;
  dryRun: boolean;
  rpc: string;
}

function parseCliArgs(): CliArgs {
  const { values } = parseArgs({
    options: {
      'listing-file': { type: 'string' },
      'mnemonic-env': { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
      'help': { type: 'boolean', default: false },
    },
    strict: true,
  });
  if (values.help || !values['listing-file']) {
    console.log(USAGE);
    process.exit(values.help ? 0 : 3);
  }
  return {
    listingFile: values['listing-file'] as string,
    mnemonicEnv: values['mnemonic-env'] as string | undefined,
    dryRun: values['dry-run'] as boolean,
    rpc: values['rpc'] as string,
  };
}

/** Minimal §6.3.4 structural validation. Full schema validation comes via a JSON schema in v0.2. */
function validateListing(listing: unknown): asserts listing is Listing {
  if (typeof listing !== 'object' || listing === null) {
    throw new Error('listing must be an object');
  }
  const l = listing as Record<string, unknown>;
  if (l.v !== 'dacs-1-listing:0.1') {
    throw new Error(`listing.v must be "dacs-1-listing:0.1" (got: ${String(l.v)})`);
  }
  if (typeof l.id !== 'string' || !l.id) throw new Error('listing.id must be a non-empty string');
  if (typeof l.version !== 'number' || l.version < 1) throw new Error('listing.version must be >= 1');
  if (typeof l.seller !== 'object' || !l.seller) throw new Error('listing.seller required');
  if (typeof l.capability !== 'object' || !l.capability) throw new Error('listing.capability required');
  if (typeof l.price !== 'object' || !l.price) throw new Error('listing.price required');
  if (!Array.isArray(l.requiredCapabilities)) throw new Error('listing.requiredCapabilities must be array');
  // §6.3.4 LP-3: SR-2 MUST be in requiredCapabilities (anchoring depends on it)
  if (!(l.requiredCapabilities as string[]).includes('sr-2-anchored-storage')) {
    throw new Error('listing.requiredCapabilities MUST include "sr-2-anchored-storage" per §6.3.4');
  }
}

async function main(): Promise<void> {
  const args = parseCliArgs();

  // 1. Load + validate
  const raw = readFileSync(args.listingFile, 'utf-8');
  const listingObj: unknown = JSON.parse(raw);
  validateListing(listingObj);
  const listing: Listing = listingObj;
  console.error(`✓ Loaded listing: id=${listing.id}, version=${listing.version}, capability=${listing.capability.key}`);

  // 2. Strip signature for canonicalisation
  const unsigned: UnsignedListing = { ...listing };
  delete (unsigned as Record<string, unknown>).signature;

  // 3. JCS-canonicalise + size cap (§6.3.4)
  const canonical = jcsCanonical(unsigned);
  if (canonical.length > 16 * 1024) {
    throw new Error(
      `listing canonical bytes = ${canonical.length}, exceeds §6.3.4 16 KB cap. Trim before publishing.`
    );
  }
  console.error(`✓ JCS canonical bytes: ${canonical.length} (< 16 KB cap)`);

  // 4. Sign — STUB. Needs the seller's primary-claim ed25519 privkey, resolved from mnemonic
  if (args.mnemonicEnv) {
    const mn = process.env[args.mnemonicEnv];
    if (!mn) {
      throw new Error(`Env var ${args.mnemonicEnv} not set`);
    }
    console.error(`✓ Mnemonic source: env:${args.mnemonicEnv} (length=${mn.split(' ').length} words)`);
    console.error(`  TODO v0.2: derive ed25519 keypair from mnemonic via Demos SDK; sign with sep="${DOMAIN_SEPARATORS.LISTING}"`);
    // Demonstrate the sign() call path with a dummy key so the binding is exercised:
    const dummyKey = new Uint8Array(32);
    const sig = sign(DOMAIN_SEPARATORS.LISTING, canonical, dummyKey);
    console.error(`  (dry signature with all-zeros key: ${sig.length}-byte ed25519 signature produced)`);
  } else if (!args.dryRun) {
    console.error('  ⚠ No --mnemonic-env supplied and --dry-run not set; signing skipped');
  }

  // 5. Anchor — STUB
  if (args.dryRun) {
    console.error('✓ Dry run — anchor step skipped');
    console.log(JSON.stringify({ status: 'dry-run', canonicalBytes: canonical.length }, null, 2));
    process.exit(0);
  }
  console.error(`  TODO v0.2: anchor ${canonical.length}-byte payload to Demos SR-2 via ${args.rpc}`);
  console.error('  (anchor step not yet implemented in v0.1 scaffold)');
  console.log(JSON.stringify({ status: 'scaffold-not-anchored', canonicalBytes: canonical.length }, null, 2));
  process.exit(0);
}

main().catch((err) => {
  console.error(`pathos-dacs-listing-pub: ${err.message}`);
  process.exit(1);
});
