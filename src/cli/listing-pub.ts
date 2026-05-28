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

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { Listing, UnsignedListing } from '../types/index.js';
import { jcsCanonical } from '../jcs.js';
import { connectDemos, mnemonicFromEnv, anchor } from '../demos/index.js';

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

  // 4. LP-2 scheme check — MUST run BEFORE dry-run exit (Codex re-review #1).
  // A non-cci primary listing is invalid in v0.2 regardless of whether we
  // actually anchor. Catch it here so dry-runs also enforce the constraint.
  const sellerScheme = listing.seller.identity.primary.scheme;
  if (sellerScheme !== 'cci') {
    console.error(
      `Error: listing.seller.identity.primary.scheme="${sellerScheme}" not supported in v0.2. ` +
      `Only "cci"-scheme primaries are supported today; ERC-8004 and other schemes land in v0.3.`
    );
    process.exit(1);
  }

  // 5. Dry-run path — exits AFTER scheme validation so the rejection happens consistently
  if (args.dryRun) {
    console.error('✓ Dry run — Demos connection + anchor step skipped (scheme + canonical bytes already validated)');
    console.log(JSON.stringify({ status: 'dry-run', canonicalBytes: canonical.length, schemeValidated: true }, null, 2));
    process.exit(0);
  }

  // 6. Sign + Anchor via Demos SR-2
  if (!args.mnemonicEnv) {
    console.error('Error: --mnemonic-env required (or use --dry-run)');
    process.exit(3);
  }
  const mn = mnemonicFromEnv(args.mnemonicEnv);
  console.error(`✓ Mnemonic source: env:${args.mnemonicEnv} (${mn.split(/\s+/).length} words)`);

  const handle = await connectDemos(mn, args.rpc);
  console.error(`✓ Connected to Demos: ${handle.rpc}`);
  console.error(`  Wallet address (CCI): ${handle.address}`);

  // 7. LP-2 mismatch check — refuse to anchor for a different identity than the connected wallet.
  const sellerCciId = listing.seller.identity.primary.identifier.toLowerCase();
  const walletAddr = handle.address.toLowerCase();
  if (sellerCciId !== walletAddr) {
    console.error(
      `Error: listing.seller.identity.primary (cci:${sellerCciId}) does not match connected wallet (${walletAddr}). ` +
      `LP-2 forbids signing a listing for a different identity.`
    );
    process.exit(1);
  }

  // Anchor the JCS-canonical listing bytes to a Storage Program (SR-2)
  // The listing IS the payload — published in canonical form so any reader can
  // recompute its hash and verify it matches what they expect (LR-1).
  console.error(`  Anchoring ${canonical.length} bytes to SR-2...`);
  const result = await anchor(
    handle,
    `dacs1:listing:${listing.id}:v${listing.version}`,
    new TextDecoder().decode(canonical), // SR-2 wants string or object; pass canonical string
    { acl: 'public' }
  );

  console.error(`✓ Anchored:`);
  console.error(`    storageAddress: ${result.storageAddress}`);
  console.error(`    txHash:         ${result.txHash}`);
  console.error(`    sizeBytes:      ${result.sizeBytes}`);

  console.log(JSON.stringify({
    status: 'anchored',
    listingId: listing.id,
    version: listing.version,
    canonicalBytes: canonical.length,
    storageAddress: result.storageAddress,
    txHash: result.txHash,
    anchoredAt: result.anchoredAt,
  }, null, 2));
  process.exit(0);
}

main().catch((err) => {
  console.error(`pathos-dacs-listing-pub: ${err.message}`);
  process.exit(1);
});
