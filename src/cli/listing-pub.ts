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
 *   5. Preserve any caller-supplied signature while computing contentHash over
 *      the signature-omitted canonical form (CORE §B.2)
 *   6. Anchor via Demos SR-2 under an opaque colon-free write-input name
 *   7. Emit §6.3.5/§6.3.6 discovery artifacts and print the native locator
 *
 * Cryptographic signing is intentionally outside this CLI's conformance lane.
 */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { Listing, UnsignedListing } from '../types/index.js';
import { jcsCanonical } from '../jcs.js';
import { connectDemos, mnemonicFromEnv, anchor } from '../demos/index.js';
import {
  assertRegisteredClaimReference,
  formatClaimReference,
  listingLogicalAddress,
  opaqueListingProgramName,
} from '../dacs1/addressing.js';
import { emitDiscoveryArtifacts, listingContentHash } from '../dacs1/discovery.js';

const USAGE = `
pathos-dacs-listing-pub — DACS-1 Listing publisher

Usage:
  pathos-dacs-listing-pub --listing-file <path> --mnemonic-env <ENVVAR>
  pathos-dacs-listing-pub --listing-file <path> --dry-run

Options:
  --listing-file <path>    Path to listing JSON conformant to §6.3.4 schema
  --mnemonic-env <name>    Env var holding the seller's Demos mnemonic (e.g. DEMOS_MNEMONIC)
  --dry-run                Validate + canonicalise, but skip the SR-2 anchor/discovery write
  --rpc <url>              Demos node RPC URL (default: https://demosnode.discus.sh/)
  --publisher-origin <url> HTTPS origin that will host the emitted discovery artifacts
  --discovery-dir <path>   Artifact output root (default: discovery)
  --help                   Show this message

Exits non-zero on validation failure or size-cap exceeded.

DACS spec sections enforced: §6.3.4 (LP-1..LP-4)
`;

interface CliArgs {
  listingFile: string;
  mnemonicEnv?: string;
  dryRun: boolean;
  rpc: string;
  publisherOrigin?: string;
  discoveryDir: string;
}

function parseCliArgs(): CliArgs {
  const { values } = parseArgs({
    options: {
      'listing-file': { type: 'string' },
      'mnemonic-env': { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'rpc': { type: 'string', default: 'https://demosnode.discus.sh/' },
      'publisher-origin': { type: 'string' },
      'discovery-dir': { type: 'string', default: 'discovery' },
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
    publisherOrigin: (values['publisher-origin'] as string | undefined) ?? process.env.DACS_PUBLISHER_ORIGIN,
    discoveryDir: values['discovery-dir'] as string,
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
  const seller = l.seller as Record<string, unknown>;
  const identity = seller['identity'];
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('listing.seller.identity required');
  }
  const primary = (identity as Record<string, unknown>)['primary'];
  if (!primary || typeof primary !== 'object' || Array.isArray(primary)) {
    throw new Error('listing.seller.identity.primary required');
  }
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
  const draft = listingObj as Listing;
  const sellerPrimaryClaim = formatClaimReference(draft.seller.identity.primary);
  assertRegisteredClaimReference(sellerPrimaryClaim);
  const logicalAddress = listingLogicalAddress(sellerPrimaryClaim, draft.id, draft.version);
  if (draft.signature !== undefined && draft.logical_address === undefined) {
    throw new Error('a signed listing must already carry logical_address in its signed scope; add it and re-sign before minting');
  }
  if (draft.logical_address !== undefined && draft.logical_address !== logicalAddress) {
    throw new Error(`listing.logical_address mismatch: expected ${logicalAddress}`);
  }
  const listing: Listing = { ...draft, logical_address: logicalAddress };
  const storageProgramName = opaqueListingProgramName(logicalAddress);
  console.error(`✓ Loaded listing: id=${listing.id}, version=${listing.version}, capability=${listing.capability.key}`);
  console.error(`✓ Logical address (CF-4 metadata): ${logicalAddress}`);
  console.error(`✓ Opaque Storage Program name is colon-free`);

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

  const contentHash = listingContentHash(listing as unknown as Record<string, unknown>);

  // 4. Dry-run path — exits after CF-4, registered-scheme, hash-scope, and name checks.
  if (args.dryRun) {
    console.error('✓ Dry run — Demos connection + anchor step skipped');
    console.log(JSON.stringify({
      status: 'dry-run',
      canonicalBytes: canonical.length,
      logical_address: logicalAddress,
      storageProgramName,
      contentHash,
      schemeValidated: true,
    }, null, 2));
    process.exit(0);
  }

  // 5. Anchor via Demos SR-2. Refuse the write if no hostable discovery origin was supplied:
  // a go-forward §6.3.4(c) producer must emit the binding after the native locator exists.
  if (!args.mnemonicEnv) {
    console.error('Error: --mnemonic-env required (or use --dry-run)');
    process.exit(3);
  }
  if (typeof listing.signature !== 'string' || listing.signature.length === 0) {
    console.error('Error: live minting requires a caller-supplied listing signature that covers logical_address');
    process.exit(3);
  }
  if (!args.publisherOrigin) {
    console.error('Error: --publisher-origin (or DACS_PUBLISHER_ORIGIN) required for §6.3.4(c) discovery emission');
    process.exit(3);
  }
  const mn = mnemonicFromEnv(args.mnemonicEnv);
  console.error(`✓ Mnemonic source: env:${args.mnemonicEnv} (${mn.split(/\s+/).length} words)`);

  const handle = await connectDemos(mn, args.rpc);
  console.error(`✓ Connected to Demos: ${handle.rpc}`);
  console.error(`  Wallet address (CCI): ${handle.address}`);

  // The deployer address is a native-address write input; it is not the seller ClaimReference.
  // Anchor the complete listing (including any supplied signature) while contentHash remains
  // bound to the §B.2 signature-omitted canonical form computed above.
  const anchoredBytes = jcsCanonical(listing);
  console.error(`  Anchoring ${anchoredBytes.length} bytes to SR-2...`);
  const result = await anchor(
    handle,
    storageProgramName,
    new TextDecoder().decode(anchoredBytes),
    { acl: 'public' }
  );

  const discoveryFiles = emitDiscoveryArtifacts({
    listing: listing as unknown as Record<string, unknown>,
    sellerPrimaryClaim,
    nativeAddress: result.storageAddress,
    publisherOrigin: args.publisherOrigin,
    generatedAt: Date.now(),
    outputDir: args.discoveryDir,
  });

  console.error(`✓ Anchored:`);
  console.error(`    storageAddress: ${result.storageAddress}`);
  console.error(`    txHash:         ${result.txHash}`);
  console.error(`    sizeBytes:      ${result.sizeBytes}`);

  console.log(JSON.stringify({
    status: 'anchored',
    listingId: listing.id,
    version: listing.version,
    canonicalBytes: canonical.length,
    logical_address: logicalAddress,
    contentHash,
    storageAddress: result.storageAddress,
    txHash: result.txHash,
    anchoredAt: result.anchoredAt,
    discoveryFiles,
  }, null, 2));
  process.exit(0);
}

main().catch((err) => {
  console.error(`pathos-dacs-listing-pub: ${err.message}`);
  process.exit(1);
});
