#!/usr/bin/env tsx
/**
 * DACS-1 Listing publisher CLI
 *
 * Spec source: DACS-1 v0.1 §6.3.4 (Listing), §6.3.2 (IdentityBundle presentation), §6.3.4(c) (discovery).
 *
 * What this tool does:
 *   1. Read a signed DACS-1 Listing JSON (dacsVersion "1") from disk; signing happens elsewhere
 *      (listing-wire's signDacs1Listing, or the producer-listing helper the demo producers use)
 *   2. Validate the §6.3.4 members, then verify the record the way a counterparty would
 *      (verifyBundleListing: signature over the signature-excluded JCS hash, the presented seller
 *      identity bundle, presenter = signer; the signer is the seller's self-certifying agent DID)
 *   3. Derive the CF-4 logical address from (seller claim, listingId, listingVersion) and the storage
 *      program name in the pinned dacs-sdk's form (the logical address with each ':' percent-encoded),
 *      so that SDK's Agent resolves the listing by (owner, name)
 *   4. JCS-canonicalise; reject a signed scope over 16 KB (§6.3.4 size cap)
 *   5. --dry-run stops here and prints the coordinates
 *   6. Anchor the complete signed record via Demos SR-2 and emit the §6.3.4(c) discovery artifacts
 *
 * The v0.1 pre-DACS-1 listing body (`v: "dacs-1-listing:0.1"`, `id`/`version`, `capability`) is no longer accepted.
 */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { listingLogicalAddress } from '../dacs1/addressing.js';
import { emitDiscoveryArtifacts, listingContentHash } from '../dacs1/discovery.js';
import { connectDemos, mnemonicFromEnv, anchor } from '../demos/index.js';
import { jcsCanonical } from '../jcs.js';
import { sdkListingProgramName } from '../live/listing-wire.js';
import { agentDidSignatureVerifier } from '../live/producer-listing.js';

const USAGE = `
pathos-dacs-listing-pub — DACS-1 Listing publisher

Usage:
  pathos-dacs-listing-pub --listing-file <path> --mnemonic-env <ENVVAR> --publisher-origin <https://origin>
  pathos-dacs-listing-pub --listing-file <path> --dry-run

Options:
  --listing-file <path>    Path to a signed DACS-1 §6.3.4 Listing JSON (dacsVersion "1")
  --mnemonic-env <name>    Env var holding the deployer wallet's Demos mnemonic (e.g. DEMOS_MNEMONIC); never a CLI value
  --dry-run                Validate, verify and derive the coordinates; skip the SR-2 anchor/discovery write
  --rpc <url>              Demos node RPC URL (default: https://demosnode.discus.sh/)
  --publisher-origin <url> HTTPS origin that will host the emitted discovery artifacts (or DACS_PUBLISHER_ORIGIN)
  --discovery-dir <path>   Artifact output root (default: discovery)
  --help                   Show this message

Exits non-zero on validation failure, a signature or identity presentation that does not verify, or size-cap exceeded.
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
    console.error(USAGE);
    process.exit(values.help ? 0 : 1);
  }
  return {
    listingFile: values['listing-file'] as string,
    mnemonicEnv: values['mnemonic-env'] as string | undefined,
    dryRun: values['dry-run'] as boolean,
    rpc: values.rpc as string,
    publisherOrigin: (values['publisher-origin'] as string | undefined) ?? process.env.DACS_PUBLISHER_ORIGIN,
    discoveryDir: values['discovery-dir'] as string,
  };
}

type Dacs1Listing = Record<string, unknown> & {
  dacsVersion: '1';
  listingId: string;
  listingVersion: number;
  seller: { identity: { presentedBy: string }; displayName: string };
  signature: { algorithm: 'ed25519'; signer: string; value: string };
};

const REQUIRED_MEMBERS = ['dacsVersion', 'listingVersion', 'listingId', 'seller', 'offering', 'buyerRequirement', 'pipeline', 'pricing', 'acceptedRails', 'terms', 'validity', 'signature'] as const;

/** The DACS-1 §6.3.4 members this publisher reads; the signature and the identity presentation are verified afterwards. */
function validateDacs1Listing(listing: unknown): asserts listing is Dacs1Listing {
  if (typeof listing !== 'object' || listing === null || Array.isArray(listing)) throw new Error('listing must be an object');
  const l = listing as Record<string, unknown>;
  if (l.dacsVersion !== '1') throw new Error(`listing.dacsVersion must be "1" (a DACS-1 §6.3.4 Listing; got: ${String(l.dacsVersion)})`);
  for (const member of REQUIRED_MEMBERS) if (l[member] === undefined) throw new Error(`listing.${member} required (§6.3.4)`);
  if (typeof l.listingId !== 'string' || !l.listingId) throw new Error('listing.listingId must be a non-empty string');
  if (!Number.isSafeInteger(l.listingVersion) || (l.listingVersion as number) < 1) throw new Error('listing.listingVersion must be an integer >= 1');
  const seller = l.seller as Record<string, unknown> | null;
  if (typeof seller !== 'object' || seller === null) throw new Error('listing.seller required');
  const identity = seller.identity as Record<string, unknown> | null | undefined;
  if (typeof identity !== 'object' || identity === null || typeof identity.presentedBy !== 'string') {
    throw new Error('listing.seller.identity must be an IdentityBundle presented by the seller claim (§6.3.2)');
  }
  if (typeof seller.displayName !== 'string') throw new Error('listing.seller.displayName required');
  if (!Array.isArray(l.pipeline) || l.pipeline.length === 0) throw new Error('listing.pipeline must be a non-empty PhaseStep array');
  if (!Array.isArray(l.acceptedRails)) throw new Error('listing.acceptedRails must be an array');
  const signature = l.signature as Record<string, unknown> | null;
  if (typeof signature !== 'object' || signature === null || signature.algorithm !== 'ed25519' || typeof signature.signer !== 'string' || typeof signature.value !== 'string') {
    throw new Error('listing.signature must be { algorithm: "ed25519", signer, value } (§6.3.4)');
  }
  if (signature.signer !== identity.presentedBy) throw new Error('listing signer must be the claim the seller identity bundle presents (§6.3.4)');
}

async function main(): Promise<void> {
  const args = parseCliArgs();

  // 1-2. Load, validate the members, verify as a counterparty would.
  const raw = readFileSync(args.listingFile, 'utf-8');
  const listingObj: unknown = JSON.parse(raw);
  validateDacs1Listing(listingObj);
  const listing = listingObj;
  await verifyBundleListing(listing, { verifySignature: agentDidSignatureVerifier as never });
  const sellerClaim = listing.seller.identity.presentedBy;

  // 3. Coordinates.
  const logicalAddress = listingLogicalAddress(sellerClaim, listing.listingId, listing.listingVersion);
  if (listing.logical_address !== undefined && listing.logical_address !== logicalAddress) {
    throw new Error(`listing.logical_address mismatch: expected ${logicalAddress}`);
  }
  const storageProgramName = sdkListingProgramName(logicalAddress);
  console.error(`✓ Loaded DACS-1 listing: listingId=${listing.listingId}, listingVersion=${listing.listingVersion}, seller=${sellerClaim}`);
  console.error(`✓ Signature and identity presentation verified under the seller's agent DID`);
  console.error(`✓ Logical address (CF-4): ${logicalAddress}`);
  console.error(`✓ Storage program name (pinned dacs-sdk form, colon-free): ${storageProgramName}`);

  // 4. Size cap over the signature-omitted canonical form (§6.3.4).
  const { signature: _signature, ...unsigned } = listing;
  void _signature;
  const canonical = jcsCanonical(unsigned);
  if (canonical.length > 16 * 1024) {
    throw new Error(`listing canonical bytes = ${canonical.length}, exceeds §6.3.4 16 KB cap. Trim before publishing.`);
  }
  console.error(`✓ JCS canonical bytes: ${canonical.length} (< 16 KB cap)`);
  const contentHash = listingContentHash(listing);

  // 5. Dry run stops here.
  if (args.dryRun) {
    console.error('✓ Dry run — Demos connection + anchor step skipped');
    console.log(JSON.stringify({
      status: 'dry-run',
      listingId: listing.listingId,
      listingVersion: listing.listingVersion,
      sellerClaim,
      canonicalBytes: canonical.length,
      logical_address: logicalAddress,
      storageProgramName,
      contentHash,
      signatureVerified: true,
    }, null, 2));
    process.exit(0);
  }

  // 6. Anchor via Demos SR-2; refuse without a hostable discovery origin (§6.3.4(c) needs the native locator).
  if (!args.mnemonicEnv) {
    console.error('Error: --mnemonic-env required (or use --dry-run)');
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
  console.error(`  Wallet address: ${handle.address}`);

  // The deployer address is a native-address write input; the seller is the claim the listing presents.
  const anchoredBytes = jcsCanonical(listing);
  console.error(`  Anchoring ${anchoredBytes.length} bytes to SR-2...`);
  const result = await anchor(handle, storageProgramName, new TextDecoder().decode(anchoredBytes), { acl: 'public' });

  const discoveryFiles = emitDiscoveryArtifacts({
    listing,
    sellerPrimaryClaim: sellerClaim,
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
    listingId: listing.listingId,
    listingVersion: listing.listingVersion,
    sellerClaim,
    canonicalBytes: canonical.length,
    logical_address: logicalAddress,
    storageProgramName,
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
