#!/usr/bin/env tsx
/**
 * DACS-1 Listing publisher CLI
 *
 * Spec source: DACS-1 v0.1 §6.3.4 (Listing), §6.3.2 (IdentityBundle presentation), §6.3.4(c) (discovery).
 *
 * What this tool does:
 *   1. Read a signed DACS-1 Listing JSON (dacsVersion "1") from disk; signing happens elsewhere
 *      (listing-wire's signDacs1Listing, or the producer-listing helper the demo producers use)
 *   2. Check the §6.3.4 members, the pipeline's PhaseStep kinds, the on-record CF-4 logical address
 *      (§6.3.4(b): derived from seller claim, listingId, listingVersion) and the LR-2 16 KiB cap on the
 *      complete signed record, as the pinned dacs-sdk's isListing does; then verify the record the way a
 *      counterparty would (verifyBundleListing: signature over the signature-excluded JCS hash, the
 *      presented seller identity bundle, presenter = signer; the signer is the seller's agent DID)
 *   3. Name the storage program in the pinned dacs-sdk's form (the logical address with each ':'
 *      percent-encoded) so that SDK's Agent resolves the listing by (owner, name)
 *   4. JCS-canonicalise the complete signed record (the bytes that are anchored)
 *   5. --dry-run stops here and prints the coordinates
 *   6. Anchor the complete signed record via Demos SR-2 and emit the §6.3.4(c) discovery artifacts
 *
 * The v0.1 pre-DACS-1 listing body (`v: "dacs-1-listing:0.1"`, `id`/`version`, `capability`) is no longer accepted.
 */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import { emitDiscoveryArtifacts, listingContentHash } from '../dacs1/discovery.js';
import { connectDemos, mnemonicFromEnv, anchor } from '../demos/index.js';
import { jcsCanonical } from '../jcs.js';
import { sdkListingProgramName } from '../live/listing-wire.js';
import { agentDidSignatureVerifier, assertDacs1Listing, DACS1_LISTING_SIZE_CAP_BYTES } from '../live/producer-listing.js';

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

Exits non-zero on a member, pipeline, logical-address or size-cap failure, or a signature or identity presentation that does not verify.
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
  listingId: string;
  listingVersion: number;
  logical_address: string;
  seller: { identity: { presentedBy: string }; displayName: string };
  signature: { algorithm: 'ed25519'; signer: string; value: string };
};

async function main(): Promise<void> {
  const args = parseCliArgs();

  // 1-2. Load; check the members, the pipeline kinds, the on-record logical address and the LR-2 cap on the complete
  // signed record the way the pinned dacs-sdk's isListing does; then verify as a counterparty would.
  const raw = readFileSync(args.listingFile, 'utf-8');
  const listingObj: unknown = JSON.parse(raw);
  assertDacs1Listing(listingObj);
  const listing = listingObj as Dacs1Listing;
  await verifyBundleListing(listing, { verifySignature: agentDidSignatureVerifier as never });
  const sellerClaim = listing.seller.identity.presentedBy;

  // 3. Coordinates: the logical address the record carries (already checked against the tuple); the program name is the pinned dacs-sdk's form.
  const logicalAddress = listing.logical_address;
  const storageProgramName = sdkListingProgramName(logicalAddress);
  console.error(`✓ Loaded DACS-1 listing: listingId=${listing.listingId}, listingVersion=${listing.listingVersion}, seller=${sellerClaim}`);
  console.error(`✓ Members, pipeline kinds and on-record logical address checked; signature and identity presentation verified under the seller's agent DID`);
  console.error(`✓ Logical address (CF-4, on record): ${logicalAddress}`);
  console.error(`✓ Storage program name (pinned dacs-sdk form, colon-free): ${storageProgramName}`);

  // 4. Size: the complete canonical signed record is what LR-2 caps (assertDacs1Listing refused anything over it).
  const canonical = jcsCanonical(listing);
  console.error(`✓ JCS canonical signed record: ${canonical.length} bytes (cap ${DACS1_LISTING_SIZE_CAP_BYTES})`);
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
