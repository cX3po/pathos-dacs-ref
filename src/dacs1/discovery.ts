import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { jcsCanonical, jcsHashHex } from '../jcs.js';
import {
  bytesSha256Hex,
  listingLogicalAddress,
  parseListingLogicalAddress,
} from './addressing.js';

export interface ListingIndexEntry {
  listingId: string;
  version: number;
  contentHash: string;
  anchor: { kind: string; locator: string };
  summary: { title: string; category: string; tags: string[]; priceHint?: string };
  status: 'active' | 'revoked';
  /** Additive explicit form of the §6.3.4(c) binding; derivable from seller/id/version. */
  logical_address: string;
  /** Honest carriage status for immutable pre-§6.3.4(b) records. */
  logicalAddressMetadata: 'anchored' | 'legacy-absent';
}

export interface ListingIndex {
  indexVersion: '1';
  generatedAt: number;
  seller: string;
  listings: ListingIndexEntry[];
}

export interface ListingSummary {
  listingId: string;
  version: number;
  contentHash: string;
  anchor: { kind: string; locator: string };
  seller: { primaryClaim: string; displayName: string };
  offering: { title: string; category: string; tags: string[] };
  pricing: { priceHint?: string; currency?: string };
  status: 'active' | 'revoked';
  catalogObservedAt: number;
  logical_address: string;
}

export interface DiscoveryArtifacts {
  agentCard: Record<string, unknown>;
  agentCardBytes: Uint8Array;
  index: ListingIndex;
  indexBytes: Uint8Array;
  indexHash: string;
  catalog: { listings: ListingSummary[]; total: number };
  catalogBytes: Uint8Array;
  listingBytes: Uint8Array;
}

export interface BuildDiscoveryInput {
  listing: Record<string, unknown>;
  sellerPrimaryClaim: string;
  nativeAddress: string;
  publisherOrigin: string;
  generatedAt: number;
  status?: 'active' | 'revoked';
  /** Publish a binding for an immutable older record that cannot be retrofitted in-place. */
  legacyRecordWithoutLogicalMetadata?: boolean;
}

export interface EmitDiscoveryInput extends BuildDiscoveryInput {
  outputDir: string;
}

export interface DiscoveryFileSet {
  agentCard: string;
  listingIndex: string;
  catalog: string;
  listing: string;
}

export interface PublishedResourceFetcher {
  (url: string): Promise<Uint8Array>;
}

export interface NativeListingFetcher {
  (nativeAddress: string): Promise<{ data: unknown; storageAddress?: string } | null>;
}

export interface ResolvedPublishedListing {
  listing: Record<string, unknown>;
  logicalAddress: string;
  nativeAddress: string;
  contentHash: string;
  indexUrl: string;
  logicalAddressMetadata: 'anchored' | 'legacy-absent';
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function listingCoordinates(listing: Record<string, unknown>): { listingId: string; version: number } {
  const listingId = listing['listingId'] ?? listing['id'];
  const version = listing['listingVersion'] ?? listing['version'];
  if (typeof listingId !== 'string' || !Number.isSafeInteger(version) || Number(version) < 1) {
    throw new Error('listing must carry listingId/id and listingVersion/version');
  }
  return { listingId, version: Number(version) };
}

function listingPresentation(listing: Record<string, unknown>): {
  title: string;
  category: string;
  tags: string[];
  displayName: string;
  priceHint?: string;
  currency?: string;
} {
  const offering = record(listing['offering'] ?? {}, 'listing.offering');
  const capability = record(listing['capability'] ?? {}, 'listing.capability');
  const seller = record(listing['seller'] ?? {}, 'listing.seller');
  const price = record(listing['pricing'] ?? listing['price'] ?? {}, 'listing.price');
  const title = String(offering['title'] ?? capability['key'] ?? listing['item'] ?? 'DACS listing');
  const category = String(offering['category'] ?? capability['key'] ?? 'service.general');
  const rawTags = offering['tags'];
  const tags = Array.isArray(rawTags) ? rawTags.filter((v): v is string => typeof v === 'string') : [];
  const displayName = String(seller['displayName'] ?? 'DACS seller');
  const priceHint = typeof price['amount'] === 'string' ? price['amount'] : undefined;
  const currency = typeof price['currency'] === 'string' ? price['currency'] : undefined;
  return { title, category, tags, displayName, ...(priceHint ? { priceHint } : {}), ...(currency ? { currency } : {}) };
}

/** CORE §B.2: listing contentHash is over JCS with the top-level signature omitted. */
export function listingContentHash(listing: Record<string, unknown>): string {
  const unsigned = { ...listing };
  delete unsigned['signature'];
  return jcsHashHex(unsigned);
}

function parseJson(bytes: Uint8Array, label: string): Record<string, unknown> {
  try {
    return record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), label);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON: ${(error as Error).message}`);
  }
}

function normalizedOrigin(origin: string): string {
  const url = new URL(origin);
  if (url.protocol !== 'https:') throw new Error('publisherOrigin must use HTTPS');
  return url.origin;
}

export function buildDiscoveryArtifacts(input: BuildDiscoveryInput): DiscoveryArtifacts {
  const origin = normalizedOrigin(input.publisherOrigin);
  const { listingId, version } = listingCoordinates(input.listing);
  const expectedLogical = listingLogicalAddress(input.sellerPrimaryClaim, listingId, version);
  const legacyAbsent = input.legacyRecordWithoutLogicalMetadata === true
    && input.listing['logical_address'] === undefined;
  if (!legacyAbsent && input.listing['logical_address'] !== expectedLogical) {
    throw new Error('listing.logical_address does not match its seller/listingId/version tuple');
  }
  if (!/^stor-[0-9a-f]{40}$/.test(input.nativeAddress)) {
    throw new Error('nativeAddress must be a Demos stor- address with 40 lowercase hex characters');
  }
  if (!Number.isSafeInteger(input.generatedAt) || input.generatedAt < 0) {
    throw new Error('generatedAt must be a non-negative unix-millisecond safe integer');
  }

  const contentHash = listingContentHash(input.listing);
  const view = listingPresentation(input.listing);
  const status = input.status ?? 'active';
  const entry: ListingIndexEntry = {
    listingId,
    version,
    contentHash,
    anchor: { kind: 'storage-program', locator: input.nativeAddress },
    summary: {
      title: view.title,
      category: view.category,
      tags: view.tags,
      ...(view.priceHint ? { priceHint: view.priceHint } : {}),
    },
    status,
    logical_address: expectedLogical,
    logicalAddressMetadata: legacyAbsent ? 'legacy-absent' : 'anchored',
  };
  const index: ListingIndex = {
    indexVersion: '1',
    generatedAt: input.generatedAt,
    seller: input.sellerPrimaryClaim,
    listings: [entry],
  };
  const indexBytes = jcsCanonical(index);
  const indexHash = `sha256-${bytesSha256Hex(indexBytes)}`;
  const indexUrl = `${origin}/.well-known/dacs/listings.json`;
  const agentCard = {
    dacs: {
      dacsVersion: '1',
      listings: { indexUrl, indexHash },
      identityClaims: [input.sellerPrimaryClaim],
    },
  };
  const summary: ListingSummary = {
    listingId,
    version,
    contentHash,
    anchor: { kind: 'storage-program', locator: input.nativeAddress },
    seller: { primaryClaim: input.sellerPrimaryClaim, displayName: view.displayName },
    offering: { title: view.title, category: view.category, tags: view.tags },
    pricing: { ...(view.priceHint ? { priceHint: view.priceHint } : {}), ...(view.currency ? { currency: view.currency } : {}) },
    status,
    catalogObservedAt: input.generatedAt,
    logical_address: expectedLogical,
  };
  const catalog = { listings: [summary], total: 1 };
  return {
    agentCard,
    agentCardBytes: jcsCanonical(agentCard),
    index,
    indexBytes,
    indexHash,
    catalog,
    catalogBytes: jcsCanonical(catalog),
    listingBytes: jcsCanonical(input.listing),
  };
}

function writeBytes(path: string, bytes: Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
}

/** Emit host-ready §6.3.5 and §6.3.6 JSON artifacts. Actual HTTP hosting is separate. */
export function emitDiscoveryArtifacts(input: EmitDiscoveryInput): DiscoveryFileSet {
  const artifacts = buildDiscoveryArtifacts(input);
  const { listingId, version } = listingCoordinates(input.listing);
  const files: DiscoveryFileSet = {
    agentCard: join(input.outputDir, '.well-known', 'agent.json'),
    listingIndex: join(input.outputDir, '.well-known', 'dacs', 'listings.json'),
    catalog: join(input.outputDir, 'api', 'dacs', 'listings.json'),
    listing: join(input.outputDir, 'api', 'dacs', 'listings', listingId, `${version}.json`),
  };
  writeBytes(files.agentCard, artifacts.agentCardBytes);
  writeBytes(files.listingIndex, artifacts.indexBytes);
  writeBytes(files.catalog, artifacts.catalogBytes);
  writeBytes(files.listing, artifacts.listingBytes);
  return files;
}

/**
 * LR discovery path: agent card → hash-protected index → native locator → content.
 * No Storage Program name is accepted or reconstructed anywhere on this path.
 */
export async function resolveListingFromPublishedBinding(
  agentCardUrl: string,
  logicalAddress: string,
  fetchResource: PublishedResourceFetcher,
  fetchNative: NativeListingFetcher,
): Promise<ResolvedPublishedListing> {
  const requested = parseListingLogicalAddress(logicalAddress);
  const agent = parseJson(await fetchResource(agentCardUrl), 'agent card');
  const dacs = record(agent['dacs'], 'agent card dacs block');
  if (dacs['dacsVersion'] !== '1') throw new Error('unsupported agent-card dacsVersion');
  const listingsBlock = record(dacs['listings'], 'agent card listings block');
  const indexUrl = listingsBlock['indexUrl'];
  const expectedIndexHash = listingsBlock['indexHash'];
  if (typeof indexUrl !== 'string' || typeof expectedIndexHash !== 'string') {
    throw new Error('agent card must advertise listings.indexUrl and listings.indexHash');
  }
  const indexBytes = await fetchResource(indexUrl);
  const actualIndexHash = `sha256-${bytesSha256Hex(indexBytes)}`;
  if (actualIndexHash !== expectedIndexHash) {
    throw new Error(`listing index hash mismatch: expected ${expectedIndexHash}, got ${actualIndexHash}`);
  }
  const index = parseJson(indexBytes, 'listing index');
  if (index['indexVersion'] !== '1' || index['seller'] !== requested.sellerPrimaryClaim) {
    throw new Error('listing index version/seller does not match requested logical address');
  }
  if (!Array.isArray(index['listings'])) throw new Error('listing index listings must be an array');
  const entry = index['listings']
    .map((value, i) => record(value, `listing index entry ${i}`))
    .find((value) => value['listingId'] === requested.listingId && value['version'] === requested.listingVersion);
  if (!entry) throw new Error(`listing binding missing for ${logicalAddress}`);
  if (entry['logical_address'] !== undefined && entry['logical_address'] !== logicalAddress) {
    throw new Error('listing index entry logical_address mismatch');
  }
  if (typeof entry['contentHash'] !== 'string') throw new Error('listing index entry contentHash missing');
  const anchor = record(entry['anchor'], 'listing index entry anchor');
  if (anchor['kind'] !== 'storage-program' || typeof anchor['locator'] !== 'string') {
    throw new Error('listing index entry anchor must carry a native storage-program locator');
  }
  const nativeAddress = anchor['locator'];
  const fetched = await fetchNative(nativeAddress);
  if (!fetched) throw new Error(`native listing anchor not found: ${nativeAddress}`);
  if (fetched.storageAddress !== undefined && fetched.storageAddress !== nativeAddress) {
    throw new Error('native fetch returned a different storage address');
  }
  const listing = typeof fetched.data === 'string'
    ? parseJson(new TextEncoder().encode(fetched.data), 'anchored listing')
    : record(fetched.data, 'anchored listing');
  const metadataStatus = entry['logicalAddressMetadata'];
  if (metadataStatus !== 'anchored' && metadataStatus !== 'legacy-absent') {
    throw new Error('listing index entry logicalAddressMetadata missing/invalid');
  }
  if (metadataStatus === 'anchored' && listing['logical_address'] !== logicalAddress) {
    throw new Error('anchored listing logical_address metadata mismatch');
  }
  if (metadataStatus === 'legacy-absent' && listing['logical_address'] !== undefined) {
    throw new Error('legacy-absent binding contradicts anchored logical_address metadata');
  }
  const coordinates = listingCoordinates(listing);
  const rederived = listingLogicalAddress(requested.sellerPrimaryClaim, coordinates.listingId, coordinates.version);
  if (rederived !== logicalAddress) throw new Error('anchored listing tuple does not match logical address');
  const actualContentHash = listingContentHash(listing);
  if (actualContentHash !== entry['contentHash']) {
    throw new Error(`listing contentHash mismatch: expected ${entry['contentHash']}, got ${actualContentHash}`);
  }
  return {
    listing,
    logicalAddress,
    nativeAddress,
    contentHash: actualContentHash,
    indexUrl,
    logicalAddressMetadata: metadataStatus,
  };
}
