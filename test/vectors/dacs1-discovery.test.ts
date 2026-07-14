import { deepEqual, equal, match, notEqual, ok, rejects } from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import {
  bytesSha256Hex,
  listingLogicalAddress,
  opaqueListingProgramName,
  parseListingLogicalAddress,
} from '../../src/dacs1/addressing.js';
import {
  buildDiscoveryArtifacts,
  emitDiscoveryArtifacts,
  listingContentHash,
  resolveListingFromPublishedBinding,
} from '../../src/dacs1/discovery.js';

const SELLER = `key:${'11'.repeat(32)}`;
const LOGICAL = listingLogicalAddress(SELLER, 'weather-band', 1);
const NATIVE = `stor-${'ab'.repeat(20)}`;
const ORIGIN = 'https://seller.example';
const AGENT_URL = `${ORIGIN}/.well-known/agent.json`;
const INDEX_URL = `${ORIGIN}/.well-known/dacs/listings.json`;

function listing(): Record<string, unknown> {
  return {
    v: 'dacs-1-listing:0.1',
    id: 'weather-band',
    version: 1,
    logical_address: LOGICAL,
    seller: { displayName: 'Neutral Test Seller', identity: { primary: { scheme: 'key', identifier: '11'.repeat(32) } } },
    capability: { key: 'weather-band', description: 'Neutral conformance fixture' },
    price: { amount: '1', currency: 'DEM', perUnit: 'request' },
    requiredCapabilities: ['sr-2-anchored-storage'],
    buyerRequirements: { primaryAcceptable: ['key'], requiredClaims: [], verificationRecipes: {} },
    acceptedRails: [],
    acceptedNegotiation: ['negotiate-fixed-price'],
    publishedAt: '2026-07-14T00:00:00.000Z',
    signature: 'fixture-signature-field-is-excluded-from-content-hash',
  };
}

function artifacts() {
  return buildDiscoveryArtifacts({
    listing: listing(),
    sellerPrimaryClaim: SELLER,
    nativeAddress: NATIVE,
    publisherOrigin: ORIGIN,
    generatedAt: 1_784_006_400_000,
  });
}

function resourceMap(agentBytes: Uint8Array, indexBytes: Uint8Array): Map<string, Uint8Array> {
  return new Map([[AGENT_URL, agentBytes], [INDEX_URL, indexBytes]]);
}

function reprotected(
  index: Record<string, unknown>,
  base = artifacts(),
): { agentBytes: Uint8Array; indexBytes: Uint8Array } {
  const indexBytes = jcsCanonical(index);
  const agent = structuredClone(base.agentCard) as { dacs: { listings: { indexHash: string } } };
  agent.dacs.listings.indexHash = `sha256-${bytesSha256Hex(indexBytes)}`;
  return { agentBytes: jcsCanonical(agent), indexBytes };
}

test('§6.3.4(b): listing logical metadata is CF-4 canonical and write input is opaque/colon-free', () => {
  equal(LOGICAL, `dacs1:key%3A${'11'.repeat(32)}:weather-band:v1`);
  deepEqual(parseListingLogicalAddress(LOGICAL), {
    sellerPrimaryClaim: SELLER,
    listingId: 'weather-band',
    listingVersion: 1,
  });
  const programName = opaqueListingProgramName(LOGICAL);
  match(programName, /^dacs1listing-[0-9a-f]{64}$/);
  equal(programName.includes(':'), false);
  notEqual(programName, LOGICAL);
});

test('§B.2 + §6.3.5: contentHash omits signature and indexHash protects exact emitted bytes', () => {
  const signed = listing();
  const unsigned = { ...signed };
  delete unsigned['signature'];
  const built = artifacts();
  equal(built.index.listings[0]!.contentHash, jcsHashHex(unsigned));
  equal(listingContentHash(signed), jcsHashHex(unsigned));
  notEqual(listingContentHash(signed), jcsHashHex(signed));
  equal(built.indexHash, `sha256-${bytesSha256Hex(built.indexBytes)}`);
  equal((built.agentCard as any).dacs.listings.indexHash, built.indexHash);
  equal(built.index.listings[0]!.logical_address, LOGICAL);
  equal(built.index.listings[0]!.logicalAddressMetadata, 'anchored');
  equal(built.index.listings[0]!.anchor.locator, NATIVE);
});

test('§6.3.4(c): immutable legacy records gain a disclosed binding without record mutation', async () => {
  const legacy = listing();
  delete legacy['logical_address'];
  const built = buildDiscoveryArtifacts({
    listing: legacy,
    sellerPrimaryClaim: SELLER,
    nativeAddress: NATIVE,
    publisherOrigin: ORIGIN,
    generatedAt: 1_784_006_400_000,
    legacyRecordWithoutLogicalMetadata: true,
  });
  equal(built.index.listings[0]!.logicalAddressMetadata, 'legacy-absent');
  equal(legacy['logical_address'], undefined);
  const resources = resourceMap(built.agentCardBytes, built.indexBytes);
  const resolved = await resolveListingFromPublishedBinding(
    AGENT_URL,
    LOGICAL,
    async (url) => resources.get(url)!,
    async (nativeAddress) => ({ storageAddress: nativeAddress, data: legacy }),
  );
  equal(resolved.logicalAddressMetadata, 'legacy-absent');
});

test('§6.3.6: catalog ListingSummary carries the same logical/native/content binding', () => {
  const built = artifacts();
  const summary = built.catalog.listings[0]!;
  equal(summary.logical_address, LOGICAL);
  equal(summary.anchor.locator, NATIVE);
  equal(summary.contentHash, listingContentHash(listing()));
  equal(summary.seller.primaryClaim, SELLER);
});

test('LR path resolves published binding → native → content with programName absent', async () => {
  const built = artifacts();
  const resources = resourceMap(built.agentCardBytes, built.indexBytes);
  const nativeCalls: string[] = [];
  const resolved = await resolveListingFromPublishedBinding(
    AGENT_URL,
    LOGICAL,
    async (url) => {
      const hit = resources.get(url);
      if (!hit) throw new Error(`missing URL ${url}`);
      return hit;
    },
    async (nativeAddress) => {
      nativeCalls.push(nativeAddress);
      return { storageAddress: nativeAddress, data: JSON.stringify(listing()) };
    },
  );
  equal(resolved.nativeAddress, NATIVE);
  equal(resolved.contentHash, listingContentHash(listing()));
  deepEqual(nativeCalls, [NATIVE]);
  equal(nativeCalls.includes(opaqueListingProgramName(LOGICAL)), false);
});

test('LR rejects a wrong indexHash before native resolution', async () => {
  const built = artifacts();
  const tampered = new Uint8Array(built.indexBytes);
  tampered[tampered.length - 2] = tampered[tampered.length - 2]! ^ 1;
  const resources = resourceMap(built.agentCardBytes, tampered);
  let nativeCalled = false;
  await rejects(
    resolveListingFromPublishedBinding(
      AGENT_URL,
      LOGICAL,
      async (url) => resources.get(url)!,
      async () => { nativeCalled = true; return null; },
    ),
    /index hash mismatch/,
  );
  equal(nativeCalled, false);
});

test('LR rejects a re-hashed index with the wrong listing contentHash', async () => {
  const built = artifacts();
  const poisoned = structuredClone(built.index) as unknown as Record<string, unknown>;
  (poisoned['listings'] as Array<Record<string, unknown>>)[0]!['contentHash'] = '00'.repeat(32);
  const protectedPoison = reprotected(poisoned, built);
  const resources = resourceMap(protectedPoison.agentBytes, protectedPoison.indexBytes);
  await rejects(
    resolveListingFromPublishedBinding(
      AGENT_URL,
      LOGICAL,
      async (url) => resources.get(url)!,
      async (nativeAddress) => ({ storageAddress: nativeAddress, data: listing() }),
    ),
    /listing contentHash mismatch/,
  );
});

test('LR rejects a hash-valid index with the requested entry missing', async () => {
  const built = artifacts();
  const missing = structuredClone(built.index) as unknown as Record<string, unknown>;
  missing['listings'] = [];
  const protectedMissing = reprotected(missing, built);
  const resources = resourceMap(protectedMissing.agentBytes, protectedMissing.indexBytes);
  await rejects(
    resolveListingFromPublishedBinding(
      AGENT_URL,
      LOGICAL,
      async (url) => resources.get(url)!,
      async () => { throw new Error('must not fetch native without a binding'); },
    ),
    /binding missing/,
  );
});

test('discovery emitter writes host-ready well-known, index, catalog, and detail artifacts', () => {
  const root = mkdtempSync(join(tmpdir(), 'dacs-discovery-'));
  try {
    const files = emitDiscoveryArtifacts({
      listing: listing(),
      sellerPrimaryClaim: SELLER,
      nativeAddress: NATIVE,
      publisherOrigin: ORIGIN,
      generatedAt: 1_784_006_400_000,
      outputDir: root,
    });
    const agent = JSON.parse(readFileSync(files.agentCard, 'utf8'));
    const indexBytes = readFileSync(files.listingIndex);
    equal(agent.dacs.listings.indexHash, `sha256-${bytesSha256Hex(indexBytes)}`);
    equal(JSON.parse(readFileSync(files.catalog, 'utf8')).listings[0].anchor.locator, NATIVE);
    equal(JSON.parse(readFileSync(files.listing, 'utf8')).logical_address, LOGICAL);
    ok(readFileSync(files.catalog, 'utf8').includes(SELLER));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('listing-pub dry-run wires CF-4 metadata and colon-free naming into the mint path', () => {
  const stdout = execFileSync(
    'npx',
    ['tsx', 'src/cli/listing-pub.ts', '--listing-file', 'discovery/reference-source-listing.json', '--dry-run'],
    { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
  );
  const receipt = JSON.parse(stdout) as Record<string, unknown>;
  equal(receipt['logical_address'], LOGICAL);
  match(String(receipt['storageProgramName']), /^dacs1listing-[0-9a-f]{64}$/);
  equal(String(receipt['storageProgramName']).includes(':'), false);
  equal(receipt['contentHash'], listingContentHash(listing()));
});
