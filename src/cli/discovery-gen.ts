#!/usr/bin/env tsx
/** Emit host-ready DACS-1 §6.3.5/§6.3.6 artifacts for a known native listing anchor. */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { emitDiscoveryArtifacts } from '../dacs1/discovery.js';

const { values } = parseArgs({
  options: {
    'listing-file': { type: 'string' },
    'seller-claim': { type: 'string' },
    'native-address': { type: 'string' },
    'publisher-origin': { type: 'string' },
    'output-dir': { type: 'string', default: 'discovery' },
    'generated-at': { type: 'string' },
    'legacy-record-without-logical-metadata': { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
  strict: true,
});

if (values.help) {
  console.log(`Usage: dacs-discovery-gen --listing-file FILE --seller-claim CLAIM --native-address stor-... --publisher-origin https://... [--output-dir discovery] [--generated-at UNIX_MS] [--legacy-record-without-logical-metadata]`);
  process.exit(0);
}

const listingFile = values['listing-file'];
const sellerPrimaryClaim = values['seller-claim'];
const nativeAddress = values['native-address'];
const publisherOrigin = values['publisher-origin'];
if (!listingFile || !sellerPrimaryClaim || !nativeAddress || !publisherOrigin) {
  throw new Error('--listing-file, --seller-claim, --native-address, and --publisher-origin are required');
}
const generatedAt = values['generated-at'] === undefined ? Date.now() : Number(values['generated-at']);
const listing = JSON.parse(readFileSync(listingFile, 'utf8')) as Record<string, unknown>;
const files = emitDiscoveryArtifacts({
  listing,
  sellerPrimaryClaim,
  nativeAddress,
  publisherOrigin,
  generatedAt,
  outputDir: values['output-dir']!,
  legacyRecordWithoutLogicalMetadata: values['legacy-record-without-logical-metadata'],
});
console.log(JSON.stringify({ status: 'emitted', files }, null, 2));
