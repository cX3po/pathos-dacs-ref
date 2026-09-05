/**
 * Writes the four example delivery receipts under commerce/examples/, one per SKU, signed with a
 * throwaway seller key derived from a fixed seed so the files are deterministic and the key is
 * plainly not a real merchant key. Run: `npx tsx commerce/examples/generate-receipts.mts`.
 * Every hash in the examples is the sha256 of the literal placeholder bytes named next to it.
 */
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  DELIVERY_RECEIPT_VERSION,
  signDeliveryReceipt,
  type DeliveryReceiptBody,
} from '../../src/lib/delivery-receipt.js';

ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

/** Throwaway seller key: sha256("pathos-delivery-receipt example seller key, not a merchant key"). */
export const EXAMPLE_SELLER_SEED = createHash('sha256')
  .update('pathos-delivery-receipt example seller key, not a merchant key')
  .digest();
export const EXAMPLE_SELLER_PUBKEY_HEX = bytesToHex(ed25519.getPublicKey(EXAMPLE_SELLER_SEED));

const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const ISSUED = '2026-09-05T14:00:00.000Z';
const NETWORK = { id: 'demos:testnet', mode: 'rehearsal' as const };
const SELLER = { name: 'PATH-OS (example key)', pubKeyHex: EXAMPLE_SELLER_PUBKEY_HEX };
const TX = (n: number) => '0x' + n.toString(16).padStart(64, '0');
const BUYER = '0x' + 'b'.repeat(64);

export function exampleBodies(): DeliveryReceiptBody[] {
  const verifyInput = sha('example verify request bytes');
  return [
    {
      v: DELIVERY_RECEIPT_VERSION, sku: 'verify-bundle',
      quoteRef: `verify:${verifyInput}`, buyer: BUYER, seller: SELLER, network: NETWORK,
      payment: { txHash: TX(1), from: BUYER, amountOs: '100000000' },
      idempotencyKey: `verify:${verifyInput}`,
      inputHash: verifyInput, implementationVersion: '@pathos-labs/dacs-verifier@0.1.0',
      resultHash: sha('example verify verdict bytes'), issuedAt: ISSUED,
      retrieval: { kind: 'http-response', ref: 'POST /verify 200 with X-Payment-Proof' },
      endpoint: { resourceId: `verify:${verifyInput}`, redelivered: false },
    },
    {
      v: DELIVERY_RECEIPT_VERSION, sku: 'interop-run',
      quoteRef: 'quote:interop-run:example-1', buyer: 'did:example:implementer', seller: SELLER, network: NETWORK,
      payment: { txHash: TX(2), from: BUYER, amountOs: '5000000000' },
      idempotencyKey: 'interop-run:adapter@0123456789abcdef:next@3426faae',
      inputHash: sha('adapter command + commit 0123456789abcdef + next 3426faae'),
      implementationVersion: 'shared-suite cross-run.mjs@9028ff0',
      resultHash: sha('example interop run report bytes'), issuedAt: ISSUED,
      retrieval: { kind: 'thread-comment', ref: 'https://github.com/DACS-Agent-commerce/DACS-Standard/issues/270#issuecomment-example' },
    },
    {
      v: DELIVERY_RECEIPT_VERSION, sku: 'verifier-package',
      quoteRef: 'quote:verifier-package:0.1.0', buyer: 'did:example:integrator', seller: SELLER, network: NETWORK,
      payment: { txHash: TX(3), from: BUYER, amountOs: '1000000000' },
      idempotencyKey: 'verifier-package:@pathos-labs/dacs-verifier@0.1.0',
      inputHash: sha('@pathos-labs/dacs-verifier@0.1.0'), implementationVersion: '@pathos-labs/dacs-verifier@0.1.0',
      resultHash: sha('example tarball bytes'), issuedAt: ISSUED,
      retrieval: { kind: 'issue-attachment', ref: 'https://github.com/cX3po/pathos-dacs-ref/issues/example' },
    },
    {
      v: DELIVERY_RECEIPT_VERSION, sku: 'pr-review',
      quoteRef: 'quote:pr-review:DACS-Standard#397@1538392e', buyer: 'did:example:author', seller: SELLER, network: NETWORK,
      payment: { txHash: TX(4), from: BUYER, amountOs: '10000000000' },
      idempotencyKey: 'pr-review:DACS-Agent-commerce/DACS-Standard#397@1538392eb1ae759a1a5e2a6d9105fce36e73d00f',
      inputHash: sha('1538392eb1ae759a1a5e2a6d9105fce36e73d00f'), implementationVersion: 'review desk exact-head method 2026-09',
      resultHash: sha('example review body bytes'), issuedAt: ISSUED,
      retrieval: { kind: 'pr-review', ref: 'https://github.com/DACS-Agent-commerce/DACS-Standard/pull/397#pullrequestreview-example' },
    },
  ];
}

export function exampleReceipts() {
  return exampleBodies().map((body) => signDeliveryReceipt(body, EXAMPLE_SELLER_SEED));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const receipt of exampleReceipts()) {
    writeFileSync(join(here, `${receipt.sku}.receipt.json`), JSON.stringify(receipt, null, 2) + '\n');
  }
  writeFileSync(join(here, 'example-seller-key.json'), JSON.stringify({
    note: 'throwaway example seller key: seed = sha256("pathos-delivery-receipt example seller key, not a merchant key"); never a merchant key',
    pubKeyHex: EXAMPLE_SELLER_PUBKEY_HEX,
  }, null, 2) + '\n');
  console.log(`wrote ${exampleBodies().length} example receipts, seller ${EXAMPLE_SELLER_PUBKEY_HEX.slice(0, 16)}…`);
}
