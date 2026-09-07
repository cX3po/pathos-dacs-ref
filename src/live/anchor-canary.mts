/**
 * Canary A — one non-value SR-2 anchor, then a cold read from a fresh RPC session.
 *
 * Isolates the storage-program path from payments: anchors a small payload under a
 * unique program name, waits for the anchor result, then re-fetches it through a new
 * connection and verifies the content hash. Costs only the anchor fee; transfers nothing.
 *
 * Run:  LIVE=1 DACS_ENV_PATH=<dotenv with the mnemonics> node --import tsx src/live/anchor-canary.mts
 * Env:  DEMOS_RPC            RPC URL (default https://demosnode.discus.sh/)
 *       ANCHOR_NAME          anchor under this exact program name (overrides ANCHOR_NAME_STYLE)
 *       ANCHOR_WALLET_ENV    dotenv key holding the anchoring mnemonic (default DEMOS_MNEMONIC)
 *       ANCHOR_NAME_STYLE    `listing` mimics the gateway's `dacs1listing-<64 hex>` program name
 *       ANCHOR_ENCODING      `json` anchors an object; `binary` explicitly reproduces the node
 *                            defect; default anchors a string as wrapped JSON (the gateway path)
 *       ANCHOR_SIZE          pad the stored payload to this many bytes when large enough
 *       ANCHOR_CONNECT_BOTH  `1` connects the buyer wallet first, as the gateway does
 */
import { createHash } from 'node:crypto';
import { config } from 'dotenv';
import { StorageProgram } from '@kynesyslabs/demosdk/storage';
import { wrapTextAnchor } from '../demos/storage.js';

config({ path: process.env.DACS_ENV_PATH ?? '.env' });
const LIVE = process.env.LIVE === '1';
const RPC = process.env.DEMOS_RPC ?? 'https://demosnode.discus.sh/';
if (!LIVE) {
  console.log(JSON.stringify({ mode: 'dry', note: 'set LIVE=1 to anchor; nothing was sent' }));
  process.exit(0);
}
const { connectDemos, mnemonicFromEnv } = await import('../demos/connection.js');
const { anchor, fetchAnchored, verifyAnchor } = await import('../demos/storage.js');

const startedAt = new Date().toISOString();
const stamp = startedAt.replace(/[-:.TZ]/g, '').slice(0, 14);
// ANCHOR_NAME anchors under an explicit program name (e.g. the SDK-form percent-encoded listing address
// the coordinator writes since #84) so a node's treatment of a name form can be probed with one 2 DEM anchor.
const programName = process.env.ANCHOR_NAME && process.env.ANCHOR_NAME.length > 0
  ? process.env.ANCHOR_NAME
  : process.env.ANCHOR_NAME_STYLE === 'listing'
    ? `dacs1listing-${createHash('sha256').update(stamp).digest('hex')}`
    : `canary-a-${stamp}`;
const base: Record<string, unknown> = { kind: 'pathos-dacs-ref-canary-a', startedAt, programName };
const encoding = process.env.ANCHOR_ENCODING === 'binary'
  ? 'binary'
  : process.env.ANCHOR_ENCODING === 'json' ? 'json' : 'wrapped-json';
const targetSize = Number(process.env.ANCHOR_SIZE ?? '0');
const measureStoredBase = (): number => {
  if (encoding === 'json') return StorageProgram.getDataSize(base, 'json');
  const text = JSON.stringify(base);
  return encoding === 'binary'
    ? StorageProgram.getDataSize(text, 'binary')
    : StorageProgram.getDataSize(wrapTextAnchor(text), 'json');
};
if (Number.isFinite(targetSize) && targetSize > 0) {
  base.pad = '';
  base.pad = 'x'.repeat(Math.max(0, Math.floor(targetSize) - measureStoredBase()));
}
const asString = JSON.stringify(base);
const payload: string | Record<string, unknown> = encoding === 'json' ? base : asString;
const storedPayload = encoding === 'json' ? base : encoding === 'binary' ? asString : wrapTextAnchor(asString);
const storedBytes = StorageProgram.getDataSize(storedPayload, encoding === 'binary' ? 'binary' : 'json');
const contentBytes = encoding === 'json'
  ? storedBytes
  : new TextEncoder().encode(asString).byteLength;
const expectedHash = createHash('sha256').update(asString, 'utf8').digest('hex');

const WALLET_ENV = process.env.ANCHOR_WALLET_ENV ?? 'DEMOS_MNEMONIC';
if (process.env.ANCHOR_CONNECT_BOTH === '1') {
  const other = await connectDemos(mnemonicFromEnv('DEMOS_MNEMONIC'), RPC);
  await other.demos.getAddressInfo(other.address);
}
const handle = await connectDemos(mnemonicFromEnv(WALLET_ENV), RPC);

const t0 = Date.now();
let anchored;
try {
  anchored = await anchor(handle, programName, payload, encoding === 'binary' ? { encoding: 'binary' } : {});
} catch (error) {
  console.log(JSON.stringify({
    mode: 'live', phase: 'anchor', ok: false, encoding, programName, storedBytes, contentBytes,
    elapsedMs: Date.now() - t0, error: String(error).slice(0, 300),
  }));
  process.exit(1);
}
const anchorMs = Date.now() - t0;
const t1 = Date.now();
const cold = await fetchAnchored(RPC, anchored.storageAddress);
if (encoding === 'wrapped-json' && (cold?.wrapped !== true || typeof cold.data !== 'string')) {
  throw new Error('default canary read did not transparently unwrap the stored text envelope');
}
const verdict = await verifyAnchor(RPC, anchored.storageAddress, expectedHash);
console.log(JSON.stringify({
  mode: 'live', ok: verdict.outcome === 'pass', encoding, programName, storedBytes, contentBytes,
  storageAddress: anchored.storageAddress, txHash: anchored.txHash,
  anchorSizeBytes: anchored.sizeBytes, anchorContentBytes: anchored.contentBytes,
  anchorMs, coldReadMs: Date.now() - t1,
  coldRead: cold ? { owner: cold.owner, sizeBytes: cold.sizeBytes, createdAt: cold.createdAt } : null,
  verify: verdict,
}));
process.exit(verdict.outcome === 'pass' ? 0 : 1);
