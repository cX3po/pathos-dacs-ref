#!/usr/bin/env node
import { readFileSync, openSync, readSync, closeSync, fstatSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const ENTRY_HASH = '4d2928e40665754d00be379c2c5d67cd134dd909276bf2cb82bd5702e0781c35';
export const MAX_BYTES = 65536;
const keys = (v, expected) => Object.keys(v).sort().join(',') === [...expected].sort().join(',');
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
function requireInput(ok) { if (!ok) throw new Error('INVALID_INPUT'); }

export function inspect(input, sdk) {
  requireInput(object(input) && object(input.pricing));
  requireInput(keys(input, ['pricing','counteroffers']));
  const p = input.pricing;
  requireInput(keys(p, ['kind','bandCenter','minPct','maxPct']));
  requireInput(p.kind === 'negotiable' && object(p.bandCenter));
  requireInput(keys(p.bandCenter, ['amount','currency']));
  const boundedAmount = v => typeof v === 'string' && v.length > 0 && v.length <= 4096;
  const currency = v => typeof v === 'string' && v.length > 0 && v.length <= 128 && !/\s/.test(v);
  requireInput(boundedAmount(p.bandCenter.amount) && currency(p.bandCenter.currency));
  requireInput(typeof p.minPct === 'number' && Number.isFinite(p.minPct) && p.minPct >= 0 && p.minPct < 100);
  requireInput(typeof p.maxPct === 'number' && Number.isFinite(p.maxPct) && p.maxPct >= 0 && p.maxPct <= 1000000);
  requireInput(Array.isArray(input.counteroffers) && input.counteroffers.length <= 64);
  for (const offer of input.counteroffers) {
    requireInput(object(offer) && keys(offer, ['amount','currency']) && boundedAmount(offer.amount) && currency(offer.currency));
  }
  // Pass only declared terms; no price parsing, normalization or float arithmetic.
  const pricing = {kind: 'negotiable', bandCenter: {amount:p.bandCenter.amount,currency:p.bandCenter.currency}, minPct: p.minPct, maxPct: p.maxPct};
  const band = sdk.negotiablePriceBand(pricing);
  const counteroffers = input.counteroffers.map(offer => {
    // Both SDK amount validation and currency binding apply to every offer.
    let within;
    try { within = sdk.isNegotiablePriceWithinBand(offer.amount, pricing); }
    catch { return {...offer, decision: 'REJECTED', reason: 'INVALID_AMOUNT'}; }
    if (offer.currency !== pricing.bandCenter.currency) return {...offer, decision: 'REJECTED', reason: 'CURRENCY_MISMATCH'};
    return {...offer, decision: within ? 'ACCEPTABLE' : 'REJECTED', reason: within ? 'WITHIN_INCLUSIVE_BAND' : 'OUTSIDE_BAND'};
  });
  return {mode: 'LOCAL_ONLY', band, currency: pricing.bandCenter.currency, counteroffers};
}

export async function loadSdk(root) {
  if (!root) throw new Error('SDK_UNAVAILABLE');
  const entry = resolve(root, 'dist/negotiate/fixedPrice.js');
  let hash;
  try { hash = createHash('sha256').update(readFileSync(entry)).digest('hex'); }
  catch { throw new Error('SDK_UNAVAILABLE'); }
  if (hash !== ENTRY_HASH) throw new Error('SDK_HASH_MISMATCH');
  return import(pathToFileURL(entry).href);
}

export function readInput(path) {
  // Read at most MAX_BYTES+1 even if the file grows. Refuse FIFO/device hangs.
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    requireInput(fstatSync(fd).isFile());
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count <= MAX_BYTES) {
      const n = readSync(fd, bytes, count, bytes.length - count, null);
      if (n === 0) break;
      count += n;
    }
    requireInput(count <= MAX_BYTES);
    return JSON.parse(bytes.subarray(0, count).toString('utf8'));
  } finally { if (fd !== undefined) closeSync(fd); }
}

async function main() {
  const timeout = setTimeout(() => { console.error(JSON.stringify({decision:'ERROR',reason:'TIMEOUT'})); process.exit(2); }, 5000);
  try {
    if (process.argv.length !== 3) throw new Error('USAGE: node cli.mjs input.json (set DACS_SDK_ROOT)');
    const input = readInput(process.argv[2]);
    const sdk = await loadSdk(process.env.DACS_SDK_ROOT);
    const result = inspect(input, sdk);
    console.log(JSON.stringify(result));
    process.exitCode = result.counteroffers.some(o => o.decision === 'REJECTED') ? 1 : 0;
  } catch (error) {
    const allowed = ['SDK_UNAVAILABLE','SDK_HASH_MISMATCH','INVALID_INPUT'];
    const reason = allowed.includes(error.message) || error.message.startsWith('USAGE:') ? error.message : 'INVALID_INPUT_OR_SDK_ERROR';
    console.error(JSON.stringify({decision:'ERROR',reason})); process.exitCode = 2;
  } finally { clearTimeout(timeout); }
}
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) await main();
