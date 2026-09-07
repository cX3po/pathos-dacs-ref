#!/usr/bin/env node
/**
 * receipt-recheck — verify a stored delivery receipt in a fresh process, under an expected seller key.
 *
 *   node --import tsx src/live/receipt-recheck.mts --file <record.json> --seller-pubkey <64 hex>
 *
 * The record is a buyer-pilot run record (memory/demos/verify_pilot/<run>.json) or any JSON whose
 * `deliveryReceipt` member is a DeliveryReceipt. The expected seller key is mandatory: it is supplied
 * independently of the record, so a receipt that is merely self-consistent under another seller's key does
 * not verify. Prints one JSON line { ok, reason, seller } and exits 0 when the receipt verifies under that
 * key, 1 when it does not, 2 on a harness problem. Nothing is coerced.
 */
import { readFileSync } from 'node:fs';
import { verifyDeliveryReceipt } from '../lib/delivery-receipt.js';

const args = process.argv.slice(2);
const opt = (name: string): string | undefined => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const file = opt('--file'); const expected = opt('--seller-pubkey');
if (!file || !expected || !/^[0-9a-f]{64}$/i.test(expected)) { console.error('usage: --file <record.json> --seller-pubkey <64 hex>'); process.exit(2); }
let doc: Record<string, unknown>;
try { doc = JSON.parse(readFileSync(file, 'utf8')); } catch (error) { console.log(JSON.stringify({ ok: false, reason: `harness: ${String(error).slice(0, 160)}` })); process.exit(2); }
// A pilot run record (tools/demos_verify_pilot.py) keeps the buyer harness output under `buyer`; a bare harness output or
// a delivery envelope carries the receipt at the top level.
const receipt = doc.deliveryReceipt
  ?? (doc.buyer as { deliveryReceipt?: unknown } | undefined)?.deliveryReceipt
  ?? (doc.delivery as { deliveryReceipt?: unknown } | undefined)?.deliveryReceipt;
if (!receipt) { console.log(JSON.stringify({ ok: false, reason: 'record carries no deliveryReceipt' })); process.exit(1); }
const check = verifyDeliveryReceipt(receipt, expected.toLowerCase());
const seller = (receipt as { seller?: { pubKeyHex?: string } }).seller?.pubKeyHex ?? null;
console.log(JSON.stringify({ ok: check.ok === true, reason: check.ok === true ? null : (check as { reason?: string }).reason ?? 'receipt did not verify', seller }));
process.exit(check.ok === true ? 0 : 1);
