/**
 * Receipt-ledger DRY-RUN demo — end-to-end, fully offline, cannot broadcast.
 *   npx tsx src/demos/receipt-ledger-demo.mts
 *
 * Shows the whole flow that build #2 produces for a FIRST ledger entry:
 *   PATH-OS artifact  →  fromArtifact (ReceiptEntry)  →  LedgerData  →
 *   StorageProgram.createStorageProgram payload + deterministic address + size + fee.
 *
 * Everything here is the SDK's PURE/static surface (key derivation, address derivation, payload
 * construction, fee calc) — no `demos.connect(rpc)`, no `confirm`, no `broadcastAndWait`. The live
 * read (current nonce + prior entries) and the broadcast are the owner-gated apply step, done by
 * planAppend()/storage.ts::anchor once approved. nonce=0 here is a clearly-labelled placeholder.
 */
import { Demos } from '@kynesyslabs/demosdk/websdk';
import { StorageProgram } from '@kynesyslabs/demosdk/storage';
import { fromArtifact } from './receipt-mappers.js';
import type { LedgerData } from './receipt-ledger.js';

const demos = new Demos();
const mnemonic = demos.newMnemonic(128);          // offline
await demos.connectWallet(mnemonic);              // offline key derivation (no network)
const deployer = demos.getAddress();

// A sample PATH-OS artifact (e.g. a gate verdict) mapped to a receipt entry.
const entry = fromArtifact(
  'gate-verdict',
  'demo-gate-1',
  { decision: 'APPROVED', reviewer: 'codex', files: 2 },
  { outcome: 'APPROVED', at: '2026-06-05T22:00:00Z', detail: { severityHigh: 0 } }
);

const ledgerName = 'pathos-receipts-demo';
const ledger: LedgerData = { ledgerVersion: '1', name: ledgerName, entries: [entry] };
const nonce = 0;   // PLACEHOLDER — the real nonce comes from getAddressNonce at apply time
const salt = '';

const storageAddress = StorageProgram.deriveStorageAddress(deployer, ledgerName, nonce, salt);
const acl = StorageProgram.publicACL();
const payload = StorageProgram.createStorageProgram(deployer, ledgerName, ledger, 'json', acl, { nonce, salt });
const sizeBytes = StorageProgram.getDataSize(ledger, 'json');
const feeOS = StorageProgram.calculateStorageFee(ledger, 'json').toString();
const withinSizeLimit = StorageProgram.validateSize(ledger, 'json');

console.log('── receipt-ledger DRY-RUN plan (NO broadcast) ──');
console.log('  ledger:         ', ledgerName);
console.log('  deployer:       ', deployer);
console.log('  storageAddress: ', storageAddress, '(nonce=0 placeholder — re-derives at apply with real nonce)');
console.log('  op:             ', 'create (first entry)');
console.log('  entry:          ', JSON.stringify(entry));
console.log('  sizeBytes:      ', sizeBytes, '| feeOS:', feeOS, `(≈ ${Number(feeOS) / 1e9} DEM) | withinSizeLimit: ${withinSizeLimit}`);
console.log('  payload fields: ', Object.keys(payload as object).join(', '));
console.log('\n⚠ DRY-RUN ONLY — confirm + broadcastAndWait (the on-chain write that costs DEM) is the');
console.log('  owner-gated step and is intentionally NOT called here.');
