/**
 * PATHOS ↔ DACS conformance harness.
 *
 * NOT part of the DACS reference impl — this is the oracle PATHOS's Python signer
 * (axiom/tools/receipts/sign.py) round-trips against, to guarantee byte-identical
 * JCS canonicalization + ed25519 signatures. PATHOS-internal receipts use their own
 * separator namespace (pathos-*:v1:), which is NOT in the DACS §7.7 closed registry,
 * so we exercise the crypto at the buildSignedBytes + raw @noble/ed25519 layer
 * (separator is just a UTF-8 byte prefix; matching JCS + matching ed25519 ⇒ equivalent).
 *
 * Usage (all I/O via JSON on argv[2]):
 *   npx tsx pathos-conformance-harness.mts jcs    '{"payload":{...}}'
 *     → prints hex of jcsCanonical(payload)
 *   npx tsx pathos-conformance-harness.mts verify  '{"sep":"...","payload":{...},"sigHex":"...","pubHex":"..."}'
 *     → prints "true" | "false"
 *   npx tsx pathos-conformance-harness.mts sign    '{"sep":"...","payload":{...},"seedHex":"..."}'
 *     → prints JSON {"sigHex":"...","pubHex":"..."}
 */
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { jcsCanonical } from './src/jcs.js';
import { buildSignedBytes } from './src/domain-sep.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

const hex = (u: Uint8Array): string => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s: string): Uint8Array => new Uint8Array((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)));

const cmd = process.argv[2];
const arg = JSON.parse(process.argv[3] ?? '{}');

if (cmd === 'jcs') {
  process.stdout.write(hex(jcsCanonical(arg.payload)));
} else if (cmd === 'verify') {
  // raw buildSignedBytes + raw ed25519.verify — bypasses DACS closed-registry on purpose
  const signed = buildSignedBytes(arg.sep as any, jcsCanonical(arg.payload));
  let ok = false;
  try { ok = ed25519.verify(unhex(arg.sigHex), signed, unhex(arg.pubHex)); } catch { ok = false; }
  process.stdout.write(ok ? 'true' : 'false');
} else if (cmd === 'sign') {
  const seed = unhex(arg.seedHex);
  const pub = ed25519.getPublicKey(seed);
  const signed = buildSignedBytes(arg.sep as any, jcsCanonical(arg.payload));
  const sig = ed25519.sign(signed, seed);
  process.stdout.write(JSON.stringify({ sigHex: hex(sig), pubHex: hex(pub) }));
} else {
  process.stderr.write(`unknown command: ${cmd}\n`);
  process.exit(2);
}
