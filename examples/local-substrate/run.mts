/**
 * §11.3b — DACS on a NON-Demos substrate.
 *
 * Proves SR-2 ("anchored storage") is genuinely substrate-agnostic: the SAME,
 * UNMODIFIED DACS-5 verifier (`verifyBundle`) runs against a local filesystem store
 * instead of the Demos StorageProgram — zero Demos dependency — via the
 * `fetchAnchoredImpl` seam the verifier already exposes. It performs the full §10.4.2
 * two-sided anchoring walk on local storage: a clean PASS for a consistent buyer+seller
 * pair, and the spec-correct §10.4.3 "aborted-by-self" FAIL for a unilateral anchor.
 *
 * Run:  npx tsx examples/local-substrate/run.mts
 */
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AttestationBundle } from '../../src/types/index.js';
import { verifyBundle, computeAnchorPair, bytesToHex } from '../../src/lib/verify-bundle.js';
import { sign, generateKeypair } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHash } from '../../src/jcs.js';
import { localAnchor, localFetchAnchored, localVerifyAnchor } from '../../src/substrate/local.js';
import { sha256 } from '@noble/hashes/sha2';

function signedBundle(jobId: string, role: 'buyer' | 'seller', selfPub: string, selfPriv: Uint8Array, counterpartyPub: string): AttestationBundle {
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId,
    role,
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: selfPub }, claims: [], issuedAt: '2026-05-28T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: counterpartyPub } },
    state: 'completed',
    phases: [],
    finalisedAt: '2026-05-28T01:00:00Z',
  };
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, jcsCanonical(unsigned), selfPriv, jcsHash(unsigned));
  return { ...unsigned, signature: Buffer.from(sig).toString('base64') };
}

async function main() {
  const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'dacs-local-sr2-'));
  const local = (rpc: string, addr: string) => localFetchAnchored(rpc, addr);
  const jobId = 'local-substrate-demo-0001';
  const pair = computeAnchorPair(jobId);

  // A consistent two-party session (buyer + seller cross-reference each other).
  const b = generateKeypair(), s = generateKeypair();
  const bPub = bytesToHex(b.pubKey), sPub = bytesToHex(s.pubKey);
  const buyer = signedBundle(jobId, 'buyer', bPub, b.privKey, sPub);
  const seller = signedBundle(jobId, 'seller', sPub, s.privKey, bPub);

  console.log(`\n§11.3b — DACS-5 verifier on a NON-Demos (local filesystem) substrate`);
  console.log(`store: ${storeDir}\n`);

  // [1] bundle structurally valid (no substrate needed)
  const structural = await verifyBundle(buyer, { skipTwoSidedLookup: true });
  console.log(`[1] bundle structurally valid: ${structural.decision} (signers verified: ${structural.signersVerified.length})`);

  // [2] SR-2 contract on local: anchor → verifyAnchor (pass / tamper / missing)
  await localAnchor(storeDir, pair.buyer, buyer, bPub);
  const expect = bytesToHex(sha256(new TextEncoder().encode(JSON.stringify(buyer))));
  console.log(`[2] SR-2 anchor+verify on local: ${(await localVerifyAnchor(storeDir, pair.buyer, expect)).outcome}`
    + ` · tamper → ${(await localVerifyAnchor(storeDir, pair.buyer, 'de'.repeat(32))).outcome}`
    + ` · missing → ${(await localVerifyAnchor(storeDir, 'stor-' + 'ab'.repeat(32), expect)).outcome}`);

  // [3] FULL two-sided verify on local — anchor BOTH parties, run the real verifier.
  await localAnchor(storeDir, pair.seller, seller, sPub);
  const both = await verifyBundle(buyer, { rpc: storeDir, fetchAnchoredImpl: local });
  console.log(`[3] full §10.4.2 two-sided verify on LOCAL storage → ${both.decision}`
    + ` (attestationsVerified=${both.attestationsVerified}, steps=${both.steps.length})`);

  // [4] spec-correct §10.4.3: a unilateral anchor (seller removed) ⇒ aborted-by-self FAIL
  await fs.rm(path.join(storeDir, encodeURIComponent(pair.seller) + '.json'), { force: true });
  const unilateral = await verifyBundle(buyer, { rpc: storeDir, fetchAnchoredImpl: local });
  console.log(`[4] unilateral anchor (seller absent) → ${unilateral.decision} (spec-correct §10.4.3 aborted-by-self)`);

  console.log(`\nSR-2 is substrate-agnostic: the unmodified DACS-5 verifier ran its full`);
  console.log(`two-sided-anchoring walk on local storage — PASS and the correct unilateral`);
  console.log(`FAIL — with zero Demos dependency, via the impl's own fetchAnchoredImpl seam.`);
  await fs.rm(storeDir, { recursive: true, force: true });
}

main().catch((e) => { console.error('error:', e?.message ?? e); process.exit(1); });
