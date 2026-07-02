/**
 * The Stranger Gauntlet — a DACS trust showcase (reference engine, console-only).
 *
 *   npx tsx showcase/stranger-gauntlet/gauntlet.mts
 *
 * A2A's unsolved problem is TRUSTING A STRANGER'S AGENT: a shopper meets a vendor
 * agent it has never seen and has no basis to believe the "deal done" it is handed.
 * The Gauntlet demonstrates that DACS solves this at the artifact layer. One Shopper
 * meets THREE stranger Vendor agents in the same session:
 *
 *   • Vendor A (honest)      — a valid, real-ed25519-signed two-sided AttestationBundle
 *   • Vendor B (honest)      — a different valid, real-signed bundle
 *   • Vendor C (COUNTERFEIT)  — a bundle that was validly signed and then TAMPERED after
 *                               signing (a bait-and-switch on the listing it attests to)
 *
 * All three are run through the SAME §10.4.1 referee — `verifyBundleV1` — and the
 * showcase produces a "Trust Report": for each vendor, the §7.5.1 decision and, for
 * the counterfeit, the DECISIVE check that killed it. The counterfeit MUST NOT be
 * accepted (§7.5.1 do-not-collapse). If it ever were, that would be a real verifier
 * bug and the process exits 1.
 *
 * This is DEFENSIVE conformance verification: we prove the verifier CATCHES a bad
 * bundle built from our own fixtures. It is not attack tooling and touches no network,
 * no funds, and no deployed identities — deterministic fixed-seed keys, console only.
 * Style mirrors src/showcase (the Vendor↔Shopper DACS-1→5 session it descends from).
 *
 * NOTE on vocabulary: the §10.4 bundle referee returns the three acceptance values
 * `accept | reject | indeterminate` (BundleV1Verdict.decision). Only `accept` is
 * success ("trusted"); BOTH `reject` (invalid) and `indeterminate` (undecidable) mean
 * NOT-TRUSTED (§7.5.1). That maps onto the broader §7.5.1 four-value decision vocabulary
 * (pass | fail | indeterminate | error) used by the DACS-2 VerifyResult: accept≈pass,
 * reject≈fail. The Trust Report shows the verifier's native word plus this trust framing.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsHashHex } from '../../src/jcs.js';
import { bundleSignedScopeHashV1 } from '../../src/lib/bundle-signed-scope-v1.js';
import { verifyBundleV1, type BundleV1Verdict } from '../../src/lib/verify-bundle-v1.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// ── deterministic real ed25519 keys (mirrors test/vectors/verify-bundle-v1.test.ts) ─────────────
interface Key { priv: Uint8Array; pubHex: string; }
function fixedKey(fill: number): Key {
  const priv = new Uint8Array(32).fill(fill); // fixed seed → deterministic, zero network/entropy
  return { priv, pubHex: hex(ed25519.getPublicKey(priv)) };
}

// ── bundle construction (the honest, spec-conformant path) ───────────────────────────────────────
interface HonestOpts {
  jobId: string;
  item: string;
  priceOs: string;
  shopper: Key; // buyer, constant across the session
  vendor: Key;  // seller
}

/** A content-addressed listing (real jcsHashHex, like src/showcase/flow.ts's signArtifact). */
function listingContentHash(o: { jobId: string; vendor: string; item: string; priceOs: string }): string {
  return jcsHashHex({ v: 'dacs-listing:0.1', listingId: `${o.jobId}-listing`, ...o });
}

/** Build the unsigned §10.4 AttestationBundleV1 for a Shopper↔Vendor session. */
function unsignedBundle(o: HonestOpts, listHash: string): Omit<AttestationBundleV1, 'signatures'> {
  return {
    bundleVersion: '1',
    jobId: o.jobId,
    outcome: 'completed',
    anchoredByRole: 'buyer', // this is the Shopper's (buyer) copy of the two-sided bundle
    listingRef: { listingId: `${o.jobId}-listing`, version: 1, contentHash: listHash },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.shopper.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.vendor.pubHex } },
    ],
    phaseSummary: [
      { index: 0, kind: 'vet-credentials', outcome: 'ok' },
      { index: 1, kind: 'negotiate-fixed-price', outcome: 'ok' },
      { index: 2, kind: 'pay-cross-chain-htlc', outcome: 'ok' },
    ],
    vetRecords: [],
    settlementEvidence: [],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1735689600000,
  };
}

/** Sign an unsigned bundle with each key over "dacs-bundle:v1:" || bundleHash (§10.4.1). */
function signBundle(unsigned: Omit<AttestationBundleV1, 'signatures'>, keys: Key[]): AttestationBundleV1 {
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  return {
    ...unsigned,
    signatures: keys.map((k) => ({
      party: { scheme: 'cci' as const, identifier: k.pubHex },
      algorithm: 'ed25519' as const,
      value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), k.priv)).toString('base64'),
    })),
  };
}

/** Build a fully-honest, two-sided real-key-signed bundle (buyer + seller). */
function honestBundle(o: HonestOpts): AttestationBundleV1 {
  const listHash = listingContentHash({ jobId: o.jobId, vendor: o.vendor.pubHex, item: o.item, priceOs: o.priceOs });
  return signBundle(unsignedBundle(o, listHash), [o.shopper, o.vendor]);
}

// ── the referee's decisive-reason extractor ──────────────────────────────────────────────────────
interface KilledBy { check: string; detail: string; }

/**
 * Which single §10.4.1 check is DECISIVE for a not-accepted verdict, in the verifier's own
 * precedence order (structural → signer-rule → hard signature failure → indeterminate). Returns
 * null for `accept`. This is what makes "the counterfeit's killing check explicit".
 */
function decisiveReason(v: BundleV1Verdict): KilledBy | null {
  if (v.decision === 'accept') return null;
  if (!v.structurallyValid) {
    return { check: 'structurallyValid=false', detail: v.reasons[0] ?? 'structural validation failed' };
  }
  if (!v.signerRuleSatisfied) {
    const r = v.reasons.find((x) => /unlisted|required signer|buyer \+ seller/.test(x));
    return { check: 'signerRuleSatisfied=false', detail: r ?? 'required-signer rule violated (§10.4.1)' };
  }
  const hardFail = v.signatureChecks.find((c) => c.decision === 'fail');
  if (hardFail) {
    return {
      check: 'signature-invalid',
      detail: `signer ${hardFail.party.slice(0, 22)}… — ${hardFail.reason ?? 'signature failed verification'}`,
    };
  }
  // No hard failure, but not every signature could be verified → §7.5.1 indeterminate.
  const r = v.reasons.find((x) => /indeterminate/.test(x));
  return { check: 'indeterminate', detail: r ?? v.reasons[0] ?? 'undecidable (unresolvable key / placeholder DID)' };
}

// ── report shapes ────────────────────────────────────────────────────────────────────────────────
type Decision = BundleV1Verdict['decision'];
interface VendorResult {
  name: string;
  jobId: string;
  decision: Decision;   // accept | reject | indeterminate  (§10.4.1 native)
  trusted: boolean;     // decision === 'accept'
  killedBy: KilledBy | null;
  bundleHash: string;
}
interface GauntletResult {
  showcase: 'stranger-gauntlet';
  shopper: string;
  vendors: VendorResult[];
  honestBothTrusted: boolean;
  counterfeitCaught: boolean;
  verdict: 'PASS' | 'FAIL';
}

// ── console display (mirrors src/showcase/display.ts badge tone) ───────────────────────────────────
const trustBadge = (d: Decision) =>
  d === 'accept' ? '🟢 TRUSTED (accept)' : d === 'reject' ? '🔴 CAUGHT (reject)' : '🟡 NOT-TRUSTED (indeterminate)';

function printTrustReport(res: GauntletResult): void {
  console.log('\n════════════════════════════════════════════════════════════════════');
  console.log('  THE STRANGER GAUNTLET — DACS Trust Report');
  console.log('  One Shopper. Three stranger vendor agents. One §10.4.1 referee.');
  console.log('════════════════════════════════════════════════════════════════════');
  console.log(`  Shopper (buyer): cci:${res.shopper.slice(0, 20)}…`);
  console.log(`  Referee:         verifyBundleV1 (§10.4.1 acceptance verifier)\n`);

  for (const v of res.vendors) {
    console.log(`  ── ${v.name}`);
    console.log(`     job:       ${v.jobId}`);
    console.log(`     bundleHash: ${v.bundleHash ? v.bundleHash.slice(0, 24) + '…' : '(structural reject — no hash)'}`);
    console.log(`     decision:   ${trustBadge(v.decision)}`);
    if (v.killedBy) {
      console.log(`     killed by:  ${v.killedBy.check}`);
      console.log(`                 └ ${v.killedBy.detail}`);
    } else {
      console.log(`     killed by:  — (all §10.4.1 checks passed; signatures verify)`);
    }
    console.log('');
  }

  console.log('  ──────────────────────────────────────────────────────────────────');
  console.log(`  Honest vendors trusted:  ${res.honestBothTrusted ? '✅ A + B both accept' : '❌ an honest vendor was NOT accepted'}`);
  console.log(`  Counterfeit caught:      ${res.counterfeitCaught ? '✅ Vendor C did NOT slip through' : '❌ Vendor C was ACCEPTED — verifier bug!'}`);
  console.log(`  Gauntlet verdict:        ${res.verdict === 'PASS' ? '✅ PASS' : '❌ FAIL'}`);
  console.log('  ──────────────────────────────────────────────────────────────────\n');
}

// ── the gauntlet ───────────────────────────────────────────────────────────────────────────────
export function runStrangerGauntlet(): GauntletResult {
  // One constant Shopper; three stranger vendors, each its own deterministic key + job.
  const shopper = fixedKey(0x5a);
  const vendorA = fixedKey(0xa1);
  const vendorB = fixedKey(0xb2);
  const vendorC = fixedKey(0xc3);

  // Vendor A + B — honest, real-key-signed two-sided bundles.
  const bundleA = honestBundle({ jobId: 'gauntlet-vendor-a', item: 'inference-job:summarisation', priceOs: '5000000000', shopper, vendor: vendorA });
  const bundleB = honestBundle({ jobId: 'gauntlet-vendor-b', item: 'inference-job:translation', priceOs: '3000000000', shopper, vendor: vendorB });

  // Vendor C — COUNTERFEIT. Build an honest, validly-signed bundle FIRST, then tamper a signed-scope
  // field AFTER signing: rewrite listingRef.contentHash to point at a DIFFERENT listing (a
  // bait-and-switch — the signed attestation now claims to cover a listing nobody agreed to). Because
  // listingRef.contentHash IS in the signed canonical scope (unlike anchoredByRole, which is excluded
  // by R5-1), the referee's recomputed bundleHash no longer matches the hash the ed25519 signatures
  // were made over → every resolvable signature fails → §10.4.1 rejects. The tamper is deliberately a
  // no-op on structure/signer-set so the KILLING check is unambiguously the signature, not a side effect.
  const honestC = honestBundle({ jobId: 'gauntlet-vendor-c', item: 'inference-job:image-gen', priceOs: '9000000000', shopper, vendor: vendorC });
  const baitListingHash = listingContentHash({ jobId: 'gauntlet-vendor-c', vendor: vendorC.pubHex, item: 'inference-job:image-gen', priceOs: '1' /* ← price swapped after signing */ });
  const bundleC: AttestationBundleV1 = {
    ...honestC,
    listingRef: { ...honestC.listingRef, contentHash: baitListingHash }, // post-signature content tamper
  };

  const run = (name: string, jobId: string, b: AttestationBundleV1): VendorResult => {
    const v = verifyBundleV1(b); // enforcing mode (requireSignatures:true) — real keys, real crypto
    return { name, jobId, decision: v.decision, trusted: v.decision === 'accept', killedBy: decisiveReason(v), bundleHash: v.bundleHash };
  };

  const vendors: VendorResult[] = [
    run('Vendor A (honest)', 'gauntlet-vendor-a', bundleA),
    run('Vendor B (honest)', 'gauntlet-vendor-b', bundleB),
    run('Vendor C (counterfeit)', 'gauntlet-vendor-c', bundleC),
  ];

  const [a, bRes, c] = vendors as [VendorResult, VendorResult, VendorResult];
  const honestBothTrusted = a.trusted && bRes.trusted;
  const counterfeitCaught = !c.trusted; // §7.5.1: NOT accept === caught (reject OR indeterminate)
  return {
    showcase: 'stranger-gauntlet',
    shopper: shopper.pubHex,
    vendors,
    honestBothTrusted,
    counterfeitCaught,
    verdict: honestBothTrusted && counterfeitCaught ? 'PASS' : 'FAIL',
  };
}

// ── entry point ────────────────────────────────────────────────────────────────────────────────
function main(): void {
  const res = runStrangerGauntlet();
  printTrustReport(res);

  // Machine-readable result — a later HTTP / signed-receipt layer can consume this verbatim.
  console.log('  Machine-readable result (JSON):');
  console.log(JSON.stringify({
    showcase: res.showcase,
    shopper: `cci:${res.shopper}`,
    vendors: res.vendors.map((v) => ({ name: v.name, decision: v.decision, killedBy: v.killedBy })),
    honestBothTrusted: res.honestBothTrusted,
    counterfeitCaught: res.counterfeitCaught,
    verdict: res.verdict,
  }, null, 2));
  console.log('');

  // Exit 0 ONLY IF both honest vendors are trusted AND the counterfeit was caught. A `1` here would
  // mean the counterfeit slipped through — a real §7.5.1 do-not-collapse verifier bug.
  process.exit(res.verdict === 'PASS' ? 0 : 1);
}

// Run when invoked directly (not when imported by the test).
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
