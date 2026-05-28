#!/usr/bin/env tsx
/**
 * csv-class end-to-end example.
 *
 * Walks the full DACS-1 + DACS-2 + DACS-5 loop in one process. No chain writes,
 * no network beyond an optional GLEIF call (see SKIP_GLEIF). The script ends
 * with a structured summary that maps each step to its spec section.
 *
 * Run:  npx tsx examples/csv-class/run.mts
 *
 * Env:
 *   SKIP_GLEIF=1     skip the live GLEIF fetch (use a canned response instead)
 */

import { generateKeypair, sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHash } from '../../src/jcs.js';
import { verifyBundle, bytesToHex } from '../../src/lib/verify-bundle.js';
import { dahrFetch } from '../../src/demos/index.js';
import type { Listing, AttestationBundle, VerifyResult } from '../../src/types/index.js';

const log = (...args: unknown[]) => console.error('[csv-class]', ...args);

async function main() {
  // ─── 1. Generate buyer + seller keypairs ──────────────────────────────────────
  const buyer = generateKeypair();
  const seller = generateKeypair();
  const buyerCci = bytesToHex(buyer.pubKey);
  const sellerCci = bytesToHex(seller.pubKey);
  log(`buyer CCI: ${buyerCci.slice(0, 16)}…`);
  log(`seller CCI: ${sellerCci.slice(0, 16)}…`);

  // ─── 2. DACS-1 — seller publishes a listing ───────────────────────────────────
  const listing: Listing = {
    v: 'dacs-1-listing:0.1',
    id: 'rowsense-analyze-csv-001',
    version: 1,
    seller: { identity: { primary: { scheme: 'cci', identifier: sellerCci } } },
    capability: {
      key: 'analyze-csv',
      description: 'Analyze CSV row-by-row, return per-row category + confidence as JSON',
      input: 'text/csv',
      output: 'application/json',
    },
    price: { amount: '0.01', currency: 'USDC', perUnit: 'row' },
    requiredCapabilities: ['sr-2-anchored-storage'],
    buyerRequirements: {
      primaryAcceptable: ['cci'],
      requiredClaims: [],
      verificationRecipes: {} as Record<string, string>,
    },
    acceptedRails: ['pay-x402@1'],
    acceptedNegotiation: ['negotiate-fixed-price'],
    publishedAt: new Date().toISOString(),
  };
  const listingUnsigned: Listing = { ...listing };
  const listingCanonical = jcsCanonical(listingUnsigned);
  const listingSig = sign(DOMAIN_SEPARATORS.LISTING, listingCanonical, seller.privKey);
  const listingSigned: Listing = { ...listingUnsigned, signature: Buffer.from(listingSig).toString('base64') };
  if (listingCanonical.length > 16 * 1024) throw new Error('listing exceeds §6.3.4 16 KB cap');
  // Compute the listing's content hash so we can embed it as a phase artifact.
  // In a real flow this is what the buyer would resolve from the seller's
  // SR-2 anchor; here we generate it locally because the example doesn't write to chain.
  const { sha256 } = await import('@noble/hashes/sha2');
  const listingContentHash = bytesToHex(sha256(jcsCanonical(listingSigned)));
  log(`✓ DACS-1 listing built + signed (${listingCanonical.length} canonical bytes; hash=${listingContentHash.slice(0, 16)}…)`);

  // ─── 3. DACS-2 — vet seller via GLEIF (skip-anchor mode) ──────────────────────
  const lei = 'HWUPKR0MPOU8FGXBT394'; // Apple Inc.
  let dahrAttestation: VerifyResult['attestation'];
  let decision: 'pass' | 'fail' | 'indeterminate' = 'indeterminate';
  let entityName: string | undefined;
  if (process.env.SKIP_GLEIF !== '1') {
    try {
      const result = await dahrFetch(undefined, `https://api.gleif.org/api/v1/lei-records/${lei}`, {
        skipAnchor: true,
        recipe: 'gleif-cbp:1',
        headers: { Accept: 'application/vnd.api+json' },
      });
      dahrAttestation = result.attestation;
      const body = result.responseBody as { data?: { attributes?: { entity?: { legalName?: { name?: string } }; registration?: { status?: string } } } };
      const status = body.data?.attributes?.registration?.status;
      entityName = body.data?.attributes?.entity?.legalName?.name;
      decision = status === 'ISSUED' ? 'pass' : status ? 'fail' : 'indeterminate';
      log(`✓ DACS-2 vet via GLEIF — decision=${decision} entity="${entityName ?? 'unknown'}"`);
    } catch (e) {
      log(`⚠ DACS-2 GLEIF call failed: ${(e as Error).message} — falling back to skip-gleif`);
    }
  }
  if (!dahrAttestation) {
    // Canned attestation for offline run. The stub-locator prefix MUST equal the
    // first 32 hex chars of contentHash (the verifier checks for forgery).
    const cannedHash = 'a'.repeat(64);
    dahrAttestation = {
      anchor: { substrate: 'demos', locator: `stor-stub-${cannedHash.slice(0, 32)}` },
      contentHash: cannedHash,
      type: 'dahr-stub:gleif-cbp:1',
      producedAt: new Date().toISOString(),
    };
    decision = 'pass';
    entityName = '(skip-gleif canned)';
    log(`✓ DACS-2 vet (offline canned)`);
  }

  // ─── 4. DACS-5 — buyer + seller each build their AttestationBundle ────────────
  const jobId = `csv-class-${Date.now()}`;
  const verifyResult: VerifyResult = {
    v: 'dacs-2-verify-result:0.1',
    jobId,
    claim: { scheme: 'lei', identifier: lei },
    recipe: 'gleif-cbp:1',
    decision,
    reason: `LEI ${decision === 'pass' ? 'active' : decision} — entity="${entityName ?? 'unknown'}"`,
    runAt: new Date().toISOString(),
    freshnessSec: 60 * 60 * 24,
    attestation: dahrAttestation,
  };

  const buyerBundleUnsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId,
    role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: buyerCci }, claims: [], issuedAt: new Date().toISOString(), presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: sellerCci } },
    state: 'completed',
    phases: [
      {
        // Discovery phase records the listing the buyer engaged with.
        // The listing content-hash is embedded as a synthetic AttestationRef so
        // the §10.4.1 walk has a reference to chase.
        phaseId: 'discover',
        startedAt: new Date().toISOString(),
        endedAt: new Date().toISOString(),
        outcome: 'pass',
        attestations: [{
          anchor: { substrate: 'demos', locator: `stor-stub-${listingContentHash.slice(0, 32)}` },
          contentHash: listingContentHash,
          type: 'dahr-stub:listing-ref:v1',
          producedAt: new Date().toISOString(),
        }],
      },
      {
        phaseId: 'vet-credentials',
        startedAt: verifyResult.runAt,
        endedAt: new Date().toISOString(),
        outcome: 'pass',
        attestations: [dahrAttestation],
      },
    ],
    verifyResults: [verifyResult],
    finalisedAt: new Date().toISOString(),
  };
  const buyerCanonical = jcsCanonical(buyerBundleUnsigned);
  const buyerHash = jcsHash(buyerBundleUnsigned);
  const buyerSig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, buyerCanonical, buyer.privKey, buyerHash);
  const buyerBundle: AttestationBundle = { ...buyerBundleUnsigned, signature: Buffer.from(buyerSig).toString('base64') };

  const sellerBundleUnsigned: AttestationBundle = {
    ...buyerBundleUnsigned,
    role: 'seller',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: sellerCci }, claims: [], issuedAt: new Date().toISOString(), presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: buyerCci } },
  };
  const sellerCanonical = jcsCanonical(sellerBundleUnsigned);
  const sellerHash = jcsHash(sellerBundleUnsigned);
  const sellerSig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, sellerCanonical, seller.privKey, sellerHash);
  const sellerBundle: AttestationBundle = { ...sellerBundleUnsigned, signature: Buffer.from(sellerSig).toString('base64') };
  log(`✓ DACS-5 both bundles built + signed`);

  // ─── 5. Verify both sides via the same library the CLI uses ───────────────────
  const buyerVerdict = await verifyBundle(buyerBundle, {
    counterpartyBundle: sellerBundle,
    // skipTwoSidedLookup undefined; counterparty path is used because we supplied counterpartyBundle
  });
  const sellerVerdict = await verifyBundle(sellerBundle, {
    counterpartyBundle: buyerBundle,
  });

  log('');
  log('───── RESULTS ─────');
  log(`buyer-side verdict:  ${buyerVerdict.decision}`);
  log(`seller-side verdict: ${sellerVerdict.decision}`);
  log(`scope honesty marker:  ${dahrAttestation.type}`);
  log(`buyer bundleHash:    ${buyerVerdict.canonicalBundleHash.slice(0, 16)}…`);
  log(`seller bundleHash:   ${sellerVerdict.canonicalBundleHash.slice(0, 16)}…`);
  log('');

  // The expected v0.2 outcome is `indeterminate` — the §7.5.1 invariant in action:
  // stub attestations (dahr-stub:) MUST NOT pass at the top level until a real
  // validator-quorum DAHR (v0.3) wraps the underlying fetch. The example
  // EXPLICITLY ASSERTS both verdicts equal 'indeterminate' so any future
  // regression that accidentally collapses dahr-stub: to pass is caught here.
  const buyerStepFails = buyerVerdict.steps.some(s => s.outcome === 'fail');
  const sellerStepFails = sellerVerdict.steps.some(s => s.outcome === 'fail');

  if (buyerStepFails || sellerStepFails) {
    console.log('csv-class: FAIL — at least one step failed (real bug)');
    console.log(`  buyer steps:  ${JSON.stringify(buyerVerdict.steps.map(s => `${s.outcome}:${s.step}`))}`);
    console.log(`  seller steps: ${JSON.stringify(sellerVerdict.steps.map(s => `${s.outcome}:${s.step}`))}`);
    process.exit(1);
  }

  if (buyerVerdict.decision !== 'indeterminate' || sellerVerdict.decision !== 'indeterminate') {
    console.log(`csv-class: FAIL — §7.5.1 invariant regression`);
    console.log(`  expected verdict=indeterminate for both sides (dahr-stub: attestations have no validator quorum)`);
    console.log(`  got: buyer=${buyerVerdict.decision} seller=${sellerVerdict.decision}`);
    console.log(`  This means dahr-stub: was silently coerced to pass — a real bug, fix it.`);
    process.exit(1);
  }

  // Both verdicts are correctly 'indeterminate' and no steps failed.
  console.log('csv-class: OK — full loop ran cleanly; verdict=indeterminate as expected for v0.2 stub scope');
  console.log('  (§7.5.1 invariant survives end-to-end; pass requires v0.3 validator-quorum DAHR)');
  process.exit(0);
}

main().catch(e => {
  console.error('csv-class: ERROR', e);
  process.exit(2);
});
