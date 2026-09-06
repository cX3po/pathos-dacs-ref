import { test } from 'node:test';
import assert from 'node:assert/strict';
import { main, parameterHash, parseBundleKind, DacsTestnetRefusal, type DacsTestnetConfig } from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';

const config = (overrides: Partial<DacsTestnetConfig> = {}): DacsTestnetConfig => ({
  jobId: 'kind-job', mode: 'dry-run', organ: 'nws_alerts', query: '35.2271,-80.8431',
  priceDem: '1', spendCapDem: 50, rpc: 'https://demosnode.discus.sh/', ...overrides,
});

test('the bundle kind is a session parameter: it changes the dry-run hash and anything else is a configuration refusal', () => {
  const base = parameterHash(config());
  assert.equal(base, parameterHash(config({ bundleKind: 'ebfab' })), 'the default form and the explicit default hash alike');
  assert.notEqual(base, parameterHash(config({ bundleKind: 'fab' })), 'the standard form is a different session');
  assert.equal(parseBundleKind('fab'), 'fab');
  assert.equal(parseBundleKind('ebfab'), 'ebfab');
  for (const junk of ['FAB', 'fault', '', 'ebfab ']) {
    assert.throws(() => parseBundleKind(junk), (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'config', junk);
  }
});

async function dryRunAnchoredBundles(env: NodeJS.ProcessEnv): Promise<Array<Record<string, unknown>>> {
  let state: Map<string, unknown> | undefined;
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], env, (run) => {
      const deps = createDryRunDependencies(run);
      state = deps.fixtureState.byNative;
      return deps;
    });
    assert.equal(exit, 0);
  } finally {
    process.stdout.write = out;
  }
  return [...(state ?? new Map()).values()].filter((v): v is Record<string, unknown> =>
    typeof v === 'object' && v !== null && 'anchoredByRole' in (v as Record<string, unknown>));
}

test('DACS_BUNDLE_KIND=fab finalizes DACS-5 FaultAttestationBundle copies; the default stays the evidence-bound form', async () => {
  const standard = await dryRunAnchoredBundles({ DACS_BUNDLE_KIND: 'fab' });
  assert.ok(standard.length >= 2, 'buyer and seller copies are anchored');
  for (const bundle of standard) {
    assert.equal(bundle.faultBundleVersion, '1');
    assert.equal(bundle.evidenceBoundFaultBundleVersion, undefined);
    assert.equal(bundle.bundleVersion, undefined);
  }
  const additive = await dryRunAnchoredBundles({});
  assert.ok(additive.length >= 2);
  for (const bundle of additive) {
    assert.equal(bundle.evidenceBoundFaultBundleVersion, '1');
    assert.equal(bundle.faultBundleVersion, undefined);
  }
  // An unknown kind never reaches finalization: the CLI refuses at configuration (exit 2, typed refusal).
  const err = process.stderr.write.bind(process.stderr); const out = process.stdout.write.bind(process.stdout);
  const stderr: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fault' }, (run) => createDryRunDependencies(run));
    assert.equal(exit, 2);
  } finally {
    process.stderr.write = err; process.stdout.write = out;
  }
  assert.match(stderr.join(''), /"reason":"config"/);
});

// DACS-2 §7.5.2: an AttestationRef on the wire is exactly { anchor: { kind, locator }, contentHash, signer? }. The
// pinned dacs-sdk checks those keys exactly; LIVE attempt 7 (2026-09-06) was refused by it because our references
// carried a substrate name, a type and a producedAt. Every reference a finalized copy cites must be the spec form.
function citedRefs(bundle: Record<string, unknown>): Array<Record<string, unknown>> {
  const refs: Array<Record<string, unknown>> = [];
  if (bundle.agreementRef) refs.push(bundle.agreementRef as Record<string, unknown>);
  for (const k of ['vetRecords', 'settlementEvidence', 'amendments', 'ratingRefs']) for (const r of (bundle[k] as unknown[] | undefined) ?? []) refs.push(r as Record<string, unknown>);
  for (const ph of (bundle.phaseSummary as Array<Record<string, unknown>>) ?? []) if (ph.attestationRef) refs.push(ph.attestationRef as Record<string, unknown>);
  return refs;
}

test('every reference a finalized copy cites is the DACS-2 §7.5.2 wire form, in both bundle forms', async () => {
  for (const env of [{ DACS_BUNDLE_KIND: 'fab' }, {}]) {
    const copies = await dryRunAnchoredBundles(env);
    assert.ok(copies.length >= 2);
    let seen = 0;
    for (const copy of copies) {
      for (const ref of citedRefs(copy)) {
        seen++;
        const keys = Object.keys(ref).sort();
        assert.ok(keys.join(',') === 'anchor,contentHash' || keys.join(',') === 'anchor,contentHash,signer', `ref keys ${keys.join(',')}`);
        assert.deepEqual(Object.keys(ref.anchor as object).sort(), ['kind', 'locator']);
        assert.equal((ref.anchor as { kind: string }).kind, 'storage-program');
        assert.match(String(ref.contentHash), /^[0-9a-f]{64}$/);
      }
    }
    assert.ok(seen >= 4, `cited references seen: ${seen}`);
  }
});

// DACS-5: the bundle's agreementRef cites the anchored DACS-3 AgreementDocument (the pinned dacs-sdk reads it as
// dacs-3-agreement and checks its parties against the bundle). The finality commitment our ST-11 refetch verifies
// travels on the session as commitmentRef and is not what the bundle cites.
test('a finalized copy cites the anchored agreement document, not the finality commitment', async () => {
  const { jcsHashHex } = await import('../../src/jcs.js');
  let store: Map<string, unknown> | undefined;
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fab' }, (run) => { const deps = createDryRunDependencies(run); store = deps.fixtureState.byNative; return deps; });
    assert.equal(exit, 0);
  } finally { process.stdout.write = out; }
  const entries = [...(store ?? new Map()).values()].filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null);
  const bundles = entries.filter((v) => 'anchoredByRole' in v);
  assert.ok(bundles.length >= 2);
  const commitments = entries.filter((v) => typeof v.agreementHash === 'string' && !('anchoredByRole' in v));
  assert.equal(commitments.length, 1, 'one finality commitment record is anchored');
  for (const bundle of bundles) {
    const ref = bundle.agreementRef as { anchor: { kind: string; locator: string }; contentHash: string };
    assert.equal(ref.anchor.kind, 'storage-program');
    const cited = store!.get(ref.anchor.locator) as Record<string, unknown> | undefined;
    assert.ok(cited, 'the cited locator resolves in the store');
    assert.equal(cited!.agreementVersion, '1', 'the cited artifact is the DACS-3 AgreementDocument');
    assert.equal(cited!.jobId, bundle.jobId);
    assert.equal((cited!.signatures as unknown[]).length, 2, 'both parties signed the cited document');
    const { signatures: _sigs, ...unsignedCited } = cited as Record<string, unknown>; void _sigs;
    assert.equal(ref.contentHash, jcsHashHex(unsignedCited), 'DACS-2 §7.5.2: contentHash covers the signature-excluded document');
    for (const party of cited!.parties as Array<{ vetRecordRef: { anchor: { locator: string }; contentHash: string } }>) {
      const composite = store!.get(party.vetRecordRef.anchor.locator) as Record<string, unknown>;
      assert.equal(composite.recordVersion, '1', 'DACS-3 §8.5: the party cites a DACS-2 composite record');
      const { signature: _cs, ...unsignedComposite } = composite; void _cs;
      assert.equal(party.vetRecordRef.contentHash, jcsHashHex(unsignedComposite), 'the citation hashes the signature-excluded composite');
    }
    for (const ev of bundle.settlementEvidence as Array<{ anchor: { locator: string }; contentHash: string }>) {
      const record = store!.get(ev.anchor.locator) as Record<string, unknown>;
      const { signature: _sig, ...unsignedRecord } = record; void _sig;
      assert.equal(ev.contentHash, jcsHashHex(unsignedRecord), 'evidence references hash the signature-excluded record');
    }
    assert.notEqual(cited, commitments[0], 'the commitment is not the cited artifact');
  }
});

// DACS-5: the payment phase's summary entry carries the settlement's ChainTxRefs, the same arms the evidence record carries;
// the pinned dacs-sdk's Agent verifies a successful payment phase's evidence against exactly that entry (Agent.ts verifyEvidence).
test('a finalized copy\'s payment phase entry carries txRefs equal to the evidence record\'s ChainTxRef arms, and every settlement phase entry cites its evidence', async () => {
  let store: Map<string, unknown> | undefined;
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fab' }, (run) => { const deps = createDryRunDependencies(run); store = deps.fixtureState.byNative; return deps; });
    assert.equal(exit, 0);
  } finally { process.stdout.write = out; }
  const bundles = [...(store ?? new Map()).values()].filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null && 'anchoredByRole' in v);
  assert.ok(bundles.length >= 2);
  for (const bundle of bundles) {
    const phases = bundle.phaseSummary as Array<{ index: number; kind: string; txRefs?: unknown[]; attestationRef?: { anchor: { locator: string } } }>;
    const pay = phases.find((p) => p.kind === 'pay-dem')!, deliver = phases.find((p) => p.kind === 'deliver-storage-program')!;
    assert.ok(pay.attestationRef && deliver.attestationRef, 'settlement phases cite their evidence');
    const evidence = store!.get(pay.attestationRef!.anchor.locator) as { paymentTxRefs: unknown[] };
    assert.deepEqual(pay.txRefs, evidence.paymentTxRefs, 'txRefs are the evidence record\'s ChainTxRef arms');
    assert.equal((pay.txRefs as Array<{ kind: string }>)[0]!.kind, 'demos');
    assert.equal(deliver.txRefs, undefined);
  }
});

// DACS-1 §6.3.4: the published listing is the Standard's Listing (the pinned dacs-sdk's isListing shape), with the seller's own
// identity bundle presented per-claim (§6.3.2) and the program named in the SDK's form so its Agent resolves it by (owner, name).
test('the dry-run listing is a DACS-1 Listing: Standard members only, a per-claim seller presentation that verifies, the pay step bound to its rail, and the SDK-form program name', async () => {
  const { verifyDomainHashAgentSignature } = await import('../../src/adapters/demos/identity.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { listingLogicalAddress } = await import('../../src/dacs1/addressing.js');
  const { sdkListingProgramName } = await import('../../src/live/listing-wire.js');
  const { jcsHashHex } = await import('../../src/jcs.js');
  let state: { byNative: Map<string, unknown>; byLogical: Map<string, unknown> } | undefined;
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fab' }, (run) => { const deps = createDryRunDependencies(run); state = deps.fixtureState; return deps; });
    assert.equal(exit, 0);
  } finally { process.stdout.write = out; }
  const entries = [...state!.byNative.values()].filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null);
  const listing = entries.find((v) => v.dacsVersion === '1' && typeof v.listingId === 'string')!;
  assert.ok(listing, 'a DACS-1 listing is anchored');
  assert.deepEqual(Object.keys(listing).sort(), ['acceptedRails', 'buyerRequirement', 'dacsVersion', 'listingId', 'listingVersion', 'logical_address', 'offering', 'pipeline', 'pricing', 'seller', 'signature', 'terms', 'validity']);
  // DACS-1-IDENTIFY §6.3.4(b): the anchored record carries its CF-4 logical address, inside the signed scope, equal to the address derived from the tuple.
  assert.equal(listing.logical_address, listingLogicalAddress((listing.seller as { identity: { presentedBy: string } }).identity.presentedBy, listing.listingId as string, listing.listingVersion as number));
  const seller = listing.seller as { identity: Record<string, unknown>; displayName: string };
  const identity = seller.identity as { bundleVersion: string; presentedBy: string; presentedAt: number; claims: Array<{ ref: string }>; presentation: { kind: string; signatures: Array<{ ref: string; signature: string }> } };
  const signature = listing.signature as { signer: string; algorithm: string; value: string };
  assert.equal(identity.bundleVersion, '1');
  assert.equal(identity.presentedBy, signature.signer, 'the listing signer is the presented primary claim');
  assert.deepEqual(identity.claims, [{ ref: identity.presentedBy }]);
  assert.equal(identity.presentation.kind, 'per-claim');
  const { presentation: _p, ...bundleScope } = identity; void _p;
  const entry = identity.presentation.signatures[0]!;
  assert.equal(entry.ref, identity.presentedBy);
  assert.equal(verifyDomainHashAgentSignature(identity.presentedBy as `${string}:${string}`, DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, jcsHashHex(bundleScope), Buffer.from(entry.signature, 'base64url')), true, 'the wallet signed dacs-bundle-presentation:v1: || bundle_hash');
  const { signature: _s, ...unsignedListing } = listing; void _s;
  assert.equal(verifyDomainHashAgentSignature(signature.signer as `${string}:${string}`, DOMAIN_SEPARATORS.LISTING, jcsHashHex(unsignedListing), Buffer.from(signature.value, 'base64url')), true);
  const pipeline = listing.pipeline as Array<{ kind: string; parameters?: { rail?: string } }>;
  const pay = pipeline.find((p) => p.kind === 'pay-dem')!;
  assert.equal(pay.parameters?.rail, 'pay-dem');
  assert.ok((listing.acceptedRails as Array<{ railId: string }>).some((r) => r.railId === pay.parameters!.rail), 'LRR-1: the pay step names an accepted rail');
  assert.equal((listing.offering as { deliverable: { kind: string } }).deliverable.kind, 'storage-program');
  assert.equal((listing.buyerRequirement as { requirementVersion: string }).requirementVersion, '1');
  const validity = listing.validity as { notBefore: number; notAfter?: number };
  assert.ok(Number.isSafeInteger(validity.notBefore) && (validity.notAfter === undefined || validity.notAfter >= validity.notBefore));
  // The bundle's ListingPin hashes the signature-excluded listing, and the program is named as the SDK derives it from the seller claim.
  const bundles = entries.filter((v) => 'anchoredByRole' in v);
  for (const bundle of bundles) assert.equal((bundle.listingRef as { contentHash: string }).contentHash, jcsHashHex(unsignedListing));
  const logical = listingLogicalAddress(identity.presentedBy, listing.listingId as string, listing.listingVersion as number);
  assert.ok(state!.byLogical.has(sdkListingProgramName(logical)), `anchored under ${sdkListingProgramName(logical)}`);
  assert.ok(!sdkListingProgramName(logical).includes(':'), 'colon-free program name');
});

// DACS-2 §7.5 / §7.7 and DACS-3 §8.5: the vet phase anchors, per party, a self-signed VerifyResult signed by the counterparty and the composite
// that evaluates it under the requirement the counterparty holds; the agreement parties cite the composites and carry the evaluated bundle hashes.
test('the vet phase anchors a counterparty-signed VerifyResult and composite per party, the agreement cites the composites, and the run result records the single-fetch outcome', async () => {
  const { verifyDomainHashAgentSignature } = await import('../../src/adapters/demos/identity.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { jcsHashHex } = await import('../../src/jcs.js');
  const { identityBundleHash, selfSignedBundleRequirement } = await import('../../src/live/listing-wire.js');
  let store: Map<string, unknown> | undefined; const chunks: string[] = [];
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((c: string | Uint8Array) => { chunks.push(String(c)); return true; }) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fab' }, (run) => { const deps = createDryRunDependencies(run); store = deps.fixtureState.byNative; return deps; });
    assert.equal(exit, 0);
  } finally { process.stdout.write = out; }
  const result = JSON.parse(chunks.join('').trim().split('\n').pop()!);
  assert.equal(result.verification.vet.outcome, 'pass');
  assert.deepEqual(result.verification.vet.records, { buyer: { method: 'self-signed', decision: 'pass', composite: 'pass' }, seller: { method: 'self-signed', decision: 'pass', composite: 'pass' } });
  assert.equal(result.verification.vet.singleFetch.trustLevel, 'not-applicable'); assert.equal(result.verification.vet.singleFetch.executed, false);
  const entries = [...store!.values()].filter((v): v is Record<string, unknown> => typeof v === 'object' && v !== null);
  const agreement = entries.find((v) => v.agreementVersion === '1')!;
  const listing = entries.find((v) => v.dacsVersion === '1' && v.listingVersion !== undefined)!;
  const buyerBundle = entries.find((v) => v.bundleVersion === '1' && v.presentedBy !== (listing.seller as { identity: { presentedBy: string } }).identity.presentedBy)!;
  assert.ok(buyerBundle, 'the buyer anchored the identity bundle it presented');
  const claimOf = (role: string) => (agreement.parties as Array<{ role: string; primaryClaim: string }>).find((p) => p.role === role)!.primaryClaim;
  for (const party of agreement.parties as Array<{ role: 'buyer' | 'seller'; primaryClaim: string; bundleHash: string; vetRecordRef: { anchor: { locator: string }; contentHash: string; signer?: string } }>) {
    const counterparty = claimOf(party.role === 'buyer' ? 'seller' : 'buyer');
    const composite = store!.get(party.vetRecordRef.anchor.locator) as Record<string, unknown>;
    assert.ok(composite, `${party.role} composite resolves`);
    assert.deepEqual(Object.keys(composite).sort(), ['bundleHash', 'dealSpecific', 'evaluatedParty', 'freshness', 'generatedAt', 'jobId', 'overallDecision', 'recordVersion', 'requirementHash', 'signature', 'supplementary'], 'exact §7.7 wire keys');
    assert.equal(composite.jobId, result.jobId); assert.equal(composite.evaluatedParty, party.primaryClaim); assert.equal(composite.overallDecision, 'pass');
    const evaluatedBundle = party.role === 'seller' ? (listing.seller as { identity: Record<string, unknown> }).identity : buyerBundle;
    assert.equal(composite.bundleHash, identityBundleHash(evaluatedBundle as never), 'the composite binds the identity bundle the party presented');
    assert.equal(party.bundleHash, composite.bundleHash, 'the agreement party carries the evaluated bundle hash');
    const requirement = party.role === 'buyer' ? listing.buyerRequirement : selfSignedBundleRequirement('did');
    assert.equal(composite.requirementHash, jcsHashHex(requirement), party.role === 'buyer' ? 'the buyer is evaluated under the listing buyerRequirement' : 'the seller is evaluated under the buyer self-signed requirement');
    const { signature: cSig, ...cScope } = composite as { signature: { signer: string; value: string } };
    assert.equal(party.vetRecordRef.contentHash, jcsHashHex(cScope)); assert.equal(party.vetRecordRef.signer, cSig.signer); assert.equal(cSig.signer, counterparty, 'the counterparty signed the composite');
    assert.equal(verifyDomainHashAgentSignature(cSig.signer as `${string}:${string}`, DOMAIN_SEPARATORS.COMPOSITE_VERIFY, jcsHashHex(cScope), Buffer.from(cSig.value, 'base64url')), true, 'signed over dacs-composite:v1:');
    const dealSpecific = composite.dealSpecific as Array<{ anchor: { kind: string; locator: string }; contentHash: string; recipeVersion: number }>;
    assert.equal(dealSpecific.length, 1); assert.deepEqual(Object.keys(dealSpecific[0]!).sort(), ['anchor', 'contentHash', 'recipeVersion']);
    const record = store!.get(dealSpecific[0]!.anchor.locator) as Record<string, unknown>;
    assert.ok(record, `${party.role} VerifyResult resolves`);
    assert.equal(record.resultVersion, '1'); assert.equal(record.method, 'self-signed'); assert.equal(record.decision, 'pass'); assert.equal(record.recipeVersion, 1);
    assert.equal(`${record.scheme}:${record.identifier}`, party.primaryClaim, 'the record names the party claim');
    const { signature, ...scope } = record as { signature: { signer: string; value: string } };
    assert.equal(dealSpecific[0]!.contentHash, jcsHashHex(scope), 'the composite cites the signature-excluded result hash');
    assert.equal(signature.signer, counterparty, 'the counterparty signed the VerifyResult');
    assert.equal(verifyDomainHashAgentSignature(signature.signer as `${string}:${string}`, DOMAIN_SEPARATORS.VERIFY_RESULT, jcsHashHex(scope), Buffer.from(signature.value, 'base64url')), true, 'signed over dacs-verifyresult:v1:');
    const attestation = record.attestation as { anchor: { locator: string }; contentHash: string };
    assert.deepEqual(Object.keys(attestation).sort(), ['anchor', 'contentHash'], 'exact AttestationRef wire keys');
    if (party.role === 'seller') assert.equal(attestation.anchor.locator, result.anchors.listing, 'the seller result attests the anchored listing');
    else assert.equal(store!.get(attestation.anchor.locator), buyerBundle, 'the buyer result attests the anchored buyer bundle');
  }
});
