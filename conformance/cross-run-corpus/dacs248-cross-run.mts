#!/usr/bin/env tsx
/** Second-implementation cross-run for the DACS-Standard #248 candidate vectors. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../../src/jcs.js';
import {
  deriveBundleLogicalAddress,
  resolveBundleBinding,
  resolveFaultBundlePointer,
  resolveFaultBundlePair,
  resolveMixedVersionPair,
  type BundleBindingRequest,
  type BundleBindingResolution,
  type BundleBindingV1,
  type BundleBindingRole,
} from '../../src/lib/bundle-binding-v1.js';

type JsonObject = Record<string, any>;
type Corpus = { set: string; publicKeys: Record<string, string>; vectors: JsonObject[] };
const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(here, 'dacs248');
const files = [
  'bundle-binding-v0.1.json',
  'outsider-binding-flooding-v0.3.json',
  'receipt-rederivation-v0.3.json',
  // #248 round-13 FaultAttestationBundle families.
  'fab-bundle-extended-pointer-v0.3.json',
  'fault-bundle-perspective-pair-v0.3.json',
  'mixed-version-reconciliation-v0.3.json',
] as const;

/** #248 round-13 §10.4.2 extended-pointer path — the vector carries pointer/dereferenced/binding. */
function pointerVector(corpus: Corpus, vector: JsonObject): BundleBindingResolution {
  return resolveFaultBundlePointer({
    publicKeys: corpus.publicKeys,
    pointer: vector.pointer,
    dereferenced: vector.dereferenced,
    binding: vector.binding,
  });
}

/** #248 round-13 §10.4.3 FAB perspective-pair — the vector carries a role->copy map. */
function pairVector(corpus: Corpus, vector: JsonObject): BundleBindingResolution {
  return resolveFaultBundlePair({ publicKeys: corpus.publicKeys, copies: vector.copies });
}

/** #248 round-13 §10.4.3 mixed-version reconciliation — the vector carries a role->copy map. */
function mixedVector(corpus: Corpus, vector: JsonObject): BundleBindingResolution {
  return resolveMixedVersionPair({ publicKeys: corpus.publicKeys, copies: vector.copies });
}
function directVector(corpus: Corpus, vector: JsonObject): BundleBindingResolution {
  const anchored = vector.anchored ?? {};
  const request: BundleBindingRequest = {
    ...vector.request,
    publicKeys: corpus.publicKeys,
    partyMap: vector.partyMap,
    budget: vector.budget,
  };
  return resolveBundleBinding(request, vector.bindings ?? [], (nativeAddress) => anchored[nativeAddress]);
}

function canonicalBundleScope(bundle: JsonObject): string {
  const { signatures: _signatures, anchoredByRole: _anchoredByRole, ...scope } = bundle;
  return Buffer.from(jcsCanonical(scope)).toString('base64');
}

function contentHash(value: unknown): string {
  return Buffer.from(sha256(jcsCanonical(value))).toString('hex');
}

function rosterMap(bundle: JsonObject): Record<string, string> {
  return Object.fromEntries((bundle.parties ?? []).map((party: JsonObject) => [party.primaryClaim, party.role]));
}

/**
 * The receipt corpus is a replay corpus, not a top-level BundleBinding corpus.  Its replay
 * adapter invokes resolveBundleBinding for every carried BB-6 context, then applies the
 * receipt-only §10.5 relations that are outside BB-1..BB-8.
 */
function receiptVector(corpus: Corpus, vector: JsonObject): BundleBindingResolution {
  const derivation = vector.derivation ?? (vector.taggedBundles ? {
    replayableDerivationVersion: '1',
    bundleRefs: vector.taggedBundles.map((tagged: JsonObject) => ({ contentHash: contentHash(tagged.bundle) })),
    resolutionContext: vector.taggedBundles.map((tagged: JsonObject) => ({
      contentHash: contentHash(tagged.bundle),
      ...tagged,
    })),
  } : undefined);
  if (!derivation || derivation.replayableDerivationVersion !== '1' || derivation.derivationVersion !== undefined) {
    return { disposition: 'fail', detail: '§10.5: unsupported or ambiguous derivation discriminator' };
  }
  if (!Array.isArray(derivation.bundleRefs) || !Array.isArray(derivation.resolutionContext)) {
    return { disposition: 'fail', detail: '§10.5.3: bundleRefs/resolutionContext missing' };
  }
  const refs = derivation.bundleRefs.map((ref: string | JsonObject) =>
    typeof ref === 'string' ? ref : ref.contentHash);
  const contexts = derivation.resolutionContext;
  if (refs.length !== contexts.length || refs.some((hash: string) =>
    contexts.filter((context: JsonObject) => context.contentHash === hash).length !== 1)) {
    return { disposition: 'fail', detail: '§10.5.3: resolutionContext is not keyed one-for-one' };
  }

  const deref = vector.derefBundles ?? Object.fromEntries(
    (vector.taggedBundles ?? []).flatMap((tagged: JsonObject) => {
      const entries: Array<[string, JsonObject]> = [[contentHash(tagged.bundle), tagged.bundle]];
      const counterparty = tagged.counterpartyRef?.contentHash;
      if (counterparty && vector.derefBundles?.[counterparty]) entries.push([counterparty, vector.derefBundles[counterparty]]);
      return entries;
    }),
  );
  for (const context of contexts) {
    const binding = context.roleEvidence?.binding;
    const candidates: BundleBindingV1[] | undefined = context.bb6Context?.candidateBindings;
    if (!binding || !Array.isArray(candidates) || candidates.length === 0) {
      return { disposition: 'fail', detail: '§10.5 Replay (1)/(2): role evidence or BB-6 context missing' };
    }
    if (candidates.some((candidate) => candidate.jobId !== binding.jobId || candidate.role !== binding.role ||
      candidate.logicalAddress !== deriveBundleLogicalAddress(binding.jobId, binding.role))) {
      return { disposition: 'fail', detail: '§10.5 Replay (2): carried candidate fails BB-5 requested-tuple checks' };
    }
    const winnerBundle = deref[binding.bundleContentHash] ?? context.bundle;
    const authenticatedRoster = winnerBundle ? rosterMap(winnerBundle) : {};
    const partyMap = context.bb6Context.partyMap ?? {};
    if (Object.entries(partyMap).some(([claim, role]) => authenticatedRoster[claim] !== role)) {
      return { disposition: 'fail', detail: '§10.5 Replay (2): party map contradicts authenticated roster' };
    }
    // Replay requires every mapped/authorized candidate to be dereferenceable.  A fetched
    // hash-mismatching object remains present so the resolver can apply BB-5 check 8 (inert).
    if (candidates.some((candidate) => partyMap[String(candidate.signer)] === candidate.role &&
      deref[candidate.bundleContentHash] === undefined && candidate.nativeAddress !== binding.nativeAddress)) {
      return { disposition: 'fail', detail: '§10.5 Replay (2): authorized competitor is unfetchable' };
    }
    const request: BundleBindingRequest = {
      jobId: binding.jobId,
      role: binding.role as BundleBindingRole,
      publicKeys: corpus.publicKeys,
      partyMap,
      budget: context.bb6Context.budget,
    };
    const resolution = resolveBundleBinding(request, candidates, (_native, candidate) =>
      deref[candidate.bundleContentHash] ?? (candidate.nativeAddress === binding.nativeAddress ? context.bundle : undefined));
    if (resolution.disposition !== 'present' || resolution.resolvedNativeAddress !== binding.nativeAddress) {
      return { disposition: 'fail', detail: `§10.5 Replay (1)/(2): BB-6 did not reproduce winner (${resolution.detail})` };
    }

    if (context.counterpartyDisposition === 'present') {
      const ref = context.counterpartyRef;
      const counterBinding = context.counterpartyRoleEvidence?.binding;
      const counterBundle = ref && deref[ref.contentHash];
      if (!ref || !counterBinding || !counterBundle) {
        return { disposition: 'fail', detail: '§10.5 Replay (3): counterparty evidence missing' };
      }
      const counter = resolveBundleBinding({
        jobId: counterBinding.jobId,
        role: counterBinding.role,
        publicKeys: corpus.publicKeys,
        partyMap: rosterMap(counterBundle),
      }, [counterBinding], () => counterBundle);
      if (counter.disposition !== 'present' || counter.resolvedNativeAddress !== counterBinding.nativeAddress) {
        return { disposition: 'fail', detail: '§10.5 Replay (3): counterparty role authentication failed' };
      }
      const authoritative = resolution.bundle as JsonObject;
      // Per-copy finalisation time and anchored role may differ.  Material event fields may not.
      if (authoritative.jobId !== counterBundle.jobId || authoritative.outcome !== counterBundle.outcome ||
          authoritative.faultedParty !== counterBundle.faultedParty ||
          canonicalBundleScope({ ...authoritative, finalisedAt: 0 }) !== canonicalBundleScope({ ...counterBundle, finalisedAt: 0 })) {
        return { disposition: 'fail', detail: '§10.5 Replay (3): counterparty copies materially diverge' };
      }
    } else if (context.counterpartyDisposition === 'absent') {
      const ref = context.absenceEvidenceRef;
      const absenceBinding = context.absenceBinding;
      const evidence = ref && vector.absenceEvidence?.[ref.contentHash];
      if (!ref || !absenceBinding || !evidence || contentHash(evidence) !== ref.contentHash ||
          absenceBinding.nativeAddress !== evidence.nativeAddress) {
        return { disposition: 'fail', detail: '§10.5 Replay (4): absence evidence relation invalid' };
      }
      // Exercise BB-4/BB-5 on the authoritative-absence binding.  Non-resolution is expected;
      // CORE §5 absence evidence, checked above, is what upgrades that fact for receipt replay.
      resolveBundleBinding({
        jobId: absenceBinding.jobId,
        role: absenceBinding.role,
        publicKeys: corpus.publicKeys,
      }, [absenceBinding], () => undefined);
    } else {
      return { disposition: 'fail', detail: '§10.5: missing counterparty disposition' };
    }
  }
  return { disposition: 'present', detail: '§10.5 replay reproduced all BundleBinding selections and receipt relations' };
}

const rows: Array<{ id: string; expected: string; ours: string; result: string; detail: string }> = [];
for (const filename of files) {
  const corpus = JSON.parse(readFileSync(join(corpusDir, filename), 'utf8')) as Corpus;
  for (const vector of corpus.vectors) {
    let resolution: BundleBindingResolution;
    try {
      if (corpus.set === 'fab-bundle-extended-pointer-v0.3') {
        resolution = pointerVector(corpus, vector);
      } else if (corpus.set === 'fault-bundle-perspective-pair-v0.3') {
        resolution = pairVector(corpus, vector);
      } else if (corpus.set === 'mixed-version-reconciliation-v0.3') {
        resolution = mixedVector(corpus, vector);
      } else {
        resolution = vector.request ? directVector(corpus, vector) : receiptVector(corpus, vector);
      }
    } catch (error) {
      resolution = { disposition: 'fail', detail: `cross-run exception: ${error instanceof Error ? error.message : String(error)}` };
    }
    const expected = vector.expected === 'pass' ? 'present' : vector.expected;
    rows.push({
      id: `${corpus.set}/${vector.name}`,
      expected,
      ours: resolution.disposition,
      result: expected === resolution.disposition ? 'AGREE' : 'DIVERGE',
      detail: resolution.detail,
    });
  }
}

const idWidth = Math.max('id'.length, ...rows.map((row) => row.id.length));
console.log(`${'id'.padEnd(idWidth)}  expected       ours           result`);
console.log(`${'-'.repeat(idWidth)}  -------------  -------------  -------`);
for (const row of rows) {
  console.log(`${row.id.padEnd(idWidth)}  ${row.expected.padEnd(13)}  ${row.ours.padEnd(13)}  ${row.result}`);
}
const agreements = rows.filter((row) => row.result === 'AGREE').length;
console.log(`\nTOTAL ${rows.length}  AGREE ${agreements}  DIVERGE ${rows.length - agreements}`);
for (const row of rows.filter((candidate) => candidate.result === 'DIVERGE')) {
  console.log(`DIVERGENCE ${row.id}: ${row.detail}`);
}
// A cross-run is an evidence report.  Divergence is data, never process failure.
process.exitCode = 0;
