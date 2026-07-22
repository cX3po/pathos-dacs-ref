#!/usr/bin/env tsx
/**
 * Cross-run for the unsigned-field / loosely-typed member laundering vector set
 * (unsigned-field-laundering-v0.1.json). Executes every REACHABLE vector against OUR resolver and
 * reports AGREE/DIVERGE per vector; reference-only (aspirational) vectors are listed but not asserted.
 *
 * This is the sibling of dacs248-cross-run.mts, scoped to the new set so it can be run standalone in
 * CI and by any second implementation (Marius's dacs-verify, the DACS-Standard reference) that loads
 * the same JSON. Divergence is DATA, not process failure (exit 0), mirroring the parent runner — but a
 * one-line summary flags any DIVERGE so it can't be missed.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import {
  resolveBundleBinding,
  resolveFaultBundlePair,
  resolveMixedVersionPair,
  resolveFaultBundlePointer,
  type BundleBindingRequest,
  type BundleBindingResolution,
  type BundleBindingRole,
} from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

type Json = Record<string, any>;
type Corpus = { set: string; publicKeys: Record<string, string>; vectors: Json[] };

export function resolveVector(corpus: Corpus, vector: Json): BundleBindingResolution {
  switch (vector.family) {
    case 'pair':
      return resolveFaultBundlePair({ publicKeys: corpus.publicKeys, copies: vector.copies });
    case 'mixed':
      return resolveMixedVersionPair({ publicKeys: corpus.publicKeys, copies: vector.copies });
    case 'pointer':
      return resolveFaultBundlePointer({
        publicKeys: corpus.publicKeys,
        pointer: vector.pointer,
        dereferenced: vector.dereferenced,
        binding: vector.binding,
      });
    case 'direct': {
      const anchored = vector.anchored ?? {};
      const request: BundleBindingRequest = {
        ...vector.request,
        publicKeys: corpus.publicKeys,
        budget: vector.budget,
      };
      return resolveBundleBinding(request, vector.bindings ?? [], (nativeAddress) => anchored[nativeAddress]);
    }
    default:
      return { disposition: 'fail', detail: `unknown family ${vector.family}` };
  }
}

type Row = { id: string; field: string; triple: string; reachable: boolean; expected: string; ours: string; result: string; detail: string };

function main(): void {
const here = dirname(fileURLToPath(import.meta.url));
const file = join(here, 'dacs248', 'unsigned-field-laundering-v0.1.json');
const corpus = JSON.parse(readFileSync(file, 'utf8')) as Corpus;
const rows: Row[] = [];
for (const vector of corpus.vectors) {
  let resolution: BundleBindingResolution;
  try {
    resolution = resolveVector(corpus, vector);
  } catch (error) {
    resolution = { disposition: 'fail', detail: `cross-run exception: ${error instanceof Error ? error.message : String(error)}` };
  }
  const result = !vector.reachable
    ? 'REF-ONLY'
    : vector.expected === resolution.disposition ? 'AGREE' : 'DIVERGE';
  rows.push({
    id: vector.name,
    field: vector.field,
    triple: vector.triple,
    reachable: vector.reachable,
    expected: vector.expected,
    ours: resolution.disposition,
    result,
    detail: resolution.detail,
  });
}

const idWidth = Math.max('vector'.length, ...rows.map((r) => r.id.length));
console.log(`set: ${corpus.set}`);
console.log(`${'vector'.padEnd(idWidth)}  field                     triple    expected       ours           result`);
console.log(`${'-'.repeat(idWidth)}  ------------------------  --------  -------------  -------------  --------`);
for (const r of rows) {
  console.log(
    `${r.id.padEnd(idWidth)}  ${r.field.padEnd(24)}  ${r.triple.padEnd(8)}  ${r.expected.padEnd(13)}  ${r.ours.padEnd(13)}  ${r.result}`,
  );
}

const reachable = rows.filter((r) => r.reachable);
const agree = reachable.filter((r) => r.result === 'AGREE').length;
const diverge = reachable.filter((r) => r.result === 'DIVERGE');
const refOnly = rows.filter((r) => !r.reachable).length;
console.log(`\nREACHABLE ${reachable.length}  AGREE ${agree}  DIVERGE ${diverge.length}   |   reference-only ${refOnly}`);
for (const r of diverge) {
  console.log(`DIVERGENCE ${r.id}: expected=${r.expected} ours=${r.ours} — ${r.detail}`);
}
// A cross-run is an evidence report. Divergence is data, never process failure.
process.exitCode = 0;
}

// Run the standalone report only when invoked as the entry module (not when imported for resolveVector).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
