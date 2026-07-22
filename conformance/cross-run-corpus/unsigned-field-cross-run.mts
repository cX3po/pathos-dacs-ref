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

const FAMILIES = new Set(['pair', 'mixed', 'pointer', 'direct']);
const DISPOSITIONS = new Set(['present', 'fail', 'indeterminate']);
const TRIPLES = new Set(['pristine', 'mutated', 'control']);
// The COMPLETE set of keys a vector may carry. Any other key is a misspelling — and a misspelled
// SCORING key (reachble, pathosBasline, …) silently drops a vector from strict scoring, the exact
// laundering-by-omission class Codex mined across finding D + its residual (2026-07-22). An unknown-key
// guard closes the ENTIRE misspelling class in one rule rather than enumerating each field's typo.
const ALLOWED_KEYS = new Set([
  'name', 'family', 'field', 'triple', 'expected', 'reachable', 'pathosBaseline', 'provenance',
  'copies', 'pointer', 'dereferenced', 'binding', 'request', 'bindings', 'anchored', 'budget',
]);

/**
 * Validate a vector's runtime METADATA before scoring (Codex 2026-07-22, findings D + residual). A
 * malformed, misspelled, or omitted scoring key must NOT silently drop the vector out of strict
 * scoring: a typo'd `reachble: true` reads as `reachable === undefined` (falsy) → REF-ONLY → ignored by
 * --strict; a misspelled/absent `pathosBaseline` on a reference-only vector likewise drops it. This is
 * the same laundering-by-omission class the set targets — closed here by scoring any metadata-invalid
 * vector as ERROR (which fails --strict). Returns an error string, or null if valid.
 */
export function metaError(vector: Json): string | null {
  // (1) unknown-key guard — catches ANY misspelled key (reachble, pathosBasline, …) comprehensively.
  for (const k of Object.keys(vector)) {
    if (!ALLOWED_KEYS.has(k)) return `unknown key "${k}" (possible misspelling of a scoring field → silent scope removal)`;
  }
  // (2) required scoring fields + enums.
  if (typeof vector.name !== 'string' || vector.name.length === 0) return `missing/invalid "name"`;
  if (!FAMILIES.has(vector.family)) return `invalid "family" ${JSON.stringify(vector.family)}`;
  if (typeof vector.reachable !== 'boolean') return `"reachable" must be boolean, got ${JSON.stringify(vector.reachable)}`;
  if (!DISPOSITIONS.has(vector.expected)) return `invalid "expected" disposition ${JSON.stringify(vector.expected)}`;
  if (vector.triple !== undefined && !TRIPLES.has(vector.triple)) return `invalid "triple" ${JSON.stringify(vector.triple)}`;
  // (3) a reference-only vector is scored ONLY via pathosBaseline; require a valid one so a missing (not
  //     just misspelled) baseline can't drop it from --strict. All committed ref-only vectors have one.
  if (vector.reachable === false) {
    if (!DISPOSITIONS.has(vector.pathosBaseline)) return `reference-only vector requires a valid "pathosBaseline" (got ${JSON.stringify(vector.pathosBaseline)}) — a missing/misspelled baseline silently drops it from strict scoring`;
  } else if (vector.pathosBaseline !== undefined && !DISPOSITIONS.has(vector.pathosBaseline)) {
    return `invalid "pathosBaseline" ${JSON.stringify(vector.pathosBaseline)}`;
  }
  return null;
}

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
      // An unknown/misspelled family means NO resolver ran — it must NOT be laundered into a 'fail'
      // disposition that could score AGREE against a vector whose expected==='fail' and pass --strict
      // on zero resolver coverage (Codex 2026-07-22). Throw so the cross-run's catch scores it ERROR,
      // which fails --strict independently of disposition (same guard as a thrown resolver exception).
      throw new Error(`unknown vector family "${vector.family}" — no resolver ran (not a disposition)`);
  }
}

type Row = { id: string; field: string; triple: string; reachable: boolean; expected: string; ours: string; result: string; detail: string };

// Result taxonomy:
//   AGREE / DIVERGE   — reachable vector: our resolver matched / missed its `expected` disposition.
//   BASELINE-OK/DRIFT — reference-only vector (reachable:false): our resolver does NOT consume this
//                       field, so the vector can't assert `expected` against us — instead a valid
//                       `pathosBaseline` (REQUIRED for every reachable:false vector; metaError rejects a
//                       missing/misspelled one as ERROR) pins the disposition our resolver DOES return (a
//                       safe non-`present`). A future change that makes the un-consumed field silently
//                       swing our verdict (e.g. adding bundleCount consumption without a reject-bool
//                       guard) drifts off the pin and turns it RED.
//   REF-ONLY          — defensive-only: unreachable now for a metadata-valid corpus (every reachable:false
//                       vector must carry a pathosBaseline), retained so the scorer never trusts a bare drop.

function main(): void {
const here = dirname(fileURLToPath(import.meta.url));
const file = join(here, 'dacs248', 'unsigned-field-laundering-v0.1.json');
const corpus = JSON.parse(readFileSync(file, 'utf8')) as Corpus;
const rows: Row[] = [];
for (const vector of corpus.vectors) {
  let resolution: BundleBindingResolution;
  let threw = false;
  const metaErr = metaError(vector);
  if (metaErr) {
    // Malformed scoring metadata → ERROR (fails --strict), never a silent drop out of scoring.
    threw = true;
    resolution = { disposition: 'fail', detail: `malformed vector metadata: ${metaErr}` };
  } else {
    try {
      resolution = resolveVector(corpus, vector);
    } catch (error) {
      threw = true;
      resolution = { disposition: 'fail', detail: `cross-run exception: ${error instanceof Error ? error.message : String(error)}` };
    }
  }
  // A THROWN resolver exception is its OWN failure mode (ERROR) — it must NEVER be laundered into a
  // 'fail' disposition that happens to match a vector whose expected==='fail' (that would score AGREE
  // and pass --strict on a crash). ERROR fails strict mode independently of disposition matching
  // (Codex 2026-07-22). Takes precedence over reachable/ref-only scoring for any vector.
  const result = threw
    ? 'ERROR'
    : !vector.reachable
      ? (typeof vector.pathosBaseline === 'string'
          ? (resolution.disposition === vector.pathosBaseline ? 'BASELINE-OK' : 'BASELINE-DRIFT')
          : 'REF-ONLY')
      : vector.expected === resolution.disposition ? 'AGREE' : 'DIVERGE';
  rows.push({
    // Coerce display fields to strings: a metadata-malformed vector (ERROR) may be MISSING name/field/
    // triple, and a raw undefined would crash `.padEnd()` during rendering and swallow the ERROR summary
    // (Codex 2026-07-22, diagnostics-only). Strict exit is already correct; this keeps the report legible.
    id: String(vector.name ?? '<unnamed>'),
    field: String(vector.field ?? ''),
    triple: String(vector.triple ?? ''),
    reachable: vector.reachable === true,
    expected: String(vector.expected ?? ''),
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
const errors = rows.filter((r) => r.result === 'ERROR');
const baselinePinned = rows.filter((r) => r.result === 'BASELINE-OK' || r.result === 'BASELINE-DRIFT');
const baselineDrift = rows.filter((r) => r.result === 'BASELINE-DRIFT');
const refOnly = rows.filter((r) => r.result === 'REF-ONLY').length;
console.log(`\nREACHABLE ${reachable.length}  AGREE ${agree}  DIVERGE ${diverge.length}  ERROR ${errors.length}   |   baseline-pinned ${baselinePinned.length} (drift ${baselineDrift.length})   |   reference-only ${refOnly}`);
for (const r of diverge) {
  console.log(`DIVERGENCE ${r.id}: expected=${r.expected} ours=${r.ours} — ${r.detail}`);
}
for (const r of errors) {
  console.log(`ERROR ${r.id}: resolver THREW (not a disposition) — ${r.detail}`);
}
for (const r of baselineDrift) {
  console.log(`BASELINE-DRIFT ${r.id}: pinned=${(corpus.vectors.find((v) => v.name === r.id) || {}).pathosBaseline} ours=${r.ours} — an un-consumed field silently swung our verdict; ${r.detail}`);
}
// Standalone, a cross-run is an evidence report: divergence is DATA, not process failure (exit 0),
// mirroring dacs248-cross-run.mts. But when embedded in the aggregate convergence suite
// (convergence-suite.mts), the suite's contract is "exit 0 ⟺ converged" — so it registers us with
// --strict, under which a REACHABLE divergence (an undocumented resolver disagreement, since every
// reachable vector's `expected` is baked into the JSON), a BASELINE-DRIFT (an un-consumed field that
// silently swung our resolver's verdict away from its pinned safe disposition), OR an ERROR (the
// resolver threw on any vector — a crash must never pass strict mode, even if the caught 'fail'
// disposition happens to match) exits non-zero and turns the suite RED. Without --strict any of these
// would exit 0 and the suite would paint a real hole green.
const strict = process.argv.includes('--strict');
process.exitCode = strict && (diverge.length > 0 || baselineDrift.length > 0 || errors.length > 0) ? 1 : 0;
}

// Run the standalone report only when invoked as the entry module (not when imported for resolveVector).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
