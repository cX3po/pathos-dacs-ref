#!/usr/bin/env node
/**
 * partner-kit/run-conformance.mjs — execute the kit's 49 declared conformance vectors.
 *
 * NON-NORMATIVE. Passing this kit means your environment reproduces the pathos-dacs-ref
 * reference behavior on these 49 vectors — it is a conformance SANITY kit, NOT a full
 * DACS certification (no such certification exists; the normative source is the DACS spec).
 *
 * Self-contained: node >= 18, zero npm dependencies, no imports outside this directory.
 *
 * Usage:  node run-conformance.mjs [--json] [--allow-modified]
 *   --json            machine-readable report on stdout
 *   --allow-modified  skip the MANIFEST.json per-file integrity check (loud warning);
 *                     by default a hash mismatch fails closed with exit 3.
 * Exit:   0 = all 49 executed and passed · 1 = any failure/count mismatch ·
 *         2 = usage/load error · 3 = kit integrity (tamper) failure
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// SECURITY BOUNDARY: keep all kit-controlled modules out of the static import graph.
// They are loaded only after MANIFEST.json hashes have been checked. Static imports are
// evaluated before this module's body and would let tampered sibling top-level code run
// before the integrity gate could fail closed.
let jcsCanonical, jcsHashHex;
let DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS, DACS_X_EXTENSION_SEPARATORS;
let PATHOS_EXTENSION_SEPARATORS, buildSignedBytes;
let sign, verify, publicKeyFromPrivate;
let evaluateArtifact, summarise, parseManifest;

const KIT_DIR = path.dirname(fileURLToPath(import.meta.url));
const hex = (u8) => Buffer.from(u8).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const utf8 = (s) => new TextEncoder().encode(s);

// ── The 5 canonical reject constructors (§B.2 foot-guns) ────────────────
// Ported from vectors/canonical-form/cases.ts rejectCases — these inputs are not always
// faithfully JSON-serialisable (BigInt, lone surrogate, precise unsafe integers), so they
// are CONSTRUCTED here rather than carried as data. A conforming canonicaliser MUST
// reject each one for the stated reason.
const NFC_CAFE = 'caf\u00e9';   // c a f + U+00E9 (precomposed)
const NFD_CAFE = 'cafe\u0301';  // c a f e + U+0301 (combining acute)
const REJECT_CONSTRUCTORS = {
  'number-over-2pow53': () => ({ big: 9007199254740992 }),
  'number-large-magnitude-over-range': () => ({ n: 1e300 }),
  'number-exponent-over-range': () => ({ n: 1e21 }),
  'lone-surrogate': () => ({ s: '\uD800' }),
  'bigint': () => ({ b: BigInt(1) }),
  // 'nfc-key-collision' REMOVED: member names are no longer NFC-normalised (CF-1 covers
  // string VALUES only; RFC 8785 preserves names as received), so an NFC/NFD name pair
  // cannot collide. That input is now a canonical-ACCEPT case, nfc-nfd-key-pair-distinct.
};

let SEP_MAPS = {};
function sepByRef(ref) {
  const [map, key] = ref.split('.');
  const v = SEP_MAPS[map]?.[key];
  if (!v) throw new Error(`unknown separator ref: ${ref}`);
  return v;
}

// ── Vector executors, one per section ───────────────────────────────────

function runCanonicalAccept(v) {
  const canonical = Buffer.from(jcsCanonical(v.input)).toString('hex');
  if (canonical !== v.canonicalUtf8Hex) return `canonical bytes differ (got ${canonical.slice(0, 32)}…)`;
  const h = jcsHashHex(v.input);
  if (h !== v.expectedSha256) return `hash differs (got ${h})`;
  return null;
}

function runCanonicalReject(v) {
  const build = REJECT_CONSTRUCTORS[v.constructorId];
  if (!build) return `no reject constructor registered for "${v.constructorId}"`;
  try {
    jcsCanonical(build());
    return 'input was ACCEPTED — a conforming canonicaliser MUST reject it';
  } catch {
    return null; // rejected, as required
  }
}

function runSignVector(v) {
  // rawSeparator-only vectors (unknown-separator cases) carry no registry ref.
  const sep = v.separatorRef ? sepByRef(v.separatorRef) : undefined;
  const body = utf8(v.bodyUtf8);
  const inter = v.intermediateHashHex ? unhex(v.intermediateHashHex) : undefined;
  const priv = v.privKeyHex ? unhex(v.privKeyHex) : undefined;
  const pub = v.pubKeyHex ? unhex(v.pubKeyHex) : undefined;

  switch (v.op) {
    case 'sign-roundtrip': {
      const sig = sign(sep, body, priv, inter);
      if (hex(sig) !== v.expectedSigHex) return `signature differs from reference (got ${hex(sig).slice(0, 24)}…)`;
      if (!verify(sep, sig, body, pub, inter)) return 'own signature does not verify';
      if (v.derivedPubMustMatch && hex(publicKeyFromPrivate(priv)) !== v.pubKeyHex) return 'derived public key differs';
      return null;
    }
    case 'verify-true': {
      return verify(sep, unhex(v.sigHex), body, pub, inter) ? null : 'expected verify=true, got false';
    }
    case 'verify-false': {
      return verify(sep, unhex(v.sigHex), body, pub, inter) ? 'expected verify=false, got true' : null;
    }
    case 'verify-unknown-separator-false': {
      return verify(v.rawSeparator, unhex(v.sigHex), body, pub, inter)
        ? 'unknown separator must verify=false' : null;
    }
    case 'sign-must-throw': {
      try {
        sign(v.rawSeparator ?? sep, body, priv, inter);
        return 'sign() accepted a separator it MUST refuse';
      } catch { return null; }
    }
    case 'signed-bytes-golden': {
      const got = hex(buildSignedBytes(sep, body, inter));
      return got === v.expectedSignedBytesHex ? null : `signed_bytes layout differs (got ${got.slice(0, 32)}…)`;
    }
    default:
      return `unknown sign op "${v.op}"`;
  }
}

function runDriftVector(v) {
  switch (v.op) {
    case 'evaluate': {
      const row = evaluateArtifact(v.artifact, v.fixtureName, v.expectedHash ?? null);
      for (const [k, want] of Object.entries(v.expectRow)) {
        if (row[k] !== want) return `row.${k} = ${JSON.stringify(row[k])}, expected ${JSON.stringify(want)}`;
      }
      return null;
    }
    case 'summarise-missing': {
      const manifest = parseManifest(v.manifest);
      const files = Object.keys(v.artifacts);
      const rows = files.map((f) => evaluateArtifact(v.artifacts[f], f, manifest[f] ?? null));
      const s = summarise(rows);
      const missing = Object.keys(manifest).filter((k) => !files.includes(k));
      const failClosed = s.drift > 0 || s.structFail > 0 || missing.length > 0;
      if (missing.length !== v.expectMissingCount) return `missing=${missing.length}, expected ${v.expectMissingCount}`;
      if (failClosed !== v.expectFailClosed) return `failClosed=${failClosed}, expected ${v.expectFailClosed}`;
      return null;
    }
    case 'manifest-must-throw': {
      try {
        parseManifest(v.manifest);
        return 'malformed manifest was ACCEPTED — parser must fail closed';
      } catch { return null; }
    }
    default:
      return `unknown drift op "${v.op}"`;
  }
}

const EXECUTORS = {
  'canonical-accept': runCanonicalAccept,
  'canonical-reject': runCanonicalReject,
  'domain-sep-sign': runSignVector,
  'drift-signed-scope': runDriftVector,
};

// ── Kit integrity self-check (fail-closed, tamper-evident) ──────────────

function selfCheck(manifest, allowModified) {
  const problems = [];
  for (const [file, expected] of Object.entries(manifest.files)) {
    let got;
    try {
      got = createHash('sha256').update(readFileSync(path.join(KIT_DIR, file))).digest('hex');
    } catch (e) {
      problems.push(`${file}: unreadable (${e.message})`);
      continue;
    }
    if (got !== expected) problems.push(`${file}: sha256 ${got.slice(0, 16)}… ≠ manifest ${expected.slice(0, 16)}…`);
  }
  if (problems.length && !allowModified) {
    process.stderr.write('KIT INTEGRITY FAILURE — files differ from MANIFEST.json:\n');
    for (const p of problems) process.stderr.write(`  ✗ ${p}\n`);
    process.stderr.write('Refusing to run (fail-closed). Re-download the kit, or pass --allow-modified to run anyway (results are then NOT attributable to the published kit).\n');
    return false;
  }
  if (problems.length) {
    process.stderr.write(`⚠ --allow-modified: ${problems.length} file(s) differ from MANIFEST.json — results are NOT attributable to the published kit.\n`);
  }
  return true;
}

async function loadCheckedModules() {
  const [jcs, domainSep, signing, drift] = await Promise.all([
    import('./jcs.mjs'),
    import('./domain-sep.mjs'),
    import('./sign.mjs'),
    import('./drift.mjs'),
  ]);
  ({ jcsCanonical, jcsHashHex } = jcs);
  ({
    DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS, DACS_X_EXTENSION_SEPARATORS,
    PATHOS_EXTENSION_SEPARATORS, buildSignedBytes,
  } = domainSep);
  ({ sign, verify, publicKeyFromPrivate } = signing);
  ({ evaluateArtifact, summarise, parseManifest } = drift);
  SEP_MAPS = {
    DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS,
    DACS_X_EXTENSION_SEPARATORS, PATHOS_EXTENSION_SEPARATORS,
  };
}

// ── Main ────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const allowModified = args.includes('--allow-modified');
  const unknown = args.filter((a) => !['--json', '--allow-modified'].includes(a));
  if (unknown.length) {
    process.stderr.write(`usage: node run-conformance.mjs [--json] [--allow-modified] (unknown: ${unknown.join(' ')})\n`);
    return 2;
  }

  let vectors, manifest;
  try {
    vectors = JSON.parse(readFileSync(path.join(KIT_DIR, 'vectors.json'), 'utf8'));
    manifest = JSON.parse(readFileSync(path.join(KIT_DIR, 'MANIFEST.json'), 'utf8'));
  } catch (e) {
    process.stderr.write(`error: cannot load kit files: ${e.message}\n`);
    return 2;
  }

  if (!selfCheck(manifest, allowModified)) return 3;

  try {
    await loadCheckedModules();
  } catch (e) {
    process.stderr.write(`error: cannot load integrity-checked kit modules: ${e.message}\n`);
    return 2;
  }

  const results = [];
  for (const v of vectors.vectors) {
    const exec = EXECUTORS[v.section];
    const failure = exec ? (() => { try { return exec(v); } catch (e) { return `executor threw: ${e.message}`; } })()
      : `unknown section "${v.section}"`;
    results.push({ id: v.id, section: v.section, description: v.description, pass: failure === null, failure });
  }

  const executed = results.length;
  const passed = results.filter((r) => r.pass).length;
  const declared = vectors.declaredTotal;
  // Fail-closed on count drift: the kit's claim is "49 of 49 declared vectors execute".
  const countOk = executed === declared && declared === 49;

  const bySection = {};
  for (const r of results) {
    bySection[r.section] = bySection[r.section] ?? { total: 0, passed: 0 };
    bySection[r.section].total++;
    if (r.pass) bySection[r.section].passed++;
  }

  if (json) {
    process.stdout.write(JSON.stringify({
      kit: manifest.kit, sourceCommit: manifest.provenance?.sourceCommit,
      declared, executed, passed, failed: executed - passed, countOk,
      sections: bySection, results,
    }, null, 2) + '\n');
  } else {
    process.stdout.write(`# ${manifest.kit?.name ?? 'pathos-dacs partner kit'} — conformance run\n`);
    process.stdout.write(`# source commit ${manifest.provenance?.sourceCommit ?? '?'} · NON-NORMATIVE sanity kit, not a DACS certification\n\n`);
    for (const [section, s] of Object.entries(bySection)) {
      process.stdout.write(`  ${s.passed === s.total ? '✓' : '✗'} ${section}: ${s.passed}/${s.total}\n`);
    }
    for (const r of results.filter((r) => !r.pass)) {
      process.stdout.write(`    ✗ ${r.id}: ${r.failure}\n`);
    }
    process.stdout.write(`\n${passed}/${declared} declared vectors passed` +
      (countOk ? '' : ` — COUNT MISMATCH (declared ${declared}, executed ${executed}, contract 49)`) + '\n');
  }
  return passed === executed && countOk ? 0 : 1;
}

process.exitCode = await main();
