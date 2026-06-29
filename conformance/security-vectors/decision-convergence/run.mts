/**
 * Cross-impl DECISION convergence — pathos-dacs-ref ↔ dacs-sdk, on a §7.5.1 ground-truth corpus.
 *
 * Canonicalization convergence is already proven (hash 3/3). This proves the harder thing: the two
 * impls reach the SAME §7.5.1 verdict on bundles engineered to trigger each decision. Built EMPIRICALLY
 * — we run both real verifiers and report the actual matrix; mismatches are findings, not hidden.
 *
 * HONEST SCOPE (guardrail #6): self-describing `cci:<hex>` keys, NO live DID resolver. This proves the
 * decision LOGIC converges on these ground-truth cases — not "all bundles," not live-resolver behaviour.
 *
 * dacs-sdk is imported from a local clone (PR #2 head). For CI this becomes an npm dep (#6 follow-on).
 */
import { ed25519 } from '@noble/curves/ed25519';
import { emitAttestationBundleV1 } from '../../../src/lib/emit-bundle-v1.js';
import { verifyBundleV1 } from '../../../src/lib/verify-bundle-v1.js';
// dacs-sdk verifier from a local clone (PR #2 head); path configurable via DACS_SDK_PATH. For CI this
// becomes an npm dep (#6 follow-on). Requires `npm ci` in the clone so its deps resolve.
const DACS_SDK = process.env.DACS_SDK_PATH ?? '/tmp/dacs-sdk-read';
// @ts-ignore — resolved by tsx at run time from the clone path
const { verifyBundleCore } = await import(`${DACS_SDK}/src/agent/verifyBundleCore.js`);

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, claim: `cci:${hex(ed25519.getPublicKey(priv))}` }; };
const buyer = mk(0x41), seller = mk(0x42);

function unsigned(over: Record<string, unknown> = {}) {
  return {
    bundleVersion: '1', jobId: 'dc-1', outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst', version: 1, contentHash: 'ab'.repeat(32) },
    agreementRef: { kind: 'dacs-3-agreement', id: 'a', contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: buyer.claim },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: seller.claim },
    ],
    // attestationRef on every phase entry: REQUIRED by dacs-sdk's isAttestationBundle, OPTIONAL in
    // pathos — a real cross-impl shape divergence (recorded as a finding). Including it satisfies both
    // so we can compare the DECISION logic itself.
    phaseSummary: [{ index: 0, kind: 'vet', outcome: 'ok', attestationRef: { kind: 'dacs-2-verify', id: 'v', contentHash: '12'.repeat(32) } }],
    vetRecords: [], settlementEvidence: [{ kind: 'dacs-4-evidence', id: 's', contentHash: 'ef'.repeat(32) }],
    recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000, ...over,
  };
}
const sign2 = (u: Record<string, unknown>) => emitAttestationBundleV1(u as never, [
  { party: buyer.claim, privKey: buyer.priv }, { party: seller.claim, privKey: seller.priv },
]);

// ── the ground-truth corpus ──────────────────────────────────────────────────
const valid = sign2(unsigned());
const tampered = { ...sign2(unsigned()), outcome: 'failed-perm' };          // mutate a SIGNED field post-emit → sig no longer matches
const malformed = { bundleVersion: '1', jobId: 'malformed-x' };             // missing required fields → both reject as not-a-bundle
// unresolvable: an abort bundle whose ONLY signer is a non-resolvable did:* (no 64-hex key)
const abortUnsigned = unsigned({ outcome: 'aborted-by-self', anchoredByRole: 'buyer',
  parties: [{ role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: 'did:demos:placeholder' }] });
const unresolvable = emitAttestationBundleV1(abortUnsigned as never, [{ party: 'did:demos:placeholder', privKey: buyer.priv }]);
// compound: a valid+tampered (hard-bad) sig AND an unresolvable sig together
const compoundBase = sign2(unsigned({ jobId: 'dc-compound' }));
const compound = { ...compoundBase, outcome: 'failed-perm',                 // tamper (hard-bad on both real sigs)
  signatures: [ ...(compoundBase as { signatures: unknown[] }).signatures,
    { party: 'did:demos:placeholder', algorithm: 'ed25519', value: Buffer.from(new Uint8Array(64)).toString('base64') } ] };
// mixed: ONE valid signature + ONE unresolvable-key signature → must be indeterminate in BOTH (NOT pass).
// This is the case that catches a dishonest `ok→pass` normalization (do-not-collapse, §7.5.1).
const mixedUnsigned = unsigned({ jobId: 'dc-mixed', parties: [
  { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: buyer.claim },
  { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: 'did:demos:placeholder' },
] });
const mixed = emitAttestationBundleV1(mixedUnsigned as never, [
  { party: buyer.claim, privKey: buyer.priv },               // resolvable + valid
  { party: 'did:demos:placeholder', privKey: seller.priv },  // signature present, key UNRESOLVABLE → unverifiable
]);

const CORPUS: Array<{ name: string; bundle: Record<string, unknown>; expect: string }> = [
  { name: 'valid', bundle: valid, expect: 'pass' },
  { name: 'tampered-sig', bundle: tampered, expect: 'fail' },
  { name: 'unresolvable-key', bundle: unresolvable, expect: 'indeterminate' },
  { name: 'malformed', bundle: malformed, expect: 'error' },
  { name: 'compound(tampered+unresolvable)', bundle: compound, expect: 'fail' },
  { name: 'mixed(valid+unresolvable)', bundle: mixed, expect: 'indeterminate' },
];

// ── normalize each impl's native verdict → the §7.5.1 4-value model ───────────
function normPathos(v: { decision: string; structurallyValid: boolean }): string {
  if (v.decision === 'accept') return 'pass';
  if (v.decision === 'indeterminate') return 'indeterminate';
  // reject: structural-invalid → error (verifier couldn't process a well-formed bundle); else bad-sig → fail
  return v.structurallyValid ? 'fail' : 'error';
}
function normSdk(v: { ok: boolean; fullyVerified: boolean; reason?: string; signatures: Array<{ verdict: string }> }): string {
  // pass ONLY if EVERY signature verified. do-not-collapse (§7.5.1): ok=true with an unverified
  // signature is a MIXED result → indeterminate, NEVER pass. (dacs-sdk `ok` = ≥1 valid & none
  // invalid/error, which is weaker than "fully verified" — using it for pass would be dishonest.)
  if (v.fullyVerified) return 'pass';
  const r = v.reason ?? '';
  if (/not an attestation bundle/i.test(r)) return 'error';
  const vs = v.signatures.map((s) => s.verdict);
  if (vs.includes('invalid')) return 'fail';
  if (vs.includes('error')) return 'error';
  // some valid + some unverified, OR all unverified, OR no sigs → cannot conclude → indeterminate
  return 'indeterminate';
}

const sdkDeps = {
  readArtifact: async (ref: string) => (byRef.get(ref) ?? null),
  resolvePublicKey: async (did: string) => {
    const m = did.match(/(?:^|:)(?:0x)?([0-9a-fA-F]{64})$/);
    return m ? Uint8Array.from(Buffer.from(m[1]!, 'hex')) : null;
  },
  verify: (message: Uint8Array, sig: Uint8Array, pub: Uint8Array) => {
    try { return ed25519.verify(sig, message, pub); } catch { return false; }
  },
};
const byRef = new Map<string, Record<string, unknown>>();

const rows: Array<Record<string, unknown>> = [];
for (const c of CORPUS) {
  byRef.set(c.name, c.bundle);
  let pathos = 'error', sdk = 'error';
  try { pathos = normPathos(verifyBundleV1(c.bundle as never)); } catch (e) { pathos = 'error'; }
  try { sdk = normSdk(await verifyBundleCore(c.name, sdkDeps as never)); } catch (e) { sdk = 'error'; }
  const converge = pathos === sdk;
  rows.push({ name: c.name, expect: c.expect, pathos, sdk, converge, matchesExpect: pathos === c.expect && sdk === c.expect });
}

const converged = rows.filter((r) => r.converge).length;
const asExpected = rows.filter((r) => r.matchesExpect).length;
console.log('\n=== Cross-impl §7.5.1 DECISION convergence (pathos-dacs-ref ↔ dacs-sdk) ===');
console.log('(self-describing cci keys, no live resolver — decision LOGIC convergence)\n');
for (const r of rows) {
  console.log(`  ${r.converge ? '✅' : '❌'} ${String(r.name).padEnd(34)} pathos=${String(r.pathos).padEnd(13)} sdk=${String(r.sdk).padEnd(13)} (expect ${r.expect})`);
}
console.log(`\nDECISION convergence: ${converged}/${rows.length}   |   both-match-ground-truth: ${asExpected}/${rows.length}`);
console.log(JSON.stringify({ metric: 'decision-convergence', converged, total: rows.length, asExpected, rows }));
