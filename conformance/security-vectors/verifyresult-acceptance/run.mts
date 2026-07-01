/**
 * DACS §7.12 VerifyResult-acceptance conformance vectors — GAP #6 / #7 / #17 (issue #158).
 * Method substitution · recipe poisoning · cross-session replay — plus the SAFE cases the spec
 * explicitly permits (cross-session reuse within validUntil; CF-3 identifier canonicalisation).
 * Run: npx tsx run.mts  → writes vectors/verifyresult-acceptance-v0.1.json, exits 1 on any mismatch.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkVerifyResultAcceptance, pubRawFromSeed, edSign, type Recipe, type VerifyResult, type Ctx } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const seed = (n: number) => Buffer.alloc(32, n).toString('hex');

const STEWARD = seed(0x71), ATTACKER_STEWARD = seed(0x72);
const stewardPub = pubRawFromSeed(STEWARD), attackerStewardPub = pubRawFromSeed(ATTACKER_STEWARD);

// the genuine, steward-signed recipe (defaultMethod consensus-backed-proxy, one accepted alternative)
function signRecipe(r: Omit<Recipe, 'stewardSig'>, signer: string): Recipe {
  const body = { method: r.method, alternatives: r.alternatives ?? [], recipeVersion: r.recipeVersion };
  return { ...r, stewardSig: edSign(Buffer.from('dacs-recipe:v1:' + JSON.stringify(body), 'utf8'), signer) };
}
const recipe = signRecipe({ method: 'consensus-backed-proxy', alternatives: ['tlsnotary'], recipeVersion: 3 }, STEWARD);

const CLAIM = { scheme: 'cci', identifier: 'ab'.repeat(32) };
const BUNDLE = sha('bundle-1');
const NOW = 1_750_000_000;

const baseVR: VerifyResult = { identifier: CLAIM, method: 'consensus-backed-proxy', bundleHash: BUNDLE, validUntil: NOW + 3600 };
const baseCtx: Ctx = { claimUnderVerification: CLAIM, pinnedRecipeVersion: 3, expectedBundleHash: BUNDLE, stewardPub, now: NOW };

type Dec = 'pass' | 'fail' | 'indeterminate' | 'error';
type Case = { name: string; expected: Dec; vr: VerifyResult; recipe: Recipe; ctx: Ctx; note: string };

const cases: Case[] = [
  { name: 'valid-acceptance', expected: 'pass', vr: baseVR, recipe, ctx: baseCtx, note: 'genuine result, accepted method, pinned version, matching identifier+bundle, fresh' },
  // #6 method substitution
  { name: 'method-substitution', expected: 'fail', vr: { ...baseVR, method: 'evm-rpc' }, recipe, ctx: baseCtx, note: 'method not in recipe defaultMethod ∪ alternatives' },
  { name: 'method-accepted-alternative', expected: 'pass', vr: { ...baseVR, method: 'tlsnotary' }, recipe, ctx: baseCtx, note: 'a declared equivalent alternative is accepted' },
  // #7 recipe poisoning
  { name: 'recipe-poisoned-bad-steward-sig', expected: 'fail', vr: baseVR, recipe: signRecipe({ method: 'consensus-backed-proxy', alternatives: ['tlsnotary'], recipeVersion: 3 }, ATTACKER_STEWARD), ctx: baseCtx, note: 'recipe signed by a non-steward key — MUST be rejected' },
  { name: 'recipe-version-not-pinned', expected: 'fail', vr: baseVR, recipe: signRecipe({ method: 'consensus-backed-proxy', alternatives: ['tlsnotary'], recipeVersion: 9 }, STEWARD), ctx: baseCtx, note: 'recipeVersion != the version pinned for this session' },
  { name: 'steward-key-unresolvable', expected: 'indeterminate', vr: baseVR, recipe, ctx: { ...baseCtx, stewardPub: null }, note: 'cannot verify the recipe signature → undecidable (NOT fail, NOT pass)' },
  // #17 VerifyResult replay
  { name: 'replay-identifier-mismatch', expected: 'fail', vr: { ...baseVR, identifier: { scheme: 'cci', identifier: 'cd'.repeat(32) } }, recipe, ctx: baseCtx, note: 'stale/relifted result for a DIFFERENT claim' },
  { name: 'replay-bundle-mismatch', expected: 'fail', vr: { ...baseVR, bundleHash: sha('other-bundle') }, recipe, ctx: baseCtx, note: 'result bound to a different bundle' },
  { name: 'expired-past-validUntil', expected: 'fail', vr: baseVR, recipe, ctx: { ...baseCtx, now: NOW + 7200 }, note: 'past validUntil — stale' },
  // SAFE cases the spec explicitly permits — must NOT be over-rejected
  { name: 'cross-session-reuse-within-validUntil', expected: 'pass', vr: baseVR, recipe, ctx: { ...baseCtx, now: NOW + 1800 }, note: 'different session, same identifier, still within validUntil — EXPLICITLY PERMITTED (§7.12)' },
  { name: 'identifier-canonical-form-equivalent', expected: 'pass', vr: { ...baseVR, identifier: `cci:0x${'AB'.repeat(32)}` }, recipe, ctx: baseCtx, note: 'same identifier in 0x/upper form — CF-3 canonicalisation MUST match, not split' },
  // malformed → error
  { name: 'malformed-verifyresult', expected: 'error', vr: { method: 'consensus-backed-proxy' } as unknown as VerifyResult, recipe, ctx: baseCtx, note: 'missing identifier — verifier-side parse error, never fail/pass' },
  { name: 'malformed-identifier-shape', expected: 'error', vr: { ...baseVR, identifier: { scheme: 'cci' } as unknown as { scheme: string; identifier: string } }, recipe, ctx: baseCtx, note: 'identifier object missing the identifier field — must be error, not a crash (Codex-HIGH)' },
];

let pass = 0;
console.log('\n=== DACS §7.12 VerifyResult-acceptance conformance vectors v0.1 (#158: #6/#7/#17) ===');
for (const c of cases) {
  const v = checkVerifyResultAcceptance(c.vr, c.recipe, c.ctx);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(38)} exp=${c.expected.padEnd(13)} got=${v.decision}`);
}
const vectorsOut = { set: 'verifyresult-acceptance-v0.1', spec: 'DACS-2 §7.12', gaps: ['#6 method-substitution', '#7 recipe-poisoning', '#17 verifyresult-replay'],
  decisionModel: '§7.5.1 4-value, never collapsed', count: cases.length,
  cases: cases.map((c) => ({ name: c.name, expected: c.expected, note: c.note, verifyResult: c.vr, recipe: c.recipe, ctx: c.ctx })) };
const json = JSON.stringify(vectorsOut, null, 2);
writeFileSync(`${DIR}/vectors/verifyresult-acceptance-v0.1.json`, json + '\n');
console.log(`\n${pass}/${cases.length} vectors pass → vectors/verifyresult-acceptance-v0.1.json  (set sha256 ${sha(json).slice(0, 16)})`);
if (pass !== cases.length) process.exit(1);
