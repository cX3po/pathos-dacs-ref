/**
 * DACS §9.4.4 rail-availability selection + poisoning conformance vectors — GAP #13 (issue #158).
 * RAV-R1/R2/R3/R5: read availability from the steward-signed AND pinned/anchored def; never select
 * disabled/failed/mocked; gated availabilities only with operator preflight; reject unauthenticated OR
 * stale-cached copies. Run: npx tsx run.mts → writes vectors json, exits 1 on any mismatch.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkRailSelection, pubRawFromSeed, edSign, railDigest, type RailDefinition, type RailCtx } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const seed = (n: number) => Buffer.alloc(32, n).toString('hex');

const STEWARD = seed(0x91), IMPOSTER = seed(0x92);
const stewardPub = pubRawFromSeed(STEWARD);

function signRail(railId: string, availability: string, signer: string, railVersion = 1): RailDefinition {
  const body = Buffer.from('dacs-rail:v1:' + JSON.stringify({ railId, availability, railVersion }), 'utf8');
  return { railId, availability, railVersion, stewardSig: edSign(body, signer) };
}

type Dec = 'pass' | 'fail' | 'indeterminate' | 'error';
type Case = { name: string; expected: Dec; rail: RailDefinition; ctx: RailCtx; note: string };
// every authentic case self-pins (pinnedRailDigest = the presented def's digest) so the RAV-R5 pin
// check runs in the pass path too; override ctx for the stale-cached / unresolvable cases.
const C = (name: string, expected: Dec, rail: RailDefinition, note: string, over: Partial<RailCtx> = {}): Case =>
  ({ name, expected, rail, note, ctx: { stewardPub, operatorPreflightOk: false, pinnedRailDigest: railDigest(rail), ...over } });

const cases: Case[] = [
  C('live-signed-pinned', 'pass', signRail('pay-x402', 'live', STEWARD), 'live + steward-signed + matches the pinned def → selectable'),
  // RAV-R2 — disabled/failed never selectable
  C('disabled-signed', 'fail', signRail('pay-old', 'disabled', STEWARD), 'RAV-R2: disabled MUST NOT be selected'),
  C('failed-signed', 'fail', signRail('pay-evm', 'failed', STEWARD), 'RAV-R2: failed (network/asset path broken) MUST NOT be selected'),
  // RAV-R1 — mocked is not a production rail
  C('mocked-signed', 'fail', signRail('pay-ap2', 'mocked', STEWARD), 'RAV-R1: mocked is a stub, MUST NOT be treated as live'),
  // RAV-R3 — gated availabilities require operator preflight
  C('operator_gated-no-preflight', 'fail', signRail('pay-ap2', 'operator_gated', STEWARD), 'RAV-R3: operator_gated without preflight → not selectable'),
  C('operator_gated-with-preflight', 'pass', signRail('pay-ap2', 'operator_gated', STEWARD), 'RAV-R3: operator_gated WITH preflight satisfied → selectable', { operatorPreflightOk: true }),
  C('closed_data-no-preflight', 'fail', signRail('pay-perm', 'closed_data', STEWARD), 'RAV-R3: closed_data without preflight → not selectable'),
  C('bilateral-with-preflight', 'pass', signRail('pay-bilat', 'bilateral', STEWARD), 'RAV-R3: bilateral WITH per-relationship agreement in place → selectable', { operatorPreflightOk: true }),
  // RAV-R5 — availability-field poisoning: trust ONLY the steward-signed AND pinned def
  C('poison-live-bad-signer', 'fail', signRail('pay-x402', 'live', IMPOSTER), 'RAV-R5: "live" claimed but signed by a non-steward key — unauthenticated, MUST NOT select'),
  C('poison-live-unsigned', 'fail', { railId: 'pay-x402', availability: 'live', railVersion: 1 }, 'RAV-R5: unsigned/counterparty-supplied copy claiming live — MUST NOT trust'),
  // the case Codex flagged: a VALIDLY steward-signed but STALE/cached copy that is NOT the pinned def
  { name: 'stale-cached-signed-copy', expected: 'fail', rail: signRail('pay-evm', 'live', STEWARD, 1),
    note: 'RAV-R5: an old steward-signed "live" v1, superseded by a pinned "failed" v2 — valid signature, but NOT the pinned/anchored def → MUST NOT steer selection',
    ctx: { stewardPub, operatorPreflightOk: false, pinnedRailDigest: railDigest(signRail('pay-evm', 'failed', STEWARD, 2)) } },
  // do-not-collapse: steward key unresolvable → indeterminate
  C('steward-key-unresolvable', 'indeterminate', signRail('pay-x402', 'live', STEWARD), 'cannot authenticate the rail def → undecidable (NOT fail, NOT pass)', { stewardPub: null }),
  // RAV-R5: a valid steward sig with NO pinned reference cannot be confirmed authoritative → must not pass
  { name: 'no-pin-context-signed-live', expected: 'indeterminate', rail: signRail('pay-x402', 'live', STEWARD),
    note: 'RAV-R5: valid steward signature but NO pinned/anchored reference to compare → cannot confirm authoritative → indeterminate (never a silent pass)',
    ctx: { stewardPub, operatorPreflightOk: false } },
  // malformed / unknown-enum → error
  C('malformed-rail', 'error', { railId: 'pay-x402' } as unknown as RailDefinition, 'missing availability — verifier-side parse error'),
  C('unknown-availability-value', 'error', signRail('pay-x402', 'banana', STEWARD), 'availability not in the §9.4.4 enum → error'),
];

let pass = 0;
console.log('\n=== DACS §9.4.4 rail-availability selection conformance vectors v0.1 (#158: #13) ===');
for (const c of cases) {
  const v = checkRailSelection(c.rail, c.ctx);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(34)} exp=${c.expected.padEnd(13)} got=${v.decision}`);
}
const vectorsOut = { set: 'rail-availability-selection-v0.1', spec: 'DACS-4 §9.4.4 (RAV-R1/R2/R3/R5)', gaps: ['#13 rail-availability-poisoning'],
  decisionModel: '§7.5.1 4-value, never collapsed', count: cases.length,
  cases: cases.map((c) => ({ name: c.name, expected: c.expected, note: c.note, rail: c.rail, ctx: c.ctx })) };
const json = JSON.stringify(vectorsOut, null, 2);
writeFileSync(`${DIR}/vectors/rail-availability-selection-v0.1.json`, json + '\n');
console.log(`\n${pass}/${cases.length} vectors pass → vectors/rail-availability-selection-v0.1.json  (set sha256 ${sha(json).slice(0, 16)})`);
if (pass !== cases.length) process.exit(1);
