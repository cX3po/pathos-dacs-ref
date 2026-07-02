/**
 * verifyPeer — an A2A Peer-Trust showcase (reference engine, console-only).
 *
 *   npx tsx showcase/verify-peer/demo.mts
 *
 * THE A2A SHOWCASE MOVE: an agent exposes a task handler that will run work for a peer. The A2A
 * ecosystem's unsolved problem is TRUSTING A STRANGER'S AGENT — a peer hands you an AgentCard (its
 * `.well-known/agent.json`: a name + an identity claim) and asks you to do work. The card is
 * DISCOVERY, not trust: anyone can claim any identity in their own card. So the handler is wrapped
 * in `withDacsTrust`, which calls `verifyPeer()` → DACS-verifies the peer's attestation bundle AND
 * binds the card's claimed identity to the identity the bundle CRYPTOGRAPHICALLY PROVES signed.
 *
 * Two strangers request the task:
 *   • Peer Honest  — a valid, real-ed25519-signed bundle whose AgentCard identity MATCHES the
 *                    identity the bundle proves → verifyPeer trusts → handler runs → ACCEPTED.
 *   • Peer Impostor — an AgentCard claiming identity X, but a bundle that proves identity Y
 *                    (a different real key) → verifyPeer catches the mismatch → DECLINED, handler
 *                    never runs.
 *
 * #194 doctrine made concrete: the AgentCard is evidence DACS binds, NOT trust it inherits. An
 * unresolvable/ambiguous reference is `indeterminate`, NEVER a borrowed `pass`. Deterministic,
 * zero network, fixed-seed keys, console only. Exit 0 IFF honest→accepted AND impostor→declined.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsHashHex } from '../../src/jcs.js';
import { bundleSignedScopeHashV1 } from '../../src/lib/bundle-signed-scope-v1.js';
import { verifyPeer, withDacsTrust, type A2AAgentCard, type PeerTrustResult } from '../../src/lib/verify-peer.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// ── deterministic real ed25519 keys (mirrors the stranger-gauntlet showcase) ─────────────────────
interface Key { priv: Uint8Array; pubHex: string; }
function fixedKey(fill: number): Key {
  const priv = new Uint8Array(32).fill(fill); // fixed seed → deterministic, zero network/entropy
  return { priv, pubHex: hex(ed25519.getPublicKey(priv)) };
}

// ── honest bundle construction (spec-conformant §10.4 two-sided AttestationBundleV1) ──────────────
interface BundleOpts { jobId: string; item: string; priceOs: string; buyer: Key; seller: Key; }

function listingContentHash(o: { jobId: string; seller: string; item: string; priceOs: string }): string {
  return jcsHashHex({ v: 'dacs-listing:0.1', listingId: `${o.jobId}-listing`, ...o });
}

function unsignedBundle(o: BundleOpts, listHash: string): Omit<AttestationBundleV1, 'signatures'> {
  return {
    bundleVersion: '1',
    jobId: o.jobId,
    outcome: 'completed',
    anchoredByRole: 'buyer',
    listingRef: { listingId: `${o.jobId}-listing`, version: 1, contentHash: listHash },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.seller.pubHex } },
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

function honestBundle(o: BundleOpts): AttestationBundleV1 {
  const listHash = listingContentHash({ jobId: o.jobId, seller: o.seller.pubHex, item: o.item, priceOs: o.priceOs });
  return signBundle(unsignedBundle(o, listHash), [o.buyer, o.seller]);
}

// ── the A2A task the server agent exposes ─────────────────────────────────────────────────────────
interface Task { kind: string; payload: string; }
interface Peer { name: string; agentCard: A2AAgentCard; bundle: AttestationBundleV1; }

// A plain business handler — it assumes it is only ever reached for a DACS-trusted peer, because
// `withDacsTrust` guarantees exactly that. It never sees an untrusted peer.
const rawHandler = (task: Task, peer: Peer): { ran: string; forPeer: string } => ({
  ran: `summarised "${task.payload}"`,
  forPeer: peer.agentCard.name,
});

// The trust-gated handler: DACS verifies every incoming peer BEFORE the business logic runs.
const trustedHandler = withDacsTrust<Task, Peer, { ran: string; forPeer: string }>(rawHandler);

// ── console display ───────────────────────────────────────────────────────────────────────────────
interface PeerLogRow { name: string; claimedIdentity: string; accepted: boolean; peerTrust: PeerTrustResult; result?: { ran: string; forPeer: string }; }

function badge(t: PeerTrustResult): string {
  if (t.trusted) return '🟢 ACCEPTED (trusted)';
  if (t.decision === 'reject') return '🔴 DECLINED (reject)';
  if (t.decision === 'indeterminate') return '🟡 DECLINED (indeterminate)';
  return '⚠️  DECLINED (error)';
}

function printPeerTrustLog(rows: PeerLogRow[]): void {
  console.log('\n════════════════════════════════════════════════════════════════════');
  console.log('  verifyPeer — A2A Peer-Trust Log');
  console.log('  One task handler. Two stranger peers. One DACS peer-trust gate.');
  console.log('════════════════════════════════════════════════════════════════════');
  console.log('  Gate:  withDacsTrust → verifyPeer (§10.4.1 verifier + #194 identity binding)');
  console.log('  Rule:  trusted === (bundle accepts && card identity is DACS-proven)\n');

  for (const r of rows) {
    const t = r.peerTrust;
    console.log(`  ── ${r.name}`);
    console.log(`     AgentCard claims: ${r.claimedIdentity}`);
    console.log(`     decision:         ${badge(t)}`);
    console.log(`     identityBound:    ${t.identityBound}`);
    if (t.killedBy) {
      console.log(`     killed by:        ${t.killedBy.check}`);
      console.log(`                       └ ${t.killedBy.detail}`);
    }
    console.log(`     handler ran:      ${r.accepted ? `✅ yes → ${r.result?.ran}` : '⛔ NO — gate declined before handler'}`);
    console.log(`     reason:           ${t.reason}`);
    console.log('');
  }
}

// ── the showcase ────────────────────────────────────────────────────────────────────────────────
export interface ShowcaseResult {
  showcase: 'verify-peer';
  rows: PeerLogRow[];
  honestAccepted: boolean;
  impostorDeclined: boolean;
  verdict: 'PASS' | 'FAIL';
}

export async function runVerifyPeerShowcase(): Promise<ShowcaseResult> {
  // The server agent (task owner) + two stranger peers, each a deterministic real key.
  const buyer = fixedKey(0x5a);        // the server agent, acting as buyer/task-owner in the bundle
  const honestSeller = fixedKey(0xa1); // the honest peer's REAL key (it will present + prove this)
  const impostorReal = fixedKey(0xb2); // the identity the impostor's bundle ACTUALLY proves (Y)
  const impostorClaim = fixedKey(0xee); // the identity the impostor's AgentCard CLAIMS to be (X ≠ Y)

  // Peer Honest — bundle proves honestSeller signed; AgentCard claims honestSeller. Match.
  const honestPeer: Peer = {
    name: 'Peer Honest (agent://alpha)',
    agentCard: { name: 'agent://alpha', identity: { scheme: 'cci', identifier: honestSeller.pubHex } },
    bundle: honestBundle({ jobId: 'a2a-task-alpha', item: 'inference-job:summarisation', priceOs: '5000000000', buyer, seller: honestSeller }),
  };

  // Peer Impostor — a perfectly valid bundle, but it proves impostorReal (Y) signed, while the
  // AgentCard CLAIMS to be impostorClaim (X). The card is a stranger's self-assertion; DACS proves
  // a different identity. #194: the card is discovery, the bundle is trust — they disagree → decline.
  const impostorPeer: Peer = {
    name: 'Peer Impostor (agent://omega)',
    agentCard: { name: 'agent://omega', identity: { scheme: 'cci', identifier: impostorClaim.pubHex } },
    bundle: honestBundle({ jobId: 'a2a-task-omega', item: 'inference-job:summarisation', priceOs: '5000000000', buyer, seller: impostorReal }),
  };

  const task: Task = { kind: 'summarise', payload: 'quarterly-report.pdf' };

  const rows: PeerLogRow[] = [];
  for (const peer of [honestPeer, impostorPeer]) {
    const outcome = await trustedHandler(task, peer);
    rows.push({
      name: peer.name,
      claimedIdentity: `${peer.agentCard.identity.scheme}:${peer.agentCard.identity.identifier.slice(0, 20)}…`,
      accepted: outcome.accepted,
      peerTrust: outcome.peerTrust,
      result: outcome.accepted ? outcome.result : undefined,
    });
  }

  const [honestRow, impostorRow] = rows as [PeerLogRow, PeerLogRow];
  const honestAccepted = honestRow.accepted && honestRow.peerTrust.trusted;
  const impostorDeclined = !impostorRow.accepted && !impostorRow.peerTrust.trusted;
  return {
    showcase: 'verify-peer',
    rows,
    honestAccepted,
    impostorDeclined,
    verdict: honestAccepted && impostorDeclined ? 'PASS' : 'FAIL',
  };
}

// ── entry point ────────────────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const res = await runVerifyPeerShowcase();
  printPeerTrustLog(res.rows);

  console.log('  ──────────────────────────────────────────────────────────────────');
  console.log(`  Honest peer accepted:   ${res.honestAccepted ? '✅ handler ran for a DACS-proven peer' : '❌ honest peer was NOT accepted'}`);
  console.log(`  Impostor peer declined: ${res.impostorDeclined ? '✅ identity-mismatch caught; handler never ran' : '❌ impostor slipped through — trust-gate bug!'}`);
  console.log(`  Showcase verdict:       ${res.verdict === 'PASS' ? '✅ PASS' : '❌ FAIL'}`);
  console.log('  ──────────────────────────────────────────────────────────────────\n');

  console.log('  Machine-readable result (JSON):');
  console.log(JSON.stringify({
    showcase: res.showcase,
    peers: res.rows.map((r) => ({ name: r.name, accepted: r.accepted, decision: r.peerTrust.decision, identityBound: r.peerTrust.identityBound, killedBy: r.peerTrust.killedBy ?? null })),
    honestAccepted: res.honestAccepted,
    impostorDeclined: res.impostorDeclined,
    verdict: res.verdict,
  }, null, 2));
  console.log('');

  // Demonstrate the do-not-collapse guarantee inline: an unresolvable peer is indeterminate, never
  // trusted. (verifyPeer resolves the AgentCard first and returns before touching the bundle.)
  const indeterminate = verifyPeer({ agentCard: undefined as unknown as A2AAgentCard, bundle: undefined as unknown as AttestationBundleV1 });
  console.log(`  Do-not-collapse spot check — unresolvable peer → decision=${indeterminate.decision}, trusted=${indeterminate.trusted} (must be false)\n`);

  process.exit(res.verdict === 'PASS' && indeterminate.trusted === false ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
