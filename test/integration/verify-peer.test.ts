/**
 * verifyPeer — A2A peer-trust primitive tests.
 *
 * Asserts the load-bearing #194 + §7.5.1 guarantees:
 *   - an honest peer (bundle proves the card's identity) is TRUSTED and its handler runs;
 *   - an impostor peer (card claims X, bundle proves Y) is NOT trusted, DECLINED with an
 *     `identity-mismatch` killedBy, and its handler never runs;
 *   - a tampered bundle is NOT trusted (bundle-level reject);
 *   - an indeterminate / unresolvable peer has trusted===false — NEVER a borrowed pass;
 *   - withDacsTrust does not call the wrapped handler for any untrusted peer.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { ed25519 } from '@noble/curves/ed25519';
import { sign } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsHashHex } from '../../src/jcs.js';
import { bundleSignedScopeHashV1 } from '../../src/lib/bundle-signed-scope-v1.js';
import { verifyPeer, withDacsTrust, type A2AAgentCard } from '../../src/lib/verify-peer.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

interface Key { priv: Uint8Array; pubHex: string; }
function fixedKey(fill: number): Key {
  const priv = new Uint8Array(32).fill(fill);
  return { priv, pubHex: hex(ed25519.getPublicKey(priv)) };
}

function honestBundle(o: { jobId: string; buyer: Key; seller: Key }): AttestationBundleV1 {
  const listHash = jcsHashHex({ v: 'dacs-listing:0.1', listingId: `${o.jobId}-listing`, jobId: o.jobId, seller: o.seller.pubHex, item: 'x', priceOs: '1' });
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1',
    jobId: o.jobId,
    outcome: 'completed',
    anchoredByRole: 'buyer',
    listingRef: { listingId: `${o.jobId}-listing`, version: 1, contentHash: listHash },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: o.seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [],
    settlementEvidence: [],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1735689600000,
  };
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  return {
    ...unsigned,
    signatures: [o.buyer, o.seller].map((k) => ({
      party: { scheme: 'cci' as const, identifier: k.pubHex },
      algorithm: 'ed25519' as const,
      value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), k.priv)).toString('base64'),
    })),
  };
}

const card = (k: Key, name = 'agent://x'): A2AAgentCard => ({ name, identity: { scheme: 'cci', identifier: k.pubHex } });

const buyer = fixedKey(0x5a);
const seller = fixedKey(0xa1);
const other = fixedKey(0xb2);

test('honest peer — bundle proves the AgentCard identity → trusted + accepted', () => {
  const bundle = honestBundle({ jobId: 'job-honest', buyer, seller });
  const r = verifyPeer({ agentCard: card(seller), bundle });
  assert.equal(r.decision, 'accept');
  assert.equal(r.trusted, true);
  assert.equal(r.identityBound, true);
  assert.equal(r.killedBy, undefined);
});

test('impostor peer — card claims X, bundle proves Y → identity-mismatch, not trusted, declined', () => {
  const bundle = honestBundle({ jobId: 'job-impostor', buyer, seller }); // bundle proves `seller`
  const r = verifyPeer({ agentCard: card(other), bundle }); // card claims `other` (≠ seller)
  assert.equal(r.trusted, false);
  assert.equal(r.decision, 'reject');
  assert.equal(r.identityBound, false);
  assert.ok(r.killedBy);
  assert.equal(r.killedBy!.check, 'identity-mismatch');
});

test('tampered bundle — post-signature content tamper → not trusted (bundle reject)', () => {
  const honest = honestBundle({ jobId: 'job-tamper', buyer, seller });
  // Rewrite a signed-scope field AFTER signing → recomputed bundleHash no longer matches the sigs.
  const tampered: AttestationBundleV1 = {
    ...honest,
    listingRef: { ...honest.listingRef, contentHash: 'cd'.repeat(32) },
  };
  const r = verifyPeer({ agentCard: card(seller), bundle: tampered });
  assert.equal(r.trusted, false);
  assert.equal(r.decision, 'reject');
  assert.ok(r.killedBy);
  assert.equal(r.killedBy!.check, 'signature-invalid');
});

test('indeterminate peer — unresolvable AgentCard identity → trusted===false, never a borrowed pass', () => {
  const bundle = honestBundle({ jobId: 'job-indeterminate', buyer, seller });
  // Missing AgentCard entirely.
  const r1 = verifyPeer({ agentCard: undefined as unknown as A2AAgentCard, bundle });
  assert.equal(r1.decision, 'indeterminate');
  assert.equal(r1.trusted, false);
  assert.equal(r1.identityBound, false);
  // Malformed AgentCard identity (not a canonical claim reference).
  const r2 = verifyPeer({ agentCard: { name: 'a', identity: { scheme: 'cci', identifier: 'not-a-key' } }, bundle });
  assert.equal(r2.decision, 'indeterminate');
  assert.equal(r2.trusted, false);
});

test('indeterminate peer — do-not-collapse: verifyPeer NEVER returns trusted=true on indeterminate', () => {
  const bundle = honestBundle({ jobId: 'job-dnc', buyer, seller });
  const r = verifyPeer({ agentCard: { name: 'a', identity: { scheme: 'did', identifier: 'not:valid' } } as A2AAgentCard, bundle });
  // A non-cci non-resolvable identity is indeterminate; the invariant is trusted must be false.
  assert.equal(r.trusted, false);
  assert.notEqual(r.decision, 'accept');
});

test('withDacsTrust — trusted peer reaches the handler', async () => {
  let ran = 0;
  const handler = withDacsTrust<string, { agentCard: A2AAgentCard; bundle: AttestationBundleV1 }, string>((task) => {
    ran++;
    return `did:${task}`;
  });
  const bundle = honestBundle({ jobId: 'job-mw-ok', buyer, seller });
  const out = await handler('work', { agentCard: card(seller), bundle });
  assert.equal(out.accepted, true);
  assert.equal(ran, 1);
  if (out.accepted) assert.equal(out.result, 'did:work');
  assert.equal(out.peerTrust.trusted, true);
});

test('withDacsTrust — untrusted peer NEVER calls the handler', async () => {
  let ran = 0;
  const handler = withDacsTrust<string, { agentCard: A2AAgentCard; bundle: AttestationBundleV1 }, string>(() => {
    ran++;
    return 'should-not-happen';
  });
  const bundle = honestBundle({ jobId: 'job-mw-bad', buyer, seller });
  // Impostor: card claims `other`, bundle proves `seller`.
  const out = await handler('work', { agentCard: card(other), bundle });
  assert.equal(out.accepted, false);
  assert.equal(ran, 0, 'handler must NOT run for an untrusted peer');
  assert.equal(out.peerTrust.trusted, false);
  assert.equal(out.peerTrust.killedBy?.check, 'identity-mismatch');
});

test('withDacsTrust — indeterminate peer is DECLINED (do-not-collapse), handler not called', async () => {
  let ran = 0;
  const handler = withDacsTrust<string, { agentCard: A2AAgentCard; bundle: AttestationBundleV1 }, string>(() => {
    ran++;
    return 'nope';
  });
  const bundle = honestBundle({ jobId: 'job-mw-ind', buyer, seller });
  const out = await handler('work', { agentCard: undefined as unknown as A2AAgentCard, bundle });
  assert.equal(out.accepted, false);
  assert.equal(ran, 0);
  assert.equal(out.peerTrust.decision, 'indeterminate');
});
