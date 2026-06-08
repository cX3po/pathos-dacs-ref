/**
 * dacs-disclose P2 — consent / revocation conformance + adversarial vectors.
 *
 * Spec source: `dacs-consent-selective-disclosure-spec-2026-06-07.md` §3 (consent + revocation),
 * §5 P2. OFFLINE — pure in-memory ledger; no network, no devnet, no broadcast.
 *
 * Locks in the P2 guarantees (each maps to a HARD-RULE required scenario):
 *   - grant → disclose ALLOWED                                                  → PASS
 *   - revoke → disclose DENIED (append-supersede)                               → FAIL (denied)
 *   - expired grant → DENIED                                                    → FAIL (denied)
 *   - wrong-audience grant → DENIED                                             → FAIL (denied)
 *   - supersede ordering (later record wins): grant→revoke→grant re-grants      → PASS
 *   - effective-state at a timestamp (granted before expiry, expired after)     → status flips
 *   - commitment-not-covered by the grant                                       → DENIED
 *   - record authenticity (bad grantor sig / tampered body)                     → dropped, fail-closed
 *   - in-memory anchor: append-order, idempotent dedupe, read-immutability      → invariants
 *   - bridge to P1: consent-proven reveal still passes P1's own crypto checks   → PASS
 *
 * Adversarial-validation note (HARD RULE): each guard is independently exercised so that reverting
 * the guard in src/lib/consent.ts makes the matching test fail. See the per-test guard tags.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import {
  attestClaimCommitment,
  computeCommitmentRoot,
  buildMerklePath,
  produceReveal,
  type ClaimCommitment,
  type RevealChallenge,
  type DisclosedClaim,
} from '../../src/lib/disclose.js';
import {
  signConsentRecord,
  verifyConsentRecord,
  computeConsentRecordId,
  resolveEffectiveConsent,
  consentCovers,
  verifyDisclosedClaimWithConsent,
  InMemoryConsentAnchor,
  type ConsentRecord,
  type ConsentRecordBody,
} from '../../src/lib/consent.js';
import type { ClaimReference } from '../../src/types/identity.js';

/* ---------------------------------- fixtures -------------------------------- */

const CLAIM_LEI: ClaimReference = { scheme: 'lei', identifier: '549300ABCDEF12345678' };
const CLAIM_CRD: ClaimReference = { scheme: 'finra-crd', identifier: '1234567' };
const CLAIM_UEI: ClaimReference = { scheme: 'sam-uei', identifier: 'ABC123DEF456' };

const NOW = 1_800_000_000_000;
const FUTURE = NOW + 60_000;
const SCOPE = 'receipt:consent-0001';
const AUDIENCE = 'verifier:acme-marketplace';

/** A grantor keypair reused across a test (the consent issuer). */
function grantor(): { priv: Uint8Array; pubHex: string } {
  const { privKey, pubKey } = generateKeypair();
  return { priv: privKey, pubHex: bytesToHex(pubKey) };
}

/** Build a grant body over a set of commitments. */
function grantBody(
  grantorPubHex: string,
  commitments: string[],
  overrides: Partial<ConsentRecordBody> = {}
): ConsentRecordBody {
  return {
    action: 'grant',
    consent_receipt_id: SCOPE,
    grantor: grantorPubHex,
    audience: AUDIENCE,
    commitments,
    issuedAt: NOW - 10_000,
    expiresAt: FUTURE,
    ...overrides,
  };
}

function revokeBody(
  grantorPubHex: string,
  supersedes: string,
  overrides: Partial<ConsentRecordBody> = {}
): ConsentRecordBody {
  return {
    action: 'revoke',
    consent_receipt_id: SCOPE,
    grantor: grantorPubHex,
    audience: AUDIENCE,
    commitments: [],
    issuedAt: NOW - 5_000,
    expiresAt: FUTURE,
    supersedes,
    ...overrides,
  };
}

/**
 * A full P1 disclosure scene PLUS a holder presentation key, so the bridge tests can verify the
 * disclosed reveal under both consent and P1 crypto.
 */
function discloseScene(reveal: ClaimReference = CLAIM_LEI): {
  commitment: ClaimCommitment;
  setHex: string[];
  root: string;
  disclosed: DisclosedClaim;
  presentationPubKeyHex: string;
  challenge: RevealChallenge;
} {
  const setClaims = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI];
  const commitments = setClaims.map((c) => attestClaimCommitment(c, `verifiedBy:${c.scheme}`));
  const target = commitments.find((c) => c.claim.scheme === reveal.scheme)!;
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);
  const path = buildMerklePath(setHex, target.commitment);
  const challenge: RevealChallenge = {
    verifier_id: AUDIENCE,
    consent_receipt_id: SCOPE,
    nonce: 'nonce-deadbeef-0001',
    expiry: FUTURE,
  };
  const { privKey, pubKey } = generateKeypair();
  const disclosed = produceReveal(target, path, challenge, privKey);
  return { commitment: target, setHex, root, disclosed, presentationPubKeyHex: bytesToHex(pubKey), challenge };
}

/* ===========================================================================
 * §3 element 1 — ConsentRecord: signing, content-addressing, authenticity
 * =========================================================================== */

test('signConsentRecord produces a content-addressed, grantor-signed record that verifies', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const rec = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  assert.equal(rec.recordId, computeConsentRecordId(rec), 'recordId must be the content hash of the body');
  assert.equal(rec.signature.length, 128, '64-byte ed25519 sig as hex');
  assert.ok(verifyConsentRecord(rec), 'a freshly signed record must verify');
});

test('GUARD: a record signed by a key that is NOT the declared grantor → verifyConsentRecord false', () => {
  // Adversarial: declare grantor = G but sign with attacker key. Revert the edVerify check in
  // verifyConsentRecord and this passes-through → test fails. (authenticity guard)
  const g = grantor();
  const attacker = generateKeypair();
  const c = attestClaimCommitment(CLAIM_LEI);
  const rec = signConsentRecord(grantBody(g.pubHex, [c.commitment]), attacker.privKey);
  assert.equal(verifyConsentRecord(rec), false);
});

test('GUARD: a tampered body (commitment swapped after signing) → verifyConsentRecord false', () => {
  // Adversarial: mutate a signed field. Revert the recordId/content-hash recompute and the sig
  // check will still catch it; revert BOTH and this passes → test fails. (integrity guard)
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const rec = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const tampered: ConsentRecord = { ...rec, commitments: [bytesToHex(new Uint8Array(32).fill(9))] };
  assert.equal(verifyConsentRecord(tampered), false);
});

test('GUARD: a record whose recordId is NOT the content hash of its body → verifyConsentRecord false', () => {
  // Isolates the content-hash id check (verifyConsentRecord checks recordId == computeConsentRecordId).
  // Body + signature stay mutually consistent; ONLY recordId is wrong. Revert the id-equality check
  // in verifyConsentRecord and this passes → test fails. (content-addressing guard)
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const rec = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const wrongId: ConsentRecord = { ...rec, recordId: bytesToHex(new Uint8Array(32).fill(0xaa)) };
  assert.equal(verifyConsentRecord(wrongId), false);
});

test('record id is order-independent over the commitment set (canonical body)', () => {
  const g = grantor();
  const a = attestClaimCommitment(CLAIM_LEI).commitment;
  const b = attestClaimCommitment(CLAIM_CRD).commitment;
  const id1 = computeConsentRecordId(grantBody(g.pubHex, [a, b]));
  const id2 = computeConsentRecordId(grantBody(g.pubHex, [b, a]));
  assert.equal(id1, id2, 'commitment-set order must not change the record id');
});

/* ===========================================================================
 * §3 element 2 — effective state: grant / revoke / supersede / expiry
 * =========================================================================== */

test('grant → disclose ALLOWED (effective state = granted, coverage ok)', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const ledger = [grant];
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'granted', eff.reason);
  const cov = consentCovers(ledger, SCOPE, AUDIENCE, c.commitment, { now: NOW });
  assert.equal(cov.ok, true, cov.reason);
});

test('revoke → disclose DENIED (append-supersede: later revoke wins)', () => {
  // GUARD: revoke handling. Revert the 'revoke' branch in resolveEffectiveConsent (treat revoke as
  // no-op) and this resolves to 'granted' → test fails. (revocation guard)
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant.recordId), g.priv);
  const ledger = [grant, revoke]; // append order: grant THEN revoke
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'revoked', eff.reason);
  assert.ok(eff.revokedBy, 'revokedBy must be populated');
  const cov = consentCovers(ledger, SCOPE, AUDIENCE, c.commitment, { now: NOW });
  assert.equal(cov.ok, false);
  assert.match(cov.reason, /not in force: revoked/);
});

test('expired grant → DENIED (window check at now)', () => {
  // GUARD: expiry. Revert the `now >= expiresAt` check and this resolves to 'granted' → test fails.
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { expiresAt: NOW - 1 }), g.priv);
  const ledger = [grant];
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'expired', eff.reason);
  const cov = consentCovers(ledger, SCOPE, AUDIENCE, c.commitment, { now: NOW });
  assert.equal(cov.ok, false);
  assert.match(cov.reason, /expired/);
});

test('grant exactly AT expiry → expired (exclusive upper bound, mirrors P1)', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { expiresAt: NOW }), g.priv);
  const eff = resolveEffectiveConsent([grant], SCOPE, { now: NOW });
  assert.equal(eff.status, 'expired', eff.reason);
});

test('wrong-audience grant → DENIED (consent is audience-scoped)', () => {
  // GUARD: audience coverage. Revert the audience equality check in consentCovers and this passes
  // → test fails. (audience guard)
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(
    grantBody(g.pubHex, [c.commitment], { audience: 'verifier:some-other-marketplace' }),
    g.priv
  );
  const cov = consentCovers([grant], SCOPE, AUDIENCE, c.commitment, { now: NOW });
  assert.equal(cov.ok, false);
  assert.match(cov.reason, /audience mismatch/);
});

test('commitment NOT covered by the grant → DENIED', () => {
  // GUARD: commitment-coverage. Revert the `grant.commitments.includes(target)` check and this
  // passes → test fails. (coverage guard)
  const g = grantor();
  const granted = attestClaimCommitment(CLAIM_LEI);
  const otherCommitment = attestClaimCommitment(CLAIM_CRD).commitment; // NOT in the grant
  const grant = signConsentRecord(grantBody(g.pubHex, [granted.commitment]), g.priv);
  const cov = consentCovers([grant], SCOPE, AUDIENCE, otherCommitment, { now: NOW });
  assert.equal(cov.ok, false);
  assert.match(cov.reason, /not covered/);
});

test('supersede ordering: grant → revoke → grant RE-GRANTS (later append wins)', () => {
  // GUARD: later-append-wins. Resolution must process in append order so the SECOND grant
  // re-establishes consent after a revoke. If the fold short-circuited on first revoke this fails.
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant1 = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant1.recordId, { issuedAt: NOW - 20_000 }), g.priv);
  // A second, byte-distinct grant (different issuedAt) re-establishes consent.
  const grant2 = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 10_000 }), g.priv);
  const ledger = [grant1, revoke, grant2];
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'granted', eff.reason);
  assert.equal(eff.grant?.recordId, grant2.recordId, 'the latest grant must be in force');
});

test('supersede ordering: grant → grant → revoke → DENIED (final revoke wins)', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant1 = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const grant2 = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 20_000 }), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant2.recordId, { issuedAt: NOW - 10_000 }), g.priv);
  const eff = resolveEffectiveConsent([grant1, grant2, revoke], SCOPE, { now: NOW });
  assert.equal(eff.status, 'revoked', eff.reason);
});

test('effective-state at a timestamp: granted BEFORE expiry, expired AFTER (same ledger, different now)', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const expiresAt = NOW + 10_000;
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { expiresAt }), g.priv);
  const ledger = [grant];
  assert.equal(resolveEffectiveConsent(ledger, SCOPE, { now: NOW }).status, 'granted');
  assert.equal(resolveEffectiveConsent(ledger, SCOPE, { now: expiresAt + 1 }).status, 'expired');
});

test('unknown scope → status none', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const eff = resolveEffectiveConsent([grant], 'receipt:never-issued', { now: NOW });
  assert.equal(eff.status, 'none');
});

test('GUARD: an unauthentic record is DROPPED before resolution (fail-closed)', () => {
  // A revoke whose signature does not verify must NOT be able to revoke a valid grant.
  // GUARD: requireValidSignatures filter. Revert it and the forged revoke takes effect → test fails.
  const g = grantor();
  const attacker = generateKeypair();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const forgedRevoke = signConsentRecord(revokeBody(g.pubHex, grant.recordId), attacker.privKey); // wrong key
  const ledger = [grant, forgedRevoke];
  // With signature validation ON (default), the forged revoke is dropped → grant still in force.
  assert.equal(resolveEffectiveConsent(ledger, SCOPE, { now: NOW }).status, 'granted');
  // With validation OFF (test-only escape hatch), the forged revoke would take effect — proving the
  // filter is what protects us.
  assert.equal(
    resolveEffectiveConsent(ledger, SCOPE, { now: NOW, requireValidSignatures: false }).status,
    'revoked'
  );
});

/* ===========================================================================
 * §3 element 3 — anchor interface + in-memory dry-run impl (OFFLINE)
 * =========================================================================== */

test('InMemoryConsentAnchor: append preserves order; read returns append order', async () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant.recordId, { issuedAt: NOW - 20_000 }), g.priv);
  const anchor = new InMemoryConsentAnchor();
  await anchor.append(grant);
  await anchor.append(revoke);
  const out = await anchor.read();
  assert.deepEqual(out.map((r) => r.recordId), [grant.recordId, revoke.recordId]);
});

test('InMemoryConsentAnchor: append is idempotent on recordId (content-addressed dedupe)', async () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const anchor = new InMemoryConsentAnchor();
  await anchor.append(grant);
  await anchor.append(grant); // byte-identical re-append → no-op
  const out = await anchor.read();
  assert.equal(out.length, 1, 'duplicate append must not grow the ledger');
});

test('GUARD: InMemoryConsentAnchor rejects an unauthentic record on append (fail-closed)', async () => {
  // Revert the verifyConsentRecord check in append() and this no longer throws → test fails.
  const g = grantor();
  const attacker = generateKeypair();
  const c = attestClaimCommitment(CLAIM_LEI);
  const bad = signConsentRecord(grantBody(g.pubHex, [c.commitment]), attacker.privKey); // wrong key
  const anchor = new InMemoryConsentAnchor();
  await assert.rejects(() => anchor.append(bad), /unauthentic record/);
});

test('InMemoryConsentAnchor: read() returns a copy — callers cannot mutate the ledger', async () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment]), g.priv);
  const anchor = new InMemoryConsentAnchor();
  await anchor.append(grant);
  const out = await anchor.read();
  out.push({} as ConsentRecord); // mutate the returned array
  const out2 = await anchor.read();
  assert.equal(out2.length, 1, 'mutating the read result must not affect the ledger');
});

test('anchor read → resolve round-trip: grant then revoke via the anchor resolves to revoked', async () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant.recordId, { issuedAt: NOW - 20_000 }), g.priv);
  const anchor = new InMemoryConsentAnchor();
  await anchor.append(grant);
  await anchor.append(revoke);
  const eff = resolveEffectiveConsent(await anchor.read(), SCOPE, { now: NOW });
  assert.equal(eff.status, 'revoked');
});

/* ===========================================================================
 * §3 element 4 — bridge P1 ↔ P2 (verifyDisclosedClaimWithConsent)
 * =========================================================================== */

test('bridge: grant covering the disclosed commitment → P1 reveal PASSES under consent', () => {
  const g = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [scene.commitment.commitment]), g.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant],
    expectedGrantor: g.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'pass', result.reason);
});

test('bridge: revoked consent → DENIED before P1 even runs', () => {
  const g = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [scene.commitment.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const revoke = signConsentRecord(revokeBody(g.pubHex, grant.recordId, { issuedAt: NOW - 20_000 }), g.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant, revoke],
    expectedGrantor: g.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent denied/);
});

test('bridge: expired consent → DENIED', () => {
  const g = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [scene.commitment.commitment], { expiresAt: NOW - 1 }), g.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant],
    expectedGrantor: g.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent denied/);
});

test('bridge: grant to a DIFFERENT audience → DENIED (audience mismatch)', () => {
  const g = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(
    grantBody(g.pubHex, [scene.commitment.commitment], { audience: 'verifier:not-this-one' }),
    g.priv
  );
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant],
    expectedGrantor: g.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent denied/);
});

test('bridge: consent OK but P1 crypto fails (wrong nonce) → still FAIL (P1 stays fail-closed)', () => {
  // Defence in depth: even with valid consent, a P1 violation must still block. Proves the bridge
  // does NOT weaken P1's own checks.
  const g = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [scene.commitment.commitment]), g.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant],
    expectedGrantor: g.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: 'a-DIFFERENT-nonce-than-the-reveal-bound', // P1 will reject this
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /nonce mismatch/); // came from P1, not the consent layer
});

test('bridge: no consent record at all → DENIED (fail-closed, status none)', () => {
  const scene = discloseScene(CLAIM_LEI);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [], // empty ledger
    expectedGrantor: bytesToHex(new Uint8Array(32).fill(1)), // any grantor — ledger is empty anyway
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /consent denied/);
});

/* ===========================================================================
 * FIX 1 — append-supersede AUTHORITY bound to the establishing grantor
 *   The FIRST authentic grant for a scope establishes the authoritative grantor. Any later
 *   grant/revoke for that scope from a DIFFERENT (but validly-signed) grantor is IGNORED.
 *   Adversarial validation: revert the establishingGrantor binding in resolveEffectiveConsent
 *   and each of these flips (attacker revoke takes effect / attacker grant re-establishes).
 * =========================================================================== */

test('FIX 1 GUARD: attacker REVOKE (different grantor, validly signed) → IGNORED, grant still in force', () => {
  // The victim grants. An ATTACKER (a real keypair, signs its OWN valid record) appends a revoke
  // for the SAME consent_receipt_id but with grantor=attackerPub. verifyConsentRecord PASSES the
  // attacker's revoke (it IS validly signed by the named attacker key) — so the ONLY thing that can
  // stop it from revoking the victim's scope is the establishing-grantor authority binding.
  const victim = grantor();
  const attacker = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(victim.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), victim.priv);
  // Attacker self-signs a revoke for the victim's scope, naming ITSELF as grantor.
  const attackerRevoke = signConsentRecord(
    revokeBody(attacker.pubHex, grant.recordId, { issuedAt: NOW - 10_000 }),
    attacker.priv
  );
  // Sanity: the attacker's revoke is genuinely authentic (so it survives the signature filter) —
  // proving this test exercises AUTHORITY, not authenticity.
  assert.ok(verifyConsentRecord(attackerRevoke), 'attacker revoke must be validly signed (authentic)');
  const ledger = [grant, attackerRevoke];
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'granted', `attacker revoke must be IGNORED — ${eff.reason}`);
  assert.equal(eff.grant?.recordId, grant.recordId, 'the victim grant must still be in force');
});

test('FIX 1 GUARD: attacker GRANT (different grantor) for an existing scope → IGNORED', () => {
  // After the victim revokes their OWN scope, an attacker tries to RE-ESTABLISH consent with its own
  // grant. Without the authority binding, "later grant wins" would let the attacker re-grant.
  const victim = grantor();
  const attacker = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(victim.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), victim.priv);
  const victimRevoke = signConsentRecord(revokeBody(victim.pubHex, grant.recordId, { issuedAt: NOW - 20_000 }), victim.priv);
  const attackerGrant = signConsentRecord(grantBody(attacker.pubHex, [c.commitment], { issuedAt: NOW - 10_000 }), attacker.priv);
  assert.ok(verifyConsentRecord(attackerGrant), 'attacker grant must be validly signed (authentic)');
  const ledger = [grant, victimRevoke, attackerGrant];
  const eff = resolveEffectiveConsent(ledger, SCOPE, { now: NOW });
  assert.equal(eff.status, 'revoked', `attacker grant must NOT re-establish consent — ${eff.reason}`);
});

test('FIX 1: legitimate grantor REVOKE (same grantor) → applied (authority preserved for the owner)', () => {
  // The establishing grantor MUST still be able to revoke/supersede its own scope — the fix must not
  // over-block the legitimate owner.
  const victim = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(victim.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), victim.priv);
  const ownRevoke = signConsentRecord(revokeBody(victim.pubHex, grant.recordId, { issuedAt: NOW - 10_000 }), victim.priv);
  const eff = resolveEffectiveConsent([grant, ownRevoke], SCOPE, { now: NOW });
  assert.equal(eff.status, 'revoked', `the legitimate grantor must be able to revoke — ${eff.reason}`);
});

test('FIX 1: legitimate grantor RE-GRANT (same grantor) after own revoke → re-established', () => {
  // Full owner lifecycle still works: grant → own-revoke → own-regrant re-establishes consent.
  const victim = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant1 = signConsentRecord(grantBody(victim.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), victim.priv);
  const ownRevoke = signConsentRecord(revokeBody(victim.pubHex, grant1.recordId, { issuedAt: NOW - 20_000 }), victim.priv);
  const grant2 = signConsentRecord(grantBody(victim.pubHex, [c.commitment], { issuedAt: NOW - 10_000 }), victim.priv);
  const eff = resolveEffectiveConsent([grant1, ownRevoke, grant2], SCOPE, { now: NOW });
  assert.equal(eff.status, 'granted', `owner re-grant must re-establish — ${eff.reason}`);
  assert.equal(eff.grant?.recordId, grant2.recordId);
});

test('FIX 1: a scope that OPENS with a revoke (no prior grant) has no authority → stays none', () => {
  // Establishing grantor is set by the first GRANT, not a revoke. A lone (authentic) revoke for an
  // un-granted scope cannot establish authority and cannot revoke anything.
  const someone = grantor();
  const lonelyRevoke = signConsentRecord(revokeBody(someone.pubHex, 'no-such-grant', { issuedAt: NOW - 10_000 }), someone.priv);
  const eff = resolveEffectiveConsent([lonelyRevoke], SCOPE, { now: NOW });
  assert.equal(eff.status, 'none', `a revoke with no prior grant cannot establish/withdraw — ${eff.reason}`);
});

test('FIX 1 (bridge): attacker revoke does not deny a legitimately-granted disclosure', () => {
  // End-to-end through the P1 bridge: an attacker revoke must not be able to deny a valid disclosure.
  const victim = grantor();
  const attacker = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(victim.pubHex, [scene.commitment.commitment], { issuedAt: NOW - 30_000 }), victim.priv);
  const attackerRevoke = signConsentRecord(revokeBody(attacker.pubHex, grant.recordId, { issuedAt: NOW - 10_000 }), attacker.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant, attackerRevoke],
    expectedGrantor: victim.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'pass', `attacker revoke must not deny a valid disclosure — ${result.reason}`);
});

/* ===========================================================================
 * FIX 2 — verifyDisclosedClaimWithConsent enforces expectedGrantor authority
 *   A grant signed by an unrelated key, even if it covers the commitment + audience, must NOT
 *   satisfy "consent proven" unless its grantor === expectedGrantor. Missing expectedGrantor throws.
 * =========================================================================== */

test('FIX 2 GUARD: grant by an UNRELATED key but expectedGrantor = the legit key → DENIED', () => {
  // The grant is for the right scope/audience/commitment and is validly signed — but by an unrelated
  // grantor. The verifier expects a DIFFERENT grantor (the legit subject). Revert the grantor-equality
  // check in verifyDisclosedClaimWithConsent and this passes → test fails. (authority guard)
  const unrelated = grantor();
  const legit = grantor();
  const scene = discloseScene(CLAIM_LEI);
  // The unrelated key establishes the scope (so resolution yields 'granted') and covers the commitment.
  const unrelatedGrant = signConsentRecord(grantBody(unrelated.pubHex, [scene.commitment.commitment]), unrelated.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [unrelatedGrant],
    expectedGrantor: legit.pubHex, // verifier expects the LEGIT subject, not the unrelated signer
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'fail', result.reason);
  assert.match(result.reason, /grantor authority mismatch/);
});

test('FIX 2: grant by expectedGrantor → PASS', () => {
  const legit = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(legit.pubHex, [scene.commitment.commitment]), legit.priv);
  const result = verifyDisclosedClaimWithConsent(scene.disclosed, {
    ledger: [grant],
    expectedGrantor: legit.pubHex,
    signedRoot: scene.root,
    presentationPubKey: scene.presentationPubKeyHex,
    expectedVerifierId: AUDIENCE,
    expectedNonce: scene.challenge.nonce,
    now: NOW,
  });
  assert.equal(result.decision, 'pass', result.reason);
});

test('FIX 2 GUARD: missing expectedGrantor → THROWS (fail-closed config gate)', () => {
  // Mirror P1's consent fail-closed config gate. Omitting expectedGrantor is a misconfiguration,
  // not a verdict. Revert the throw in verifyDisclosedClaimWithConsent and this no longer throws → fail.
  const legit = grantor();
  const scene = discloseScene(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(legit.pubHex, [scene.commitment.commitment]), legit.priv);
  assert.throws(
    () =>
      verifyDisclosedClaimWithConsent(scene.disclosed, {
        // expectedGrantor deliberately omitted
        ledger: [grant],
        signedRoot: scene.root,
        presentationPubKey: scene.presentationPubKeyHex,
        expectedVerifierId: AUDIENCE,
        expectedNonce: scene.challenge.nonce,
        now: NOW,
      } as unknown as Parameters<typeof verifyDisclosedClaimWithConsent>[1]),
    /expectedGrantor is REQUIRED/
  );
});

/* ===========================================================================
 * FIX 3 — verifyConsentRecord rejects unknown `action` values at runtime
 *   TS narrows action at compile time only; chain/read JSON is untrusted. A signed record with an
 *   action other than exactly 'grant'|'revoke' must be rejected before it can affect resolution.
 * =========================================================================== */

test('FIX 3 GUARD: a signed record with action:"foo" → verifyConsentRecord false, no effect on state', () => {
  // Build a record whose action is an UNKNOWN string, signed honestly by the grantor over its own
  // (bogus-action) body so the content hash + signature are internally consistent. The ONLY thing
  // that should reject it is the explicit action-allowlist in verifyConsentRecord. Revert that gate
  // and the record verifies → the resolver's "non-grant == revoke" branch would treat it as a revoke.
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  // Cast through the body type — runtime JSON can carry any string here.
  const badBody = grantBody(g.pubHex, [c.commitment]);
  (badBody as { action: string }).action = 'foo';
  const bad = signConsentRecord(badBody as ConsentRecordBody, g.priv);
  assert.equal(bad.action as string, 'foo', 'precondition: record carries the unknown action');
  assert.equal(verifyConsentRecord(bad), false, 'an unknown action must be rejected');
});

test('FIX 3: an unknown-action record cannot revoke a valid grant (dropped at intake)', () => {
  // The attacker (here even the same grantor) tries to use a bogus action to slip a "revoke" past the
  // authenticity check — verifyConsentRecord(false) → dropped by the resolver's signature filter.
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const grant = signConsentRecord(grantBody(g.pubHex, [c.commitment], { issuedAt: NOW - 30_000 }), g.priv);
  const badRevokeBody = revokeBody(g.pubHex, grant.recordId, { issuedAt: NOW - 10_000 });
  (badRevokeBody as { action: string }).action = 'revoke-ish'; // not exactly 'revoke'
  const badRevoke = signConsentRecord(badRevokeBody as ConsentRecordBody, g.priv);
  const eff = resolveEffectiveConsent([grant, badRevoke], SCOPE, { now: NOW });
  assert.equal(eff.status, 'granted', `unknown-action record must not revoke — ${eff.reason}`);
});

test('FIX 3 GUARD: a record with MISSING action → verifyConsentRecord false', () => {
  const g = grantor();
  const c = attestClaimCommitment(CLAIM_LEI);
  const noActionBody = grantBody(g.pubHex, [c.commitment]);
  delete (noActionBody as { action?: string }).action;
  const bad = signConsentRecord(noActionBody as ConsentRecordBody, g.priv);
  assert.equal(verifyConsentRecord(bad), false, 'a missing action must be rejected');
});
