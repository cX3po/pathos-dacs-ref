/**
 * dacs-disclose P3 — dispute-evidence bundle tests.
 *
 * Coverage map (every guarantee verifyDisputeBundle makes has a happy-path AND an adversarial test):
 *   - happy path: a bundle where presenter === grantor === reveal-signer verifies.
 *   - OPTION A: a bundle whose consent was granted by a DIFFERENT key than the presenter is REJECTED
 *     (this is the whole reason P3 exists; the in-layer expectedGrantor:=presenter forces it).
 *   - root binding: a tampered root / wrong-key rootSig is REJECTED.
 *   - shared challenge: a mixed-challenge bundle is REJECTED (and assemble throws).
 *   - unguessability: a short/non-hex consent_receipt_id is REJECTED.
 *   - single-use: a replayed bundle is REJECTED; a FAILED bundle does NOT burn the scope.
 *   - audience/nonce: wrong resolver id / wrong nonce REJECTED.
 *   - misconfiguration: missing expectedVerifierId/Nonce/consumption THROW (not a verdict).
 *   - mintConsentReceiptId: floor enforced; output is unguessable hex.
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
  type DisclosedClaim,
  type RevealChallenge,
} from '../../src/lib/disclose.js';
import { signConsentRecord, type ConsentRecord, type ConsentRecordBody } from '../../src/lib/consent.js';
import {
  assembleDisputeBundle,
  verifyDisputeBundle,
  mintConsentReceiptId,
  signBundleRoot,
  InMemoryConsumptionStore,
  MIN_RECEIPT_ID_BYTES,
  MIN_RECEIPT_ID_HEX_LEN,
  type DisputeEvidenceBundle,
} from '../../src/lib/dispute.js';
import type { ClaimReference } from '../../src/types/identity.js';

/* ---------------------------------- fixtures -------------------------------- */

const CLAIM_LEI: ClaimReference = { scheme: 'lei', identifier: '549300ABCDEF12345678' };
const CLAIM_CRD: ClaimReference = { scheme: 'finra-crd', identifier: '1234567' };
const CLAIM_UEI: ClaimReference = { scheme: 'sam-uei', identifier: 'ABC123DEF456' };

const NOW = 1_800_000_000_000;
const FUTURE = NOW + 60_000;
const RESOLVER = 'resolver:dispute-court-7';
const NONCE = 'nonce-court-aaaa-0001';

/**
 * Build a full scene where ONE keypair is presenter + grantor + reveal-signer (the option-A model).
 * Returns the assembled bundle plus the keypair + scope so tests can mutate pieces adversarially.
 */
function scene(opts: {
  reveal?: ClaimReference[];
  scope?: string;
  grantorKeyOverride?: Uint8Array; // sign the consent with a DIFFERENT key (option-A attack)
  grantorPubOverride?: string;     // declare a different grantor pub in the consent body
  challengeOverride?: Partial<RevealChallenge>;
} = {}): {
  bundle: DisputeEvidenceBundle;
  presenterPub: string;
  presenterPriv: Uint8Array;
  scope: string;
  root: string;
} {
  const reveal = opts.reveal ?? [CLAIM_LEI];
  const scope = opts.scope ?? mintConsentReceiptId();
  const presenter = generateKeypair();
  const presenterPub = bytesToHex(presenter.pubKey);

  // commitment set + root
  const setClaims = [CLAIM_LEI, CLAIM_CRD, CLAIM_UEI];
  const commitments: ClaimCommitment[] = setClaims.map((c) => attestClaimCommitment(c, `verifiedBy:${c.scheme}`));
  const setHex = commitments.map((c) => c.commitment);
  const root = computeCommitmentRoot(setHex);

  const challenge: RevealChallenge = {
    verifier_id: RESOLVER,
    consent_receipt_id: scope,
    nonce: NONCE,
    expiry: FUTURE,
    ...opts.challengeOverride,
  };

  // produce one reveal per requested claim, all under the SAME challenge, signed by the PRESENTER
  const disclosures: DisclosedClaim[] = reveal.map((rc) => {
    const target = commitments.find((c) => c.claim.scheme === rc.scheme)!;
    const path = buildMerklePath(setHex, target.commitment);
    return produceReveal(target, path, challenge, presenter.privKey);
  });

  // consent grant: by default signed BY the presenter and declaring the presenter as grantor
  const grantorPub = opts.grantorPubOverride ?? presenterPub;
  const grantorSignKey = opts.grantorKeyOverride ?? presenter.privKey;
  const grantBody: ConsentRecordBody = {
    action: 'grant',
    consent_receipt_id: scope,
    grantor: grantorPub,
    audience: RESOLVER,
    commitments: reveal.map((rc) => commitments.find((c) => c.claim.scheme === rc.scheme)!.commitment),
    issuedAt: NOW - 10_000,
    expiresAt: FUTURE,
  };
  const grant: ConsentRecord = signConsentRecord(grantBody, grantorSignKey);

  const bundle = assembleDisputeBundle({
    presentationPubKey: presenterPub,
    presenterPriv: presenter.privKey,
    signedRoot: root,
    disclosures,
    consentLedger: [grant],
  });

  return { bundle, presenterPub, presenterPriv: presenter.privKey, scope, root };
}

function opts(over: Partial<Parameters<typeof verifyDisputeBundle>[1]> = {}) {
  return {
    expectedVerifierId: RESOLVER,
    expectedNonce: NONCE,
    consumption: new InMemoryConsumptionStore(),
    now: NOW,
    ...over,
  };
}

/* =========================================================================== */
/* happy path                                                                  */
/* =========================================================================== */

test('happy path: presenter===grantor bundle verifies (single disclosure)', () => {
  const s = scene();
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.perDisclosure.length, 1);
});

test('happy path: multi-disclosure bundle under one challenge verifies', () => {
  const s = scene({ reveal: [CLAIM_LEI, CLAIM_CRD] });
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.perDisclosure.length, 2);
});

/* =========================================================================== */
/* OPTION A — the headline guarantee                                           */
/* =========================================================================== */

test('OPTION A: consent granted by a DIFFERENT key than the presenter is REJECTED', () => {
  // The attack P3 exists to stop: a real, valid consent — but granted by someone OTHER than the
  // entity presenting the evidence. P2 alone (caller-set expectedGrantor) could be fooled; P3 forces
  // expectedGrantor := presenter, so a grant by another key is not authority over THIS presentation.
  const other = generateKeypair();
  const s = scene({ grantorKeyOverride: other.privKey, grantorPubOverride: bytesToHex(other.pubKey) });
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /grantor authority mismatch|consent denied/i);
});

test('OPTION A: a grant DECLARING the presenter but SIGNED by another key is REJECTED (authenticity)', () => {
  // grantor pub says "presenter" but the signature is the attacker's → verifyConsentRecord fails
  // inside the bridge → consent denied. Confirms we cannot spoof authority by just naming the presenter.
  const other = generateKeypair();
  const s = scene({ grantorKeyOverride: other.privKey }); // grantorPub defaults to presenter
  // P3 forces requireValidSignatures in-layer (Codex finding 2) — the caller need NOT (and cannot)
  // pass it; a grant declaring the presenter but signed by another key must fail by default.
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /consent denied|signature/i);
});

/* =========================================================================== */
/* root binding                                                                 */
/* =========================================================================== */

test('root binding: a tampered signedRoot is REJECTED', () => {
  const s = scene();
  const tampered: DisputeEvidenceBundle = { ...s.bundle, signedRoot: 'deadbeef'.repeat(8) };
  const r = verifyDisputeBundle(tampered, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /root binding failed/i);
});

test('root binding: rootSig by a non-presenter key is REJECTED', () => {
  const s = scene();
  const attacker = generateKeypair();
  const forged: DisputeEvidenceBundle = { ...s.bundle, rootSig: signBundleRoot(s.bundle.signedRoot, attacker.privKey) };
  const r = verifyDisputeBundle(forged, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /root binding failed/i);
});

/* =========================================================================== */
/* shared challenge                                                             */
/* =========================================================================== */

test('shared challenge: a mixed-challenge bundle is REJECTED at verify', () => {
  const s = scene({ reveal: [CLAIM_LEI, CLAIM_CRD] });
  // mutate the second disclosure's challenge nonce → divergence
  const d1 = s.bundle.disclosures[1]!;
  const mixed: DisputeEvidenceBundle = {
    ...s.bundle,
    disclosures: [s.bundle.disclosures[0]!, { ...d1, challenge: { ...d1.challenge, nonce: 'different-nonce' } }],
  };
  const r = verifyDisputeBundle(mixed, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /mixed-challenge/i);
});

test('robustness: a later disclosure missing its challenge returns a FAIL verdict (never throws)', () => {
  // Untrusted artifact: a malformed second disclosure with no `challenge`. verifyDisputeBundle must
  // return {ok:false}, NOT throw (only resolver misconfiguration throws). (Codex finding 3.)
  const s = scene({ reveal: [CLAIM_LEI, CLAIM_CRD] });
  const d1 = s.bundle.disclosures[1]!;
  const malformed = { ...d1 } as Record<string, unknown>;
  delete malformed.challenge;
  const bad: DisputeEvidenceBundle = {
    ...s.bundle,
    disclosures: [s.bundle.disclosures[0]!, malformed as unknown as DisclosedClaim],
  };
  let r: ReturnType<typeof verifyDisputeBundle>;
  assert.doesNotThrow(() => { r = verifyDisputeBundle(bad, opts()); });
  assert.equal(r!.ok, false);
  assert.match(r!.reason, /missing its challenge|mixed-challenge/i);
});

test('single-use: consumeIfAbsent is the atomic gate — second consume of the same key loses', () => {
  // Directly exercise the CAS contract the concurrent-replay fix depends on (Codex finding 1).
  const store = new InMemoryConsumptionStore();
  assert.equal(store.consumeIfAbsent('k'), true, 'first consume wins');
  assert.equal(store.consumeIfAbsent('k'), false, 'second consume of same key loses');
  assert.equal(store.consumeIfAbsent('k2'), true, 'a different key still wins');
});

test('shared challenge: assembleDisputeBundle THROWS on a mixed-challenge bundle', () => {
  const s = scene({ reveal: [CLAIM_LEI, CLAIM_CRD] });
  const d1 = s.bundle.disclosures[1]!;
  assert.throws(
    () =>
      assembleDisputeBundle({
        presentationPubKey: s.presenterPub,
        presenterPriv: s.presenterPriv,
        signedRoot: s.root,
        disclosures: [s.bundle.disclosures[0]!, { ...d1, challenge: { ...d1.challenge, expiry: FUTURE + 1 } }],
        consentLedger: s.bundle.consentLedger,
      }),
    /mixed-challenge/i
  );
});

/* =========================================================================== */
/* unguessability of consent_receipt_id                                         */
/* =========================================================================== */

test('unguessability: a short consent_receipt_id is REJECTED', () => {
  const s = scene({ scope: 'abcd1234' }); // 8 hex chars < floor
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /too short|unguessability/i);
});

test('unguessability: a non-hex consent_receipt_id is REJECTED', () => {
  const s = scene({ scope: 'receipt:not-hex-scope-id-that-is-long-enough-to-pass-length' });
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /must be hex/i);
});

test('unguessability: an odd-length (non-byte-aligned) consent_receipt_id is REJECTED', () => {
  // 33 hex chars — passes the length floor but is not byte-derived; a real minted id is even-length.
  const s = scene({ scope: 'a'.repeat(MIN_RECEIPT_ID_HEX_LEN + 1) });
  const r = verifyDisputeBundle(s.bundle, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /non-canonical|byte-aligned/i);
});

/* =========================================================================== */
/* single-use / replay                                                          */
/* =========================================================================== */

test('unguessability: a caller override CANNOT weaken the absolute floor (NaN/0/negative ignored)', () => {
  // Codex round-2: minReceiptIdHexLen is a raise-only knob. A short scope must still be rejected even
  // when the caller tries to disable the gate with NaN / 0 / a negative override.
  for (const bad of [Number.NaN, 0, -1, 2]) {
    const s = scene({ scope: 'abcd' }); // 4 hex chars — below the 32-char floor
    const r = verifyDisputeBundle(s.bundle, opts({ minReceiptIdHexLen: bad as number }));
    assert.equal(r.ok, false, `override ${bad} must not let a short scope through`);
    assert.match(r.reason, /too short|unguessability/i);
  }
});

test('single-use: replaying the same bundle is REJECTED the second time', () => {
  const s = scene();
  const store = new InMemoryConsumptionStore();
  const first = verifyDisputeBundle(s.bundle, opts({ consumption: store }));
  assert.equal(first.ok, true, first.reason);
  const second = verifyDisputeBundle(s.bundle, opts({ consumption: store }));
  assert.equal(second.ok, false);
  assert.match(second.reason, /replay/i);
});

test('single-use: a FAILED bundle does NOT burn the scope (no griefing)', () => {
  // present a doomed bundle (wrong nonce) on a shared store, then a VALID bundle on the same scope
  // under the correct challenge must still pass — the failed attempt must not have consumed anything.
  const s = scene();
  const store = new InMemoryConsumptionStore();
  const doomed = verifyDisputeBundle(s.bundle, opts({ consumption: store, expectedNonce: 'wrong-nonce' }));
  assert.equal(doomed.ok, false);
  const good = verifyDisputeBundle(s.bundle, opts({ consumption: store }));
  assert.equal(good.ok, true, good.reason);
});

/* =========================================================================== */
/* audience / nonce                                                             */
/* =========================================================================== */

test('audience: a bundle for a different resolver is REJECTED', () => {
  const s = scene();
  const r = verifyDisputeBundle(s.bundle, opts({ expectedVerifierId: 'resolver:someone-else' }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /audience mismatch/i);
});

test('nonce: a bundle under a stale nonce is REJECTED', () => {
  const s = scene();
  const r = verifyDisputeBundle(s.bundle, opts({ expectedNonce: 'stale-nonce' }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /nonce mismatch/i);
});

/* =========================================================================== */
/* expiry (delegated to P1, asserted end-to-end here)                           */
/* =========================================================================== */

test('expiry: a bundle verified AFTER the challenge expiry is REJECTED', () => {
  const s = scene();
  const r = verifyDisputeBundle(s.bundle, opts({ now: FUTURE + 1 }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /expired/i);
});

/* =========================================================================== */
/* misconfiguration → throw                                                     */
/* =========================================================================== */

test('misconfig: missing expectedVerifierId THROWS', () => {
  const s = scene();
  assert.throws(() => verifyDisputeBundle(s.bundle, opts({ expectedVerifierId: '' as unknown as string })), /expectedVerifierId is REQUIRED/);
});

test('misconfig: missing expectedNonce THROWS', () => {
  const s = scene();
  assert.throws(() => verifyDisputeBundle(s.bundle, opts({ expectedNonce: '' as unknown as string })), /expectedNonce is REQUIRED/);
});

test('misconfig: missing ConsumptionStore THROWS', () => {
  const s = scene();
  assert.throws(
    () => verifyDisputeBundle(s.bundle, { expectedVerifierId: RESOLVER, expectedNonce: NONCE, now: NOW } as unknown as Parameters<typeof verifyDisputeBundle>[1]),
    /ConsumptionStore.*REQUIRED/
  );
});

/* =========================================================================== */
/* mintConsentReceiptId                                                          */
/* =========================================================================== */

test('mintConsentReceiptId: default output passes the unguessability floor + is hex', () => {
  const id = mintConsentReceiptId();
  assert.ok(/^[0-9a-f]+$/.test(id), 'hex');
  assert.ok(id.length >= MIN_RECEIPT_ID_HEX_LEN, `>= ${MIN_RECEIPT_ID_HEX_LEN} hex chars`);
});

test('mintConsentReceiptId: below the byte floor THROWS', () => {
  assert.throws(() => mintConsentReceiptId(MIN_RECEIPT_ID_BYTES - 1), /unguessability floor/i);
});

test('mintConsentReceiptId: two mints are distinct (CSPRNG, not a counter)', () => {
  assert.notEqual(mintConsentReceiptId(), mintConsentReceiptId());
});

/* =========================================================================== */
/* empty bundle                                                                  */
/* =========================================================================== */

test('empty bundle: zero disclosures is REJECTED at verify (and assemble throws)', () => {
  const s = scene();
  const empty: DisputeEvidenceBundle = { ...s.bundle, disclosures: [] };
  const r = verifyDisputeBundle(empty, opts());
  assert.equal(r.ok, false);
  assert.match(r.reason, /empty bundle/i);
  assert.throws(
    () => assembleDisputeBundle({ presentationPubKey: s.presenterPub, presenterPriv: s.presenterPriv, signedRoot: s.root, disclosures: [], consentLedger: [] }),
    />= 1 disclosure/
  );
});
