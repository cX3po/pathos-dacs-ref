/**
 * Conformance family: selective-disclosure reveal verification (OFFLINE).
 *
 * Exercises `verifyDisclosedClaim` — audience binding, nonce/replay binding, consent-scope binding,
 * freshness window, salt floor (>=128-bit), Merkle membership against the bundle-signed root, and the
 * reveal signature under the holder's presentation key. All pure ed25519 / sha256 / Merkle, no chain.
 *
 * The valid case is a real reveal produced by the repo's own `produceReveal` over a real Merkle path.
 * Each negative mutates exactly one input field; the verifier's fail-closed ordering
 * (audience → nonce → consent → expiry → salt → membership → signature) guarantees the targeted
 * predicate is the one that trips first, so each negative isolates a single predicate.
 */
import * as ed25519 from '@noble/ed25519';
import {
  computeCommitment,
  computeCommitmentRoot,
  buildMerklePath,
  produceReveal,
  verifyDisclosedClaim,
  type ClaimCommitment,
  type DisclosedClaim,
  type VerifyDisclosedOptions,
} from '../../../src/lib/disclose.js';
import type { ClaimReference } from '../../../src/types/identity.js';
import type { ConformanceCase, Decision, Family } from '../types.js';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const seed = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);
const clone = <T>(x: T): T => structuredClone(x);

const PRES_PRIV = seed(0x61);
const PRES_PUB = toHex(ed25519.getPublicKey(PRES_PRIV));

// Fixed 32-byte (256-bit) salts — above the 128-bit floor; deterministic.
const SALT_TARGET = '7a'.repeat(32);
const SALT_OTHER = '5c'.repeat(32);

const CLAIM: ClaimReference = { scheme: 'naics', identifier: '541511' };
const OTHER_CLAIM: ClaimReference = { scheme: 'lei', identifier: '5493000000000000XXXX' };

const VERIFIER_ID = 'verifier-A';
const SCOPE = 'consent-scope-0001';
const NONCE = 'nonce-fixed-0001';
const NOW = 1780000000000;
const EXPIRY = NOW + 1_000_000;

/** Build the deterministic valid disclosed-claim artifact + the matching verifier options. */
function buildValid(): { disclosed: DisclosedClaim; options: VerifyDisclosedOptions } {
  const targetCommit = computeCommitment(SALT_TARGET, CLAIM);
  const otherCommit = computeCommitment(SALT_OTHER, OTHER_CLAIM);
  const set = [targetCommit, otherCommit];
  const root = computeCommitmentRoot(set);
  const path = buildMerklePath(set, targetCommit);

  const commitment: ClaimCommitment = { claim: CLAIM, salt: SALT_TARGET, commitment: targetCommit };
  const challenge = { verifier_id: VERIFIER_ID, consent_receipt_id: SCOPE, nonce: NONCE, expiry: EXPIRY };
  const disclosed = produceReveal(commitment, path, challenge, PRES_PRIV);

  const options: VerifyDisclosedOptions = {
    signedRoot: root,
    presentationPubKey: PRES_PUB,
    expectedVerifierId: VERIFIER_ID,
    expectedNonce: NONCE,
    expectedConsentReceiptId: SCOPE,
    now: NOW,
  };
  return { disclosed, options };
}

interface DiscloseInput {
  disclosed: DisclosedClaim;
  options: VerifyDisclosedOptions;
}

interface Case {
  predicate: string;
  reason: string;
  mutate(v: DiscloseInput): DiscloseInput;
}

const CASES: Case[] = [
  { predicate: 'audience-binding', reason: 'reveal must bind THIS verifier_id', mutate: (v) => { v.options.expectedVerifierId = 'verifier-B'; return v; } },
  { predicate: 'nonce-binding', reason: 'reveal must carry the nonce THIS challenge issued', mutate: (v) => { v.options.expectedNonce = 'nonce-other'; return v; } },
  { predicate: 'consent-scope-binding', reason: 'reveal must bind the consent scope the verifier operates under', mutate: (v) => { v.options.expectedConsentReceiptId = 'other-scope'; return v; } },
  { predicate: 'freshness-window', reason: 'reveal must be unexpired (now < expiry)', mutate: (v) => { v.options.now = EXPIRY + 1; return v; } },
  { predicate: 'salt-floor', reason: 'salt must be >=128-bit', mutate: (v) => { v.disclosed.salt = 'ab'; return v; } },
  { predicate: 'merkle-membership', reason: 'recomputed commitment must fold to the signed root', mutate: (v) => { v.disclosed.claim = OTHER_CLAIM; return v; } },
  {
    predicate: 'reveal-signature',
    reason: 'reveal_sig must verify under the presentation key',
    mutate: (v) => {
      const s = v.disclosed.reveal_sig;
      v.disclosed.reveal_sig = (s[0] === '0' ? '1' : '0') + s.slice(1);
      return v;
    },
  },
];

export const discloseFamily: Family = {
  name: 'disclose',

  buildCases(): ConformanceCase[] {
    const v0 = buildValid();
    const cases: ConformanceCase[] = [
      { name: 'disclose/valid', family: 'disclose', predicate: 'valid', expected: 'ACCEPT', reason: 'audience+nonce+consent+freshness+membership+signature all satisfied', input: v0 },
    ];
    for (const c of CASES) {
      const mutated = c.mutate(clone(buildValid()));
      cases.push({
        name: `disclose/${c.predicate}`,
        family: 'disclose',
        predicate: c.predicate,
        expected: 'REJECT',
        reason: c.reason,
        input: mutated,
      });
    }
    return cases;
  },

  run(rawInput: unknown): { decision: Decision; detail: string } {
    const i = rawInput as DiscloseInput;
    let res;
    try {
      res = verifyDisclosedClaim(i.disclosed, i.options);
    } catch (e) {
      // A thrown error here is a config contradiction, not a per-reveal verdict — surface as REJECT.
      return { decision: 'REJECT', detail: `threw: ${(e as Error).message}` };
    }
    return { decision: res.ok ? 'ACCEPT' : 'REJECT', detail: res.reason };
  },
};
