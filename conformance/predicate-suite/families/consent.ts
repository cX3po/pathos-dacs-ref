/**
 * Conformance family: consent record authenticity + effective-state coverage (OFFLINE).
 *
 * Exercises `consentCovers` → `resolveEffectiveConsent` → `verifyConsentRecord` — all pure in-memory
 * ed25519 / sha256 logic, no chain. A case is ACCEPT iff consent is in force AND the audience matches
 * AND the queried commitment is covered. Record-auth negatives (bad action / recordId / signature)
 * are dropped fail-closed by the resolver → not covered → REJECT; state negatives (revoked / expired)
 * and coverage negatives (audience / commitment / empty) → REJECT. Two positive invariants are also
 * asserted: the authority guard (a hostile foreign revoke is ignored) and revoke-then-regrant.
 */
import * as ed25519 from '@noble/ed25519';
import {
  signConsentRecord,
  consentCovers,
  type ConsentRecord,
  type ConsentRecordBody,
} from '../../../src/lib/consent.js';
import type { ConformanceCase, Decision, Family } from '../types.js';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const seed = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

const GRANTOR_PRIV = seed(0x41);
const OTHER_PRIV = seed(0x52);
const GRANTOR_PUB = toHex(ed25519.getPublicKey(GRANTOR_PRIV));
const OTHER_PUB = toHex(ed25519.getPublicKey(OTHER_PRIV));

const SCOPE = 'consent-scope-0001';
const AUDIENCE = 'verifier-A';
const COMMIT_A = 'aa'.repeat(32);
const COMMIT_B = 'bb'.repeat(32);

// Fixed time anchor; all windows are absolute so resolution is deterministic.
const NOW = 1780000000000;
const GRANT_ISSUED = NOW - 10_000;
const GRANT_EXPIRES = NOW + 1_000_000;

function grantBody(grantor: string, opts: Partial<ConsentRecordBody> = {}): ConsentRecordBody {
  return {
    action: 'grant',
    consent_receipt_id: SCOPE,
    grantor,
    audience: AUDIENCE,
    commitments: [COMMIT_A],
    issuedAt: GRANT_ISSUED,
    expiresAt: GRANT_EXPIRES,
    ...opts,
  };
}

function revokeBody(grantor: string): ConsentRecordBody {
  return {
    action: 'revoke',
    consent_receipt_id: SCOPE,
    grantor,
    audience: AUDIENCE,
    commitments: [COMMIT_A],
    issuedAt: GRANT_ISSUED + 1_000,
    expiresAt: GRANT_EXPIRES,
  };
}

/** A standard, fully-authentic grant by the establishing grantor. */
function validGrant(): ConsentRecord {
  return signConsentRecord(grantBody(GRANTOR_PUB), GRANTOR_PRIV);
}

/** The query the run() applies against a ledger. */
interface ConsentInput {
  ledger: ConsentRecord[];
  scope: string;
  audience: string;
  commitment: string;
  now: number;
}

function input(ledger: ConsentRecord[], over: Partial<ConsentInput> = {}): ConsentInput {
  return { ledger, scope: SCOPE, audience: AUDIENCE, commitment: COMMIT_A, now: NOW, ...over };
}

interface Case {
  predicate: string;
  expected: Decision;
  reason: string;
  build(): ConsentInput;
}

const CASES: Case[] = [
  { predicate: 'valid', expected: 'ACCEPT', reason: 'grant in force, audience + commitment covered', build: () => input([validGrant()]) },
  // ---- record authenticity (resolver drops fail-closed → not covered) ----
  {
    predicate: 'action-grant-or-revoke',
    expected: 'REJECT',
    reason: 'action must be grant|revoke (unknown action dropped fail-closed)',
    build: () => {
      const g = validGrant();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (g as any).action = 'superseded';
      return input([g]);
    },
  },
  {
    predicate: 'recordId-content-hash',
    expected: 'REJECT',
    reason: 'recordId must equal the content hash of the canonical body',
    build: () => {
      const g = validGrant();
      g.recordId = 'cc'.repeat(32);
      return input([g]);
    },
  },
  {
    predicate: 'grantor-signature-verifies',
    expected: 'REJECT',
    reason: 'grantor signature must verify',
    build: () => {
      const g = validGrant();
      // Flip the first hex pair → still 64 bytes, no longer a valid signature.
      g.signature = (g.signature[0] === '0' ? '1' : '0') + g.signature.slice(1);
      return input([g]);
    },
  },
  // ---- effective state ----
  {
    predicate: 'not-revoked',
    expected: 'REJECT',
    reason: 'a later revoke by the establishing grantor supersedes the grant',
    build: () => input([validGrant(), signConsentRecord(revokeBody(GRANTOR_PUB), GRANTOR_PRIV)]),
  },
  {
    predicate: 'not-expired',
    expected: 'REJECT',
    reason: 'grant window has passed (now >= expiresAt)',
    build: () => input([validGrant()], { now: GRANT_EXPIRES + 1 }),
  },
  // ---- coverage ----
  {
    predicate: 'audience-match',
    expected: 'REJECT',
    reason: 'disclosure audience must match the grant audience',
    build: () => input([validGrant()], { audience: 'verifier-B' }),
  },
  {
    predicate: 'commitment-covered',
    expected: 'REJECT',
    reason: 'queried commitment must be in the granted commitment set',
    build: () => input([validGrant()], { commitment: COMMIT_B }),
  },
  {
    predicate: 'grant-present',
    expected: 'REJECT',
    reason: 'no authentic grant for this scope (empty ledger)',
    build: () => input([]),
  },
  // ---- positive invariants (authority guard must HOLD) ----
  {
    predicate: 'authority-guard-holds',
    expected: 'ACCEPT',
    reason: 'a revoke from a non-establishing grantor has no authority and is ignored',
    build: () => input([validGrant(), signConsentRecord(revokeBody(OTHER_PUB), OTHER_PRIV)]),
  },
  {
    predicate: 'revoke-then-regrant',
    expected: 'ACCEPT',
    reason: 'a later grant by the establishing grantor re-establishes consent after a revoke',
    build: () => {
      const regrant = signConsentRecord(
        grantBody(GRANTOR_PUB, { issuedAt: GRANT_ISSUED + 2_000 }),
        GRANTOR_PRIV,
      );
      return input([validGrant(), signConsentRecord(revokeBody(GRANTOR_PUB), GRANTOR_PRIV), regrant]);
    },
  },
];

export const consentFamily: Family = {
  name: 'consent',

  buildCases(): ConformanceCase[] {
    return CASES.map((c) => ({
      name: `consent/${c.predicate}`,
      family: 'consent',
      predicate: c.predicate,
      expected: c.expected,
      reason: c.reason,
      input: c.build(),
    }));
  },

  run(rawInput: unknown): { decision: Decision; detail: string } {
    const i = rawInput as ConsentInput;
    const cov = consentCovers(i.ledger, i.scope, i.audience, i.commitment, {
      now: i.now,
      requireValidSignatures: true,
    });
    return { decision: cov.ok ? 'ACCEPT' : 'REJECT', detail: cov.reason };
  },
};
