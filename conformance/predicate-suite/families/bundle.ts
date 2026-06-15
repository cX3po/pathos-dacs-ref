/**
 * Conformance family: §10.4 AttestationBundleV1 OFFLINE predicates.
 *
 * Exercises `verifyBundleV1` (enforcing mode) — the single-bundle structural + signer-rule +
 * signature checks that need NO chain. The chain-side §10.4.2 two-sided anchoring and the §7.5.2
 * AttestationRef walk are deliberately OUT of scope here (they require RPC); this family proves the
 * offline acceptance contract only.
 *
 * Every fixture is cryptographically real: signatures are produced with the repo's own `sign()` over
 * the repo's own `bundleSignedScopeHashV1`, using fixed deterministic seeds — so the valid case truly
 * verifies and each negative violates EXACTLY ONE predicate (signed-scope mutations short-circuit at
 * the structural stage before the signature check, so a stale signature never double-counts).
 */
import * as ed25519 from '@noble/ed25519';
import { verifyBundleV1 } from '../../../src/lib/verify-bundle-v1.js';
import { bundleSignedScopeHashV1 } from '../../../src/lib/bundle-signed-scope-v1.js';
import { sign } from '../../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../../src/domain-sep.js';
import type { ConformanceCase, Decision, Family } from '../types.js';

const enc = new TextEncoder();
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const seed = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
const clone = <T>(x: T): T => structuredClone(x);

// Deterministic key material — fixed seeds, never random.
const BUYER_PRIV = seed(0x11);
const SELLER_PRIV = seed(0x22);
const UNLISTED_PRIV = seed(0x33);
const BUYER_PUB = toHex(ed25519.getPublicKey(BUYER_PRIV));
const SELLER_PUB = toHex(ed25519.getPublicKey(SELLER_PRIV));
const UNLISTED_PUB = toHex(ed25519.getPublicKey(UNLISTED_PRIV));

// Fixed structural content hashes (the offline verifier only checks shape/format, never fetches).
const H_LISTING = '11'.repeat(32);
const H_PARTY = '22'.repeat(32);
const H_VET = '33'.repeat(32);
const H_SETTLE = '44'.repeat(32);

const cciClaim = (pub: string) => ({ scheme: 'cci', identifier: pub });

/** A fully-valid, signature-less §10.4 bundle (a completed, two-party session). */
function baseUnsigned(): Record<string, unknown> {
  return {
    bundleVersion: '1',
    jobId: 'CONFORMANCE-0001',
    outcome: 'completed',
    anchoredByRole: 'buyer',
    listingRef: { listingId: 'listing-conf-0001', version: 1, contentHash: H_LISTING },
    parties: [
      { role: 'buyer', bundleHash: H_PARTY, primaryClaim: cciClaim(BUYER_PUB) },
      { role: 'seller', bundleHash: H_PARTY, primaryClaim: cciClaim(SELLER_PUB) },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-counterparty', outcome: 'ok' }],
    vetRecords: [{ kind: 'dacs-4-evidence', id: 'vet-0001', contentHash: H_VET }],
    settlementEvidence: [{ kind: 'dacs-4-evidence', id: 'settle-0001', contentHash: H_SETTLE }],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1780004000000,
  };
}

type Signer = { pub: string; priv: Uint8Array };

/** Seal a signature-less bundle by signing its signed-scope hash with each signer. */
function sealWith(unsigned: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  const signatures = signers.map((s) => ({
    party: cciClaim(s.pub),
    algorithm: 'ed25519',
    value: b64(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), s.priv)),
  }));
  return { ...unsigned, signatures };
}

const BUYER: Signer = { pub: BUYER_PUB, priv: BUYER_PRIV };
const SELLER: Signer = { pub: SELLER_PUB, priv: SELLER_PRIV };

/** The canonical valid (ACCEPT) bundle. */
function validBundle(): Record<string, unknown> {
  return sealWith(baseUnsigned(), [BUYER, SELLER]);
}

/** Flip the first base64 char of a signature value so it stays 64 bytes but no longer verifies. */
function corruptSignedScope(): Record<string, unknown> {
  // Sign over a DIFFERENT hash than the verifier will recompute → valid 64-byte encoding, fails verify.
  const unsigned = baseUnsigned();
  const wrongHash = 'de'.repeat(32);
  const signatures = [BUYER, SELLER].map((s) => ({
    party: cciClaim(s.pub),
    algorithm: 'ed25519',
    value: b64(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(wrongHash), s.priv)),
  }));
  return { ...unsigned, signatures };
}

interface Neg {
  predicate: string;
  reason: string;
  build(): Record<string, unknown>;
}

const NEGATIVES: Neg[] = [
  // ---- structural (short-circuit before signature check) ----
  { predicate: 'bundleVersion', reason: 'bundleVersion must be "1"', build: () => { const b = validBundle(); b.bundleVersion = '2'; return b; } },
  { predicate: 'jobId', reason: 'jobId missing', build: () => { const b = validBundle(); delete b.jobId; return b; } },
  { predicate: 'outcome-enum', reason: 'unknown outcome (§10.4)', build: () => { const b = validBundle(); b.outcome = 'banana'; return b; } },
  { predicate: 'anchoredByRole-known', reason: 'anchoredByRole missing/invalid (§10.4)', build: () => { const b = validBundle(); b.anchoredByRole = 'overlord'; return b; } },
  { predicate: 'anchoredByRole-listed', reason: 'anchoredByRole not a listed party role (§10.4)', build: () => { const b = validBundle(); b.anchoredByRole = 'orchestrator'; return b; } },
  { predicate: 'listingRef', reason: 'listingRef malformed', build: () => { const b = validBundle(); (b.listingRef as Record<string, unknown>).contentHash = 'not-a-hash'; return b; } },
  { predicate: 'registry-versions', reason: 'registry versions must be non-negative integers', build: () => { const b = validBundle(); b.recipeRegistryVersion = -1; return b; } },
  { predicate: 'finalisedAt', reason: 'finalisedAt must be a non-negative integer (unix ms)', build: () => { const b = validBundle(); b.finalisedAt = 1.5; return b; } },
  { predicate: 'phaseSummary', reason: 'phaseSummary entries malformed', build: () => { const b = validBundle(); (b.phaseSummary as Record<string, unknown>[])[0].outcome = 'maybe'; return b; } },
  { predicate: 'attestation-ref-shape', reason: 'vetRecords entries must be AttestationRefs', build: () => { const b = validBundle(); b.vetRecords = [{ kind: 'dacs-4-evidence', id: 'vet-0001' }]; return b; } },
  { predicate: 'party-shape', reason: 'party[i] invalid', build: () => { const b = validBundle(); (b.parties as Record<string, unknown>[])[0].bundleHash = 'not-a-hash'; return b; } },
  { predicate: 'signature-shape', reason: 'signatures[i] invalid', build: () => { const b = validBundle(); (b.signatures as Record<string, unknown>[])[0].algorithm = ''; return b; } },
  // ---- signer-rule (§10.4.1) ----
  {
    predicate: 'no-unlisted-signers',
    reason: 'signature(s) from unlisted parties (§10.4.1)',
    build: () => {
      // parties unchanged → same signed scope → existing sigs stay valid; add a real sig from a non-party key.
      const b = validBundle();
      const bundleHash = bundleSignedScopeHashV1(b);
      (b.signatures as Record<string, unknown>[]).push({
        party: cciClaim(UNLISTED_PUB),
        algorithm: 'ed25519',
        value: b64(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), UNLISTED_PRIV)),
      });
      return b;
    },
  },
  {
    predicate: 'non-abort-needs-buyer-and-seller',
    reason: 'non-abort bundle must list buyer + seller parties (§10.4.1)',
    build: () => {
      // Drop the seller party AND its signature, then re-seal the buyer over the NEW scope so the
      // only violation is the missing seller party (no stale-signature side effect).
      const unsigned = baseUnsigned();
      (unsigned.parties as unknown[]) = [(unsigned.parties as unknown[])[0]];
      return sealWith(unsigned, [BUYER]);
    },
  },
  {
    predicate: 'non-abort-needs-all-parties-signed',
    reason: 'missing required signer(s) (§10.4.1)',
    build: () => {
      // parties unchanged → scope unchanged → buyer sig stays valid; just remove the seller signature.
      const b = validBundle();
      (b.signatures as unknown[]) = [(b.signatures as unknown[])[0]];
      return b;
    },
  },
  // ---- signature ----
  { predicate: 'signature-encoding', reason: 'signature value is not a valid 64-byte ed25519 base64/base64url', build: () => { const b = validBundle(); (b.signatures as Record<string, unknown>[])[0].value = 'not+valid+base64!!'; return b; } },
  { predicate: 'signature-verifies', reason: 'signature does not verify over dacs-bundle:v1: || bundleHash', build: () => corruptSignedScope() },
];

export const bundleFamily: Family = {
  name: 'bundle-v1',

  buildCases(): ConformanceCase[] {
    const cases: ConformanceCase[] = [
      { name: 'bundle-v1/valid', family: 'bundle-v1', predicate: 'valid', expected: 'ACCEPT', reason: 'all §10.4 offline predicates satisfied', input: validBundle() },
    ];
    for (const n of NEGATIVES) {
      cases.push({
        name: `bundle-v1/${n.predicate}`,
        family: 'bundle-v1',
        predicate: n.predicate,
        expected: 'REJECT',
        reason: n.reason,
        input: n.build(),
      });
    }
    return cases;
  },

  run(input: unknown): { decision: Decision; detail: string } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const v = verifyBundleV1(input as any, { requireSignatures: true });
    const detail = v.reasons.length
      ? v.reasons.join('; ')
      : v.signatureChecks.map((c) => `${c.party.slice(0, 16)}…:${c.decision}`).join('; ');
    return { decision: v.decision === 'accept' ? 'ACCEPT' : 'REJECT', detail };
  },
};
