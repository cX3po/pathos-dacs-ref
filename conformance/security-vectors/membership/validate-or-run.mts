/**
 * Conformance vectors for the CCI-keyed membership ENGINE (contract §9 canonical verifier).
 *
 * Contract: wayfare/conformance/cci-membership-verifier-contract.md (§9 algorithm, §4 decisions, §5
 * linkability ceiling). Deterministic, $0, OFFLINE: in-memory AnchorReader + consent-backed
 * RevokeResolver, fixtures from fixed seeds. Asserts each case's expected decision and emits a set
 * hash. Exit non-zero on any mismatch.
 *
 * Run: npx tsx conformance/security-vectors/membership/validate-or-run.mts
 *
 * Cases (contract §9 + cross-roster/cross-admin/replay + precedence + strict-anchor-shape vectors):
 *   accept                                         — happy path, member in roster, unrevoked
 *   reject(non-member)                             — leaf not in root / path to a foreign root
 *   reject(tampered-merkle-path)                   — a sibling flipped in the audit path
 *   reject(bad-admin-binding)                      — adminBinding signed by a non-admin key
 *   reject(bad-member-binding / non-holder)        — bindingSig signed by a non-CCI key
 *   reject(revoked-member)                         — consent-backed fast-revoke denies the member
 *   reject(cross-roster-replay)                    — a roster-A proof checked against expected roster B
 *   reject(cross-admin-replay)                     — same member + same rosterId string under a DIFFERENT admin (F1)
 *   reject(precedence-stale+forged-binding)        — stale-epoch AND forged member-binding → reject (F2)
 *   indeterminate(stale-epoch)                     — proof.epoch ∉ {current}∪accepted
 *   indeterminate(root-unreadable)                 — anchor.readRoot → null
 *   indeterminate(epoch-head-unreadable)           — anchor.readEpochHead → null
 *   indeterminate(malformed-epoch-head)            — anchor returns a shape-invalid epoch head (Codex caveat)
 *   indeterminate(malformed-root-artifact)         — anchor returns a shape-invalid root artifact (Codex caveat)
 *   indeterminate(admin-key-unresolvable)          — rosterAdminCCI not a 32-byte key
 *   indeterminate(revoke-ledger-unreadable)        — RevokeResolver readable:false
 *   error(malformed-proof)                         — required field missing/wrong-typed
 *   error(malformed-merkle-path-element)           — a path element missing sibling/side → error not reject (F5)
 *   audience-scoped-revoke(A revoked, B verified)  — revoke for audience A does NOT deny audience B (F4)
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

import {
  memberLeaf,
  buildRosterRoot,
  signEpochHead,
  signMemberBinding,
  buildMembershipProof,
  verifyMembership,
  type MemberLeafPreimage,
  type MembershipProof,
  type RosterRootArtifact,
  type EpochHead,
  type AnchorReader,
  type RevokeResolver,
} from '../../../src/lib/membership.js';
import { computeCommitmentRoot, buildMerklePath } from '../../../src/lib/disclose.js';
import {
  signConsentRecord,
  resolveEffectiveConsent,
  InMemoryConsentAnchor,
  type ConsentRecord,
} from '../../../src/lib/consent.js';

// @noble/ed25519 v2 sync wiring (matches src/lib/sign.ts).
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

/* ---------------------------------- helpers -------------------------------- */

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** Deterministic ed25519 keypair from a fixed seed byte. */
function keypair(seedByte: number): { priv: Uint8Array; pub: string } {
  const priv = new Uint8Array(32).fill(seedByte);
  const pub = hex(ed25519.getPublicKey(priv));
  return { priv, pub };
}

const NETWORK = 'demos-devnet';
const NOW = 1_800_000_000_000;
const FUTURE = NOW + 3_600_000;

// Fixed-seed actors.
const admin = keypair(0x10); // roster A admin (also the consent grantor for revoke)
const adminB = keypair(0x11); // roster B admin
const member = keypair(0x20); // member CCI (roster A, in roster)
const memberB = keypair(0x21); // member CCI (roster B)
const outsider = keypair(0x22); // a CCI NOT in any roster
const attacker = keypair(0x23); // signs forged bindings
const presKey = keypair(0x30); // member presentation key (roster A)
const presKeyB = keypair(0x31); // member presentation key (roster B)

const ROSTER_A = 'roster:family-lane-A';
const ROSTER_B = 'roster:subnet-B';
const EPOCH = 7;
const STALE_EPOCH = 6;
const SALT = hex(new Uint8Array(32).fill(0xab)); // 256-bit fixed salt
const AUDIENCE = 'verifier:acme-marketplace';

/* --------------------------- roster A construction ------------------------- */

// Member preimage (roster A).
const preimageA: MemberLeafPreimage = {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  cci: member.pub,
  presentationKeyPub: presKey.pub,
  epoch: EPOCH,
};
const leafA = memberLeaf(SALT, preimageA);

// Two other roster-A members (so the tree has real siblings).
const otherA1 = memberLeaf(hex(new Uint8Array(32).fill(0xc1)), {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  cci: keypair(0x40).pub,
  presentationKeyPub: keypair(0x50).pub,
  epoch: EPOCH,
});
const otherA2 = memberLeaf(hex(new Uint8Array(32).fill(0xc2)), {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  cci: keypair(0x41).pub,
  presentationKeyPub: keypair(0x51).pub,
  epoch: EPOCH,
});
const setA = [leafA, otherA1, otherA2];
const rootA = computeCommitmentRoot(setA);
const pathA = buildMerklePath(setA, leafA);

const rootArtifactA: RosterRootArtifact = buildRosterRoot(admin.priv, {
  network: NETWORK,
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  epoch: EPOCH,
  treeDepth: 2,
  root: rootA,
  publishedAt: NOW,
});

const epochHeadA: EpochHead = signEpochHead(admin.priv, {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  currentEpoch: EPOCH,
  acceptedEpochs: [],
});

const bindingSigA = signMemberBinding(member.priv, {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  epoch: EPOCH,
  presentationKeyPub: presKey.pub,
});

const proofA: MembershipProof = buildMembershipProof({
  leafPreimage: preimageA,
  salt: SALT,
  merklePath: pathA,
  bindingSig: bindingSigA,
});

/* --------------------------- roster B construction ------------------------- */
// A genuine, fully-valid roster-B proof — used for the cross-roster-replay case (presented against
// expected roster A): every signature is valid for roster B, it just isn't roster A.

const preimageB: MemberLeafPreimage = {
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_B,
  cci: memberB.pub,
  presentationKeyPub: presKeyB.pub,
  epoch: EPOCH,
};
const leafB = memberLeaf(SALT, preimageB);
const otherB1 = memberLeaf(hex(new Uint8Array(32).fill(0xd1)), {
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_B,
  cci: keypair(0x42).pub,
  presentationKeyPub: keypair(0x52).pub,
  epoch: EPOCH,
});
const setB = [leafB, otherB1];
const rootB = computeCommitmentRoot(setB);
const pathB = buildMerklePath(setB, leafB);
const rootArtifactB: RosterRootArtifact = buildRosterRoot(adminB.priv, {
  network: NETWORK,
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_B,
  epoch: EPOCH,
  treeDepth: 1,
  root: rootB,
  publishedAt: NOW,
});
const epochHeadB: EpochHead = signEpochHead(adminB.priv, {
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_B,
  currentEpoch: EPOCH,
});
const proofB: MembershipProof = buildMembershipProof({
  leafPreimage: preimageB,
  salt: SALT,
  merklePath: pathB,
  bindingSig: signMemberBinding(memberB.priv, {
    rosterAdminCCI: adminB.pub,
    rosterId: ROSTER_B,
    epoch: EPOCH,
    presentationKeyPub: presKeyB.pub,
  }),
});

/* ----------------------------- AnchorReader -------------------------------- */
// In-memory anchor keyed by (adminCCI, rosterId[, epoch]). Knows roster A and roster B.

class MapAnchor implements AnchorReader {
  private heads = new Map<string, EpochHead>();
  private roots = new Map<string, RosterRootArtifact>();
  putHead(h: EpochHead) {
    this.heads.set(`${h.rosterAdminCCI}|${h.rosterId}`, h);
  }
  putRoot(r: RosterRootArtifact) {
    this.roots.set(`${r.rosterAdminCCI}|${r.rosterId}|${r.epoch}`, r);
  }
  async readEpochHead(adminCCI: string, rosterId: string): Promise<EpochHead | null> {
    return this.heads.get(`${adminCCI}|${rosterId}`) ?? null;
  }
  async readRoot(adminCCI: string, rosterId: string, epoch: number): Promise<RosterRootArtifact | null> {
    return this.roots.get(`${adminCCI}|${rosterId}|${epoch}`) ?? null;
  }
}

const anchor = new MapAnchor();
anchor.putHead(epochHeadA);
anchor.putRoot(rootArtifactA);
anchor.putHead(epochHeadB);
anchor.putRoot(rootArtifactB);

/* ----------------------------- RevokeResolver ------------------------------ */
// Backed by consent.ts: a fast-revoke = a 'revoke' record by the establishing grantor (the admin)
// over the member-leaf commitment as the consent scope. isRevoked resolves effective consent: a
// scope opened by a grant then revoked → revoked. `readable:false` simulates a ledger outage.

const REVOKE_SCOPE = (commitmentHex: string) => `revoke:${commitmentHex}`;

async function buildRevokeLedgerFor(commitmentHex: string, audience: string = AUDIENCE): Promise<ConsentRecord[]> {
  const scope = REVOKE_SCOPE(commitmentHex);
  const led = new InMemoryConsentAnchor();
  // grant (opens the scope, establishes admin as grantor), then revoke (denies it) — both for the
  // SAME audience, so the revoke is audience-scoped to `audience` (F4).
  const grant = signConsentRecord(
    {
      action: 'grant',
      consent_receipt_id: scope,
      grantor: admin.pub,
      audience,
      commitments: [commitmentHex],
      issuedAt: NOW,
      expiresAt: FUTURE,
    },
    admin.priv
  );
  const revoke = signConsentRecord(
    {
      action: 'revoke',
      consent_receipt_id: scope,
      grantor: admin.pub,
      audience,
      commitments: [commitmentHex],
      issuedAt: NOW + 1,
      expiresAt: FUTURE,
      supersedes: grant.recordId,
    },
    admin.priv
  );
  await led.append(grant);
  await led.append(revoke);
  return led.read();
}

/**
 * A consent-backed RevokeResolver (F4 — audience-scoped). A revoke is per-(scope, audience): a
 * revoke published for audience A denies ONLY audience A; verifying the same member under audience B
 * passes UNLESS a scope-global revoke (audience '*') is present. The resolver therefore consults the
 * consent ledger's `audience` field — it does NOT ignore the audience param.
 *
 * Mechanics: each ledger entry is keyed by the audience it was published for; `audience: '*'` is a
 * scope-global revoke that denies every audience. isRevoked(commitment, audience) consults the
 * audience-specific ledger first, then the global ledger.
 */
const GLOBAL_AUDIENCE = '*';
class ConsentRevokeResolver implements RevokeResolver {
  constructor(
    // keyed by `${commitmentHex}|${audience}` — the audience the revoke was published for.
    private ledgers: Map<string, ConsentRecord[]>,
    private readable = true
  ) {}
  private resolveFor(commitmentHex: string, audience: string): boolean {
    const led = this.ledgers.get(`${commitmentHex}|${audience}`);
    if (!led) return false;
    const eff = resolveEffectiveConsent(led, REVOKE_SCOPE(commitmentHex), { now: NOW + 2 });
    return eff.status === 'revoked';
  }
  async isRevoked(memberCommitmentHex: string, audience: string): Promise<{ revoked: boolean; readable: boolean }> {
    if (!this.readable) return { revoked: false, readable: false };
    // Per-(scope,audience): the audience-specific revoke, OR a scope-global revoke, denies.
    const revoked =
      this.resolveFor(memberCommitmentHex, audience) ||
      this.resolveFor(memberCommitmentHex, GLOBAL_AUDIENCE);
    return { revoked, readable: true };
  }
}

// Default resolver: nobody revoked, ledger readable.
const revokeOk = new ConsentRevokeResolver(new Map(), true);
// Resolver where leafA is revoked FOR THE DEFAULT AUDIENCE (key = `${leafA}|${AUDIENCE}`).
const revokeLedgerForA = await buildRevokeLedgerFor(leafA, AUDIENCE);
const revokeMember = new ConsentRevokeResolver(new Map([[`${leafA}|${AUDIENCE}`, revokeLedgerForA]]), true);
// Resolver whose ledger is unreadable.
const revokeUnreadable = new ConsentRevokeResolver(new Map(), false);

// F4 — audience-scoped revoke: leafA revoked for AUDIENCE_A only. Verified under AUDIENCE_B → NOT
// denied (per-(scope,audience) semantics). The same resolver under AUDIENCE_A WOULD deny.
const AUDIENCE_A = 'verifier:audience-A';
const AUDIENCE_B = 'verifier:audience-B';
const revokeLedgerForA_audA = await buildRevokeLedgerFor(leafA, AUDIENCE_A);
const revokeAudienceScoped = new ConsentRevokeResolver(
  new Map([[`${leafA}|${AUDIENCE_A}`, revokeLedgerForA_audA]]),
  true
);

/* -------------------------------- cases ------------------------------------ */

type Decision = 'accept' | 'reject' | 'indeterminate' | 'error';
interface Case {
  name: string;
  expected: Decision;
  proof: MembershipProof;
  expect: { rosterId: string; rosterAdminCCI: string; audience: string };
  anchor: AnchorReader;
  revoke: RevokeResolver;
}

const EXP_A = { rosterId: ROSTER_A, rosterAdminCCI: admin.pub, audience: AUDIENCE };

// A proof for an outsider: a non-member CCI presenting against roster A. We give it a genuine
// member-binding (signed by the outsider over roster A/epoch) and a path built within roster A's
// set for a DIFFERENT leaf — so the recomputed outsider leaf cannot fold to rootA.
const outsiderPreimage: MemberLeafPreimage = {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER_A,
  cci: outsider.pub,
  presentationKeyPub: keypair(0x60).pub,
  epoch: EPOCH,
};
const outsiderLeaf = memberLeaf(SALT, outsiderPreimage);
const proofNonMember: MembershipProof = buildMembershipProof({
  leafPreimage: outsiderPreimage,
  salt: SALT,
  merklePath: pathA, // a real path, but for leafA — the outsider's leaf won't fold to rootA via it
  bindingSig: signMemberBinding(outsider.priv, {
    rosterAdminCCI: admin.pub,
    rosterId: ROSTER_A,
    epoch: EPOCH,
    presentationKeyPub: outsiderPreimage.presentationKeyPub,
  }),
});

// Tampered merkle path: flip a sibling byte.
const proofTamperedPath: MembershipProof = (() => {
  const p = clone(proofA);
  const sib = p.merklePath[0]!.sibling;
  p.merklePath[0]!.sibling = (sib[0] === 'f' ? '0' : 'f') + sib.slice(1);
  return p;
})();

// Bad admin binding: re-anchor rootA's artifact but signed by the attacker (non-admin).
const badAdminRootArtifact: RosterRootArtifact = buildRosterRoot(attacker.priv, {
  network: NETWORK,
  rosterAdminCCI: admin.pub, // claims to be the admin, but signed by attacker → adminBinding fails
  rosterId: ROSTER_A,
  epoch: EPOCH,
  treeDepth: 2,
  root: rootA,
  publishedAt: NOW,
});
const badAdminAnchor = new MapAnchor();
badAdminAnchor.putHead(epochHeadA);
badAdminAnchor.putRoot(badAdminRootArtifact);

// Bad member binding: attacker signs the binding instead of the member CCI.
const proofBadMemberBinding: MembershipProof = buildMembershipProof({
  leafPreimage: preimageA,
  salt: SALT,
  merklePath: pathA,
  bindingSig: signMemberBinding(attacker.priv, {
    rosterAdminCCI: admin.pub,
    rosterId: ROSTER_A,
    epoch: EPOCH,
    presentationKeyPub: presKey.pub,
  }),
});

// Stale epoch: proof.epoch=STALE, head currentEpoch=EPOCH, no grace. The stale leaf needs its OWN
// root artifact at the stale epoch (else root-read indeterminate would mask the stale-epoch one); we
// only need the head to reject the epoch, so a stale-epoch proof never reaches the root read.
const stalePreimage: MemberLeafPreimage = { ...preimageA, epoch: STALE_EPOCH };
const staleProof: MembershipProof = buildMembershipProof({
  leafPreimage: stalePreimage,
  salt: SALT,
  merklePath: pathA,
  bindingSig: signMemberBinding(member.priv, {
    rosterAdminCCI: admin.pub,
    rosterId: ROSTER_A,
    epoch: STALE_EPOCH,
    presentationKeyPub: presKey.pub,
  }),
});

// Root unreadable: anchor that has the head but not the root.
const noRootAnchor = new MapAnchor();
noRootAnchor.putHead(epochHeadA);

// Epoch-head unreadable: empty anchor.
const noHeadAnchor = new MapAnchor();

// Admin-key unresolvable: expected rosterAdminCCI is not a 32-byte hex key.
const EXP_BAD_ADMIN = { rosterId: ROSTER_A, rosterAdminCCI: 'zz', audience: AUDIENCE };

// Malformed proof: drop bindingSig.
const malformedProof = (() => {
  const p = clone(proofA) as unknown as Record<string, unknown>;
  delete p.bindingSig;
  return p as unknown as MembershipProof;
})();

/* ----------------- F1: cross-admin replay (same member + same rosterId, different admin) -------- */
// member is legitimately in Admin-X's (admin's) roster ROSTER_A → proofA is genuine. A DIFFERENT
// Admin-Y (adminB) publishes a roster at the SAME rosterId STRING (ROSTER_A) that INCLUDES member's
// public leaf, and tries to get the unmodified proofA + its reusable member-binding accepted against
// Admin-Y. With rosterAdminCCI bound into the leaf + member binding (F1), proofA's bound admin (X)
// no longer matches expected admin (Y) → reject (anchor-independent leaf-scope), so the rosterId
// collision across admins is harmless.
const memberLeafUnderY = memberLeaf(SALT, {
  rosterAdminCCI: adminB.pub, // what Admin-Y WOULD need the leaf to bind
  rosterId: ROSTER_A,
  cci: member.pub,
  presentationKeyPub: presKey.pub,
  epoch: EPOCH,
});
const otherUnderY = memberLeaf(hex(new Uint8Array(32).fill(0xe1)), {
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_A,
  cci: keypair(0x43).pub,
  presentationKeyPub: keypair(0x53).pub,
  epoch: EPOCH,
});
const setYatA = [memberLeafUnderY, otherUnderY];
const rootYatA = computeCommitmentRoot(setYatA);
const rootArtifactYatA: RosterRootArtifact = buildRosterRoot(adminB.priv, {
  network: NETWORK,
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_A, // SAME rosterId string as Admin-X's roster — the collision
  epoch: EPOCH,
  treeDepth: 1,
  root: rootYatA,
  publishedAt: NOW,
});
const epochHeadYatA: EpochHead = signEpochHead(adminB.priv, {
  rosterAdminCCI: adminB.pub,
  rosterId: ROSTER_A,
  currentEpoch: EPOCH,
});
const crossAdminAnchor = new MapAnchor();
crossAdminAnchor.putHead(epochHeadYatA);
crossAdminAnchor.putRoot(rootArtifactYatA);
// Present the UNMODIFIED genuine proofA against Admin-Y at the colliding rosterId.
const EXP_Y_AT_A = { rosterId: ROSTER_A, rosterAdminCCI: adminB.pub, audience: AUDIENCE };

/* ----------------- F2: precedence — stale-epoch (indeterminate) AND forged member binding ------ */
// A proof that is BOTH stale (epoch ∉ accepted → indeterminate) AND carries a forged member binding
// (signed by attacker, not the CCI → reject). §4 precedence: any reject beats indeterminate, even
// though the member binding is anchor-independent and the epoch check is anchor-dependent.
const staleForgedProof: MembershipProof = buildMembershipProof({
  leafPreimage: stalePreimage,
  salt: SALT,
  merklePath: pathA,
  bindingSig: signMemberBinding(attacker.priv, {
    rosterAdminCCI: admin.pub,
    rosterId: ROSTER_A,
    epoch: STALE_EPOCH,
    presentationKeyPub: presKey.pub,
  }),
});

/* ----------------- Codex caveat: malformed anchor artifacts → indeterminate -------------------- */
// Anchor that returns a SHAPE-INVALID epoch head (currentEpoch wrong type) → indeterminate, not throw.
const malformedHeadAnchor: AnchorReader = {
  async readEpochHead() {
    return { ...epochHeadA, currentEpoch: 'not-a-number' } as unknown as EpochHead;
  },
  async readRoot() {
    return rootArtifactA;
  },
};
// Anchor that returns a SHAPE-INVALID root artifact (root field missing) → indeterminate, not throw.
const malformedRootAnchor: AnchorReader = {
  async readEpochHead() {
    return epochHeadA;
  },
  async readRoot() {
    const bad = { ...rootArtifactA } as Record<string, unknown>;
    delete bad.root;
    return bad as unknown as RosterRootArtifact;
  },
};

/* ----------------- F5: malformed merkle-path element → error (not reject) ---------------------- */
const malformedPathProof: MembershipProof = (() => {
  const p = clone(proofA) as unknown as { merklePath: Record<string, unknown>[] };
  delete p.merklePath[0]!.side; // element missing `side` → malformed input → error
  return p as unknown as MembershipProof;
})();

const cases: Case[] = [
  { name: 'accept', expected: 'accept', proof: proofA, expect: EXP_A, anchor, revoke: revokeOk },
  { name: 'reject-non-member', expected: 'reject', proof: proofNonMember, expect: EXP_A, anchor, revoke: revokeOk },
  { name: 'reject-tampered-merkle-path', expected: 'reject', proof: proofTamperedPath, expect: EXP_A, anchor, revoke: revokeOk },
  { name: 'reject-bad-admin-binding', expected: 'reject', proof: proofA, expect: EXP_A, anchor: badAdminAnchor, revoke: revokeOk },
  { name: 'reject-bad-member-binding', expected: 'reject', proof: proofBadMemberBinding, expect: EXP_A, anchor, revoke: revokeOk },
  { name: 'reject-revoked-member', expected: 'reject', proof: proofA, expect: EXP_A, anchor, revoke: revokeMember },
  // cross-roster replay: a genuine roster-B proof presented against expected roster A.
  { name: 'reject-cross-roster-replay', expected: 'reject', proof: proofB, expect: EXP_A, anchor, revoke: revokeOk },
  // F1: cross-admin replay — genuine proofA presented against a DIFFERENT admin at the same rosterId.
  { name: 'reject-cross-admin-replay', expected: 'reject', proof: proofA, expect: EXP_Y_AT_A, anchor: crossAdminAnchor, revoke: revokeOk },
  // F2: precedence — stale-epoch (indeterminate) AND forged member-binding (reject) → reject.
  { name: 'reject-precedence-stale+forged-binding', expected: 'reject', proof: staleForgedProof, expect: EXP_A, anchor, revoke: revokeOk },
  // F4: audience-scoped revoke — leafA revoked for AUDIENCE_A only.
  { name: 'accept-audience-scoped-revoke-other-audience', expected: 'accept', proof: proofA, expect: { rosterId: ROSTER_A, rosterAdminCCI: admin.pub, audience: AUDIENCE_B }, anchor, revoke: revokeAudienceScoped },
  { name: 'reject-audience-scoped-revoke-same-audience', expected: 'reject', proof: proofA, expect: { rosterId: ROSTER_A, rosterAdminCCI: admin.pub, audience: AUDIENCE_A }, anchor, revoke: revokeAudienceScoped },
  { name: 'indeterminate-stale-epoch', expected: 'indeterminate', proof: staleProof, expect: EXP_A, anchor, revoke: revokeOk },
  { name: 'indeterminate-root-unreadable', expected: 'indeterminate', proof: proofA, expect: EXP_A, anchor: noRootAnchor, revoke: revokeOk },
  { name: 'indeterminate-epoch-head-unreadable', expected: 'indeterminate', proof: proofA, expect: EXP_A, anchor: noHeadAnchor, revoke: revokeOk },
  // Codex caveat: malformed anchor artifacts → indeterminate (authority unconfirmable), not throw.
  { name: 'indeterminate-malformed-epoch-head', expected: 'indeterminate', proof: proofA, expect: EXP_A, anchor: malformedHeadAnchor, revoke: revokeOk },
  { name: 'indeterminate-malformed-root-artifact', expected: 'indeterminate', proof: proofA, expect: EXP_A, anchor: malformedRootAnchor, revoke: revokeOk },
  { name: 'indeterminate-admin-key-unresolvable', expected: 'indeterminate', proof: proofA, expect: EXP_BAD_ADMIN, anchor, revoke: revokeOk },
  { name: 'indeterminate-revoke-ledger-unreadable', expected: 'indeterminate', proof: proofA, expect: EXP_A, anchor, revoke: revokeUnreadable },
  { name: 'error-malformed-proof', expected: 'error', proof: malformedProof, expect: EXP_A, anchor, revoke: revokeOk },
  // F5: malformed merkle-path element (missing `side`) → error, not reject.
  { name: 'error-malformed-merkle-path-element', expected: 'error', proof: malformedPathProof, expect: EXP_A, anchor, revoke: revokeOk },
];

/* ------------------------------- run + emit -------------------------------- */

// Persist the vector corpus (proofs + the expected decisions + the keys used).
const vectorRecords = cases.map((c) => ({
  name: c.name,
  expected: c.expected,
  proof: c.proof,
  expected_context: c.expect,
}));
const corpus = {
  set: 'membership-v0.1',
  spec: 'wayfare/conformance/cci-membership-verifier-contract.md §9',
  network: NETWORK,
  rosterA: { rosterId: ROSTER_A, admin: admin.pub, epoch: EPOCH, root: rootA },
  rosterB: { rosterId: ROSTER_B, admin: adminB.pub, epoch: EPOCH, root: rootB },
  artifacts: { epochHeadA, rootArtifactA, epochHeadB, rootArtifactB },
  count: vectorRecords.length,
  vectors: vectorRecords,
  keys: {
    note: 'ed25519 priv = 32 bytes filled with the seed byte; pub = getPublicKey(priv)',
    admin: admin.pub,
    adminB: adminB.pub,
    member: member.pub,
    memberB: memberB.pub,
    outsider: outsider.pub,
    attacker: attacker.pub,
  },
};
const setHash = sha(JSON.stringify(corpus.vectors));
writeFileSync(`${DIR}/vectors/membership-v0.1.json`, JSON.stringify({ ...corpus, hash: setHash }, null, 2));

let pass = 0;
console.log('\n=== cci-membership engine conformance vectors v0.1 (contract §9) ===');
for (const c of cases) {
  const verdict = await verifyMembership(c.proof, c.expect, { anchor: c.anchor, revoke: c.revoke });
  const ok = verdict.decision === c.expected;
  pass += ok ? 1 : 0;
  const fails = verdict.checks.filter((k) => k.ok === false).map((k) => k.id).join(',');
  const nulls = verdict.checks.filter((k) => k.ok === null).map((k) => k.id).join(',');
  console.log(
    `  [${ok ? '✓' : '✗'}] ${c.name.padEnd(40)} exp=${c.expected.padEnd(13)} got=${verdict.decision.padEnd(13)}` +
      `${fails ? ' FAIL:' + fails : ''}${nulls ? ' INDET:' + nulls : ''}`
  );
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/membership-v0.1.json`);
if (pass !== cases.length) process.exit(1);
