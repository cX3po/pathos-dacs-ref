/**
 * cci-membership engine — smoke test (happy path + negatives) through verifyMembership.
 *
 * Contract: wayfare/conformance/cci-membership-verifier-contract.md (§9 algorithm, §4 decisions).
 * OFFLINE — in-memory AnchorReader + RevokeResolver, deterministic keys. Exercises the decision
 * lattice (accept | reject | indeterminate | error) so the engine runs under `npm test`. The full
 * 13-case corpus lives in conformance/security-vectors/membership/.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeypair } from '../../src/lib/sign.js';
import { bytesToHex } from '../../src/lib/verify-bundle.js';
import { computeCommitmentRoot, buildMerklePath } from '../../src/lib/disclose.js';
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
} from '../../src/lib/membership.js';

/* ---------------------------------- fixtures -------------------------------- */

const NETWORK = 'demos-devnet';
const ROSTER = 'roster:test-A';
const EPOCH = 3;
const NOW = 1_800_000_000_000;
const AUDIENCE = 'verifier:test';
const SALT = '11'.repeat(32); // 256-bit fixed salt

const admin = (() => {
  const kp = generateKeypair();
  return { priv: kp.privKey, pub: bytesToHex(kp.pubKey) };
})();
const member = (() => {
  const kp = generateKeypair();
  return { priv: kp.privKey, pub: bytesToHex(kp.pubKey) };
})();
const attacker = (() => {
  const kp = generateKeypair();
  return { priv: kp.privKey, pub: bytesToHex(kp.pubKey) };
})();
const presKey = bytesToHex(generateKeypair().pubKey);

const preimage: MemberLeafPreimage = {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER,
  cci: member.pub,
  presentationKeyPub: presKey,
  epoch: EPOCH,
};
const leaf = memberLeaf(SALT, preimage);

// A second member so the tree has a real sibling.
const otherLeaf = memberLeaf('22'.repeat(32), {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER,
  cci: bytesToHex(generateKeypair().pubKey),
  presentationKeyPub: bytesToHex(generateKeypair().pubKey),
  epoch: EPOCH,
});
const set = [leaf, otherLeaf];
const root = computeCommitmentRoot(set);
const path = buildMerklePath(set, leaf);

const rootArtifact: RosterRootArtifact = buildRosterRoot(admin.priv, {
  network: NETWORK,
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER,
  epoch: EPOCH,
  treeDepth: 1,
  root,
  publishedAt: NOW,
});
const epochHead: EpochHead = signEpochHead(admin.priv, {
  rosterAdminCCI: admin.pub,
  rosterId: ROSTER,
  currentEpoch: EPOCH,
});
const validProof: MembershipProof = buildMembershipProof({
  leafPreimage: preimage,
  salt: SALT,
  merklePath: path,
  bindingSig: signMemberBinding(member.priv, { rosterAdminCCI: admin.pub, rosterId: ROSTER, epoch: EPOCH, presentationKeyPub: presKey }),
});

const EXPECT = { rosterId: ROSTER, rosterAdminCCI: admin.pub, audience: AUDIENCE };

/** AnchorReader that knows roster A; optional toggles to simulate outages. */
function makeAnchor(opts: { noHead?: boolean; noRoot?: boolean } = {}): AnchorReader {
  return {
    async readEpochHead() {
      return opts.noHead ? null : epochHead;
    },
    async readRoot() {
      return opts.noRoot ? null : rootArtifact;
    },
  };
}
const revokeOk: RevokeResolver = { async isRevoked() { return { revoked: false, readable: true }; } };
const revokeYes: RevokeResolver = { async isRevoked() { return { revoked: true, readable: true }; } };
const revokeUnreadable: RevokeResolver = { async isRevoked() { return { revoked: false, readable: false }; } };

/* ----------------------------------- tests --------------------------------- */

test('membership: happy path → accept', async () => {
  const v = await verifyMembership(validProof, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'accept', JSON.stringify(v.checks));
  assert.ok(v.checks.every((c) => c.ok === true));
});

test('membership: forged member binding (non-holder) → reject', async () => {
  const forged = buildMembershipProof({
    leafPreimage: preimage,
    salt: SALT,
    merklePath: path,
    bindingSig: signMemberBinding(attacker.priv, { rosterAdminCCI: admin.pub, rosterId: ROSTER, epoch: EPOCH, presentationKeyPub: presKey }),
  });
  const v = await verifyMembership(forged, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'reject');
  assert.ok(v.checks.some((c) => c.id === 'member-binding' && c.ok === false));
});

test('membership: cross-roster replay (proof scoped to a different roster) → reject', async () => {
  // A proof whose leaf preimage is for a DIFFERENT roster, checked against EXPECT (roster A).
  const otherRoster = 'roster:OTHER';
  const xPre: MemberLeafPreimage = { rosterAdminCCI: admin.pub, rosterId: otherRoster, cci: member.pub, presentationKeyPub: presKey, epoch: EPOCH };
  const xLeaf = memberLeaf(SALT, xPre);
  const xSet = [xLeaf, otherLeaf];
  const xProof = buildMembershipProof({
    leafPreimage: xPre,
    salt: SALT,
    merklePath: buildMerklePath(xSet, xLeaf),
    bindingSig: signMemberBinding(member.priv, { rosterAdminCCI: admin.pub, rosterId: otherRoster, epoch: EPOCH, presentationKeyPub: presKey }),
  });
  const v = await verifyMembership(xProof, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'reject');
  assert.ok(v.checks.some((c) => c.id === 'leaf-scope' && c.ok === false));
});

test('membership: revoked member → reject', async () => {
  const v = await verifyMembership(validProof, EXPECT, { anchor: makeAnchor(), revoke: revokeYes });
  assert.equal(v.decision, 'reject');
  assert.ok(v.checks.some((c) => c.id === 'revoke-gate' && c.ok === false));
});

test('membership: root unreadable → indeterminate', async () => {
  const v = await verifyMembership(validProof, EXPECT, { anchor: makeAnchor({ noRoot: true }), revoke: revokeOk });
  assert.equal(v.decision, 'indeterminate');
  assert.ok(v.checks.some((c) => c.id === 'root-read' && c.ok === null));
});

test('membership: revoke ledger unreadable → indeterminate', async () => {
  const v = await verifyMembership(validProof, EXPECT, { anchor: makeAnchor(), revoke: revokeUnreadable });
  assert.equal(v.decision, 'indeterminate');
  assert.ok(v.checks.some((c) => c.id === 'revoke-gate' && c.ok === null));
});

test('membership: malformed proof (missing bindingSig) → error', async () => {
  const bad = { ...validProof } as Record<string, unknown>;
  delete bad.bindingSig;
  const v = await verifyMembership(bad as unknown as MembershipProof, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'error');
  assert.ok(v.checks.some((c) => c.id === 'schema' && c.ok === false));
});

test('membership: cross-admin replay (same rosterId, different admin) → reject (F1)', async () => {
  // A genuine proof for `admin`'s roster presented against a DIFFERENT admin at the SAME rosterId.
  const adminY = (() => {
    const kp = generateKeypair();
    return { priv: kp.privKey, pub: bytesToHex(kp.pubKey) };
  })();
  const expectY = { rosterId: ROSTER, rosterAdminCCI: adminY.pub, audience: AUDIENCE };
  const v = await verifyMembership(validProof, expectY, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'reject');
  assert.ok(v.checks.some((c) => c.id === 'leaf-scope' && c.ok === false));
});

test('membership: precedence — stale-epoch AND forged member binding → reject (F2)', async () => {
  // Stale epoch alone is indeterminate; a forged member binding is an anchor-independent reject.
  // §4 precedence: reject must beat indeterminate even though both apply.
  const STALE = EPOCH - 1;
  const stalePre: MemberLeafPreimage = { ...preimage, epoch: STALE };
  const staleSet = [memberLeaf(SALT, stalePre), otherLeaf];
  const staleForged = buildMembershipProof({
    leafPreimage: stalePre,
    salt: SALT,
    merklePath: buildMerklePath(staleSet, memberLeaf(SALT, stalePre)),
    bindingSig: signMemberBinding(attacker.priv, { rosterAdminCCI: admin.pub, rosterId: ROSTER, epoch: STALE, presentationKeyPub: presKey }),
  });
  const v = await verifyMembership(staleForged, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'reject', JSON.stringify(v.checks));
  assert.ok(v.checks.some((c) => c.id === 'member-binding' && c.ok === false));
  assert.ok(v.checks.some((c) => c.id === 'epoch-accepted' && c.ok === null));
});

test('membership: malformed merkle-path element (missing side) → error (F5)', async () => {
  const bad = JSON.parse(JSON.stringify(validProof)) as { merklePath: Record<string, unknown>[] };
  delete bad.merklePath[0]!.side;
  const v = await verifyMembership(bad as unknown as MembershipProof, EXPECT, { anchor: makeAnchor(), revoke: revokeOk });
  assert.equal(v.decision, 'error');
  assert.ok(v.checks.some((c) => c.id === 'schema' && c.ok === false));
});
