import { sha256Hex, contentHashSignedScope } from "../hash.ts";
import { canonicalize } from "../canonicalize.ts";
import { verifyArtifactSignatureWithSeparator, DOMAIN_SEPARATOR_REGISTRY } from "../signing.ts";
import { schemeOf, type ClaimReference } from "../dacs1.ts";
import { dacsXSeparator } from "./separators.ts";
import { disputeRecordHash } from "./dispute.ts";
import type {
  DisputeRecord,
  ArbitrationRule,
  ChannelTranscript,
  DisclosureGrant,
} from "./types.ts";

// DACS-X step 3 — §8.7 arbitrator transcript-disclosure. Pure, read-only; holds
// no key, signs nothing (ISC-38). Composes the existing primitives only — §7.7
// signature verification, §7.2 content hashing, DACS-1 claim references — so it
// adds NO new cryptography (DP-4). It realises the §8.7 hook ("DACS-X dispute MAY
// require selective transcript disclosure under signed party agreement or
// arbitrator order") under steward sign-off DP-1.

export type DisclosureCheck =
  | { ok: true; recipient: ClaimReference; transcriptHash: string }
  | { ok: false; reason: string };

const fromB64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));

/** Ed25519 raw public keys are exactly 32 bytes; anything else is malformed
 *  input the verifier cannot evaluate (→ surfaces as `error`, not `fail`). */
function assertEd25519Key(raw: Uint8Array, role: string): void {
  if (raw.length !== 32) throw new Error(`malformed ${role} public key: expected 32 bytes, got ${raw.length}`);
}

/** §7.2 content hash of a §8.7 transcript's signed scope (the `signatures` field omitted). */
export function transcriptContentHash(transcript: ChannelTranscript): string {
  return contentHashSignedScope(transcript as unknown as Record<string, unknown>, "signatures");
}

export interface DisclosureInput {
  grant: DisclosureGrant;
  /** The §8.7 transcript being disclosed. */
  transcript: ChannelTranscript;
  /** The dispute the disclosure serves — binds the grant to an open dispute. */
  record: DisputeRecord;
  /** The agreed arbitration rule — names the credentialed arbitrator (anti-swap, DP-5). */
  agreedRule: ArbitrationRule;
  /** Recipient (arbitrator) raw public key — verifies an arbitrator-order grant. */
  recipientPublicKeyRaw: Uint8Array;
  /** member claim → raw Ed25519 public key, for party-agreement + transcript authenticity. */
  memberKeys: Record<ClaimReference, Uint8Array>;
  now: number;
}

/**
 * Verify a §8.7 transcript disclosure to the named arbitrator (DACS-X step 3).
 *
 * DP-1 properties enforced:
 *   - the recipient is the CREDENTIALED arbitrator (in the agreed rule's allow-set),
 *     not an arbitrary third party — named-arbitrator-only;
 *   - the disclosed transcript matches the grant's pinned hash — anti-substitution;
 *   - the grant binds to THIS open dispute (disputeId + disputeRecordHash);
 *   - authorization is a SIGNED PARTY AGREEMENT (every transcript member co-signs)
 *     OR an ARBITRATOR ORDER (the credentialed arbitrator signs);
 *   - the transcript is authentic — every member's §8.7 signature verifies.
 *
 * Returns a plain check result. NO presentable artifact is produced (DP-1): the
 * result is a boolean "transcript X may be shown to arbitrator Y" the arbitrator
 * consumes, never a re-anchorable disclosure bundle. Structurally distinct from
 * §11.2.7 claim-disclosure — different object (transcript, not `claims[]`),
 * different audience (arbitrator, not a counterparty), no minimised claim set out.
 */
export function verifyTranscriptDisclosure(input: DisclosureInput): DisclosureCheck {
  const { grant, transcript, record, agreedRule } = input;

  if (grant.dacsXVersion !== "1") return { ok: false, reason: `unsupported dacsXVersion ${grant.dacsXVersion}` };

  // (1) bind to the open dispute — a grant cannot float free of a DisputeRecord.
  if (grant.disputeId !== record.disputeId) {
    return { ok: false, reason: "grant.disputeId does not match the DisputeRecord" };
  }
  if (grant.disputeRecordHash !== disputeRecordHash(record)) {
    return { ok: false, reason: "grant.disputeRecordHash does not bind to the DisputeRecord" };
  }

  // (1a) the agreed rule MUST be the one the DisputeRecord pinned (§8.4.3 rule-ref).
  // Without this, a caller could swap in a rule whose allow-set names an attacker's
  // recipient and pass the named-arbitrator check below — the same anti-swap binding
  // verifyArbitratorCredential enforces. (cross-vendor review, CRITICAL.)
  if (sha256Hex(canonicalize(agreedRule)) !== record.arbitration.ruleRef) {
    return { ok: false, reason: "arbitration rule-ref mismatch — the agreed rule was swapped after agreement" };
  }

  // (1b) transcript member-set integrity: nonempty, unique, and every message author
  // is a declared member. A transcript that under-declares members must not shrink the
  // party-agreement consent set. Binding to an externally-expected channel member set
  // is out of scope for this read-only verifier (it holds no channel registry).
  if (transcript.members.length === 0) return { ok: false, reason: "transcript declares no members" };
  if (new Set(transcript.members).size !== transcript.members.length) {
    return { ok: false, reason: "transcript member set has duplicate entries" };
  }
  for (const m of transcript.messages) {
    if (!transcript.members.includes(m.author)) {
      return { ok: false, reason: `transcript message author ${m.author} is not a declared member` };
    }
  }

  // (2) recipient MUST be the credentialed arbitrator (DP-1 named-arbitrator-only).
  try {
    schemeOf(grant.recipient);
  } catch {
    return { ok: false, reason: "grant.recipient is not a well-formed claim reference" };
  }
  if (!agreedRule.arbitrators || agreedRule.arbitrators.length === 0) {
    return { ok: false, reason: "agreed rule names no arbitrator allow-set — recipient cannot be authorized (DP-5 bilateral selection)" };
  }
  if (!agreedRule.arbitrators.includes(grant.recipient)) {
    return { ok: false, reason: `recipient ${grant.recipient} is not the credentialed arbitrator in the agreed rule` };
  }

  // (3) anti-substitution: the disclosed transcript MUST be the one the grant pins.
  const computedTranscriptHash = transcriptContentHash(transcript);
  if (grant.transcriptHash !== computedTranscriptHash) {
    return { ok: false, reason: "grant.transcriptHash does not match the disclosed transcript (substitution)" };
  }

  // (4) transcript authenticity — every member's §8.7 signature verifies under the
  //     registered dacs-transcript separator. A transcript missing a member's
  //     signature, or carrying an invalid one, is not the authentic channel record.
  const transcriptSep = DOMAIN_SEPARATOR_REGISTRY["dacs-3-transcript"];
  for (const member of transcript.members) {
    const sig = transcript.signatures.find((s) => s.signer === member);
    if (!sig) return { ok: false, reason: `transcript missing member signature: ${member}` };
    const key = input.memberKeys[member];
    if (!key) return { ok: false, reason: `no public key for transcript member ${member}` };
    assertEd25519Key(key, `transcript member ${member}`); // malformed → error
    const v = verifyArtifactSignatureWithSeparator({
      separator: transcriptSep,
      doc: transcript as unknown as Record<string, unknown>,
      publicKeyRaw: key,
      signatureRaw: fromB64u(sig.signature),
      signatureFields: ["signatures"],
    });
    if (!v.ok) return { ok: false, reason: `transcript signature for ${member} did not verify` };
  }

  // (5) authorization — DP-1's "signed party agreement OR arbitrator order".
  if (grant.authority === "arbitrator-order") {
    assertEd25519Key(input.recipientPublicKeyRaw, "arbitrator"); // malformed → error
    if (grant.signatures.length !== 1 || grant.signatures[0]!.signer !== grant.recipient) {
      return { ok: false, reason: "arbitrator-order grant must carry exactly the arbitrator's signature" };
    }
    const v = verifyArtifactSignatureWithSeparator({
      separator: dacsXSeparator("dacs-x-disclosure-grant"),
      doc: grant as unknown as Record<string, unknown>,
      publicKeyRaw: input.recipientPublicKeyRaw,
      signatureRaw: fromB64u(grant.signatures[0]!.signature),
      signatureFields: ["signatures"],
    });
    if (!v.ok) return { ok: false, reason: "arbitrator-order signature did not verify" };
    return { ok: true, recipient: grant.recipient, transcriptHash: computedTranscriptHash };
  }

  if (grant.authority !== "party-agreement") {
    return { ok: false, reason: `unknown disclosure authority: ${String(grant.authority)}` };
  }

  // party-agreement: EVERY transcript member must co-sign the grant (full consent).
  for (const member of transcript.members) {
    const sig = grant.signatures.find((s) => s.signer === member);
    if (!sig) return { ok: false, reason: `party-agreement grant missing member consent: ${member}` };
    const key = input.memberKeys[member];
    if (!key) return { ok: false, reason: `no public key for grant signer ${member}` };
    assertEd25519Key(key, `grant signer ${member}`); // malformed → error
    const v = verifyArtifactSignatureWithSeparator({
      separator: dacsXSeparator("dacs-x-disclosure-grant"),
      doc: grant as unknown as Record<string, unknown>,
      publicKeyRaw: key,
      signatureRaw: fromB64u(sig.signature),
      signatureFields: ["signatures"],
    });
    if (!v.ok) return { ok: false, reason: `party-agreement signature for ${member} did not verify` };
  }
  return { ok: true, recipient: grant.recipient, transcriptHash: computedTranscriptHash };
}
