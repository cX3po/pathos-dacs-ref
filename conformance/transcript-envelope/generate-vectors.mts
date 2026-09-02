import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import {
  computeContentHash,
  deriveMemberKeys,
  openEnvelope,
  sealEnvelope,
  verifyEnvelopeIntegrity,
  type Envelope,
  type OpenResult,
} from "./envelope.mjs";

const VECTOR_PATH = resolve(fileURLToPath(new URL("../vectors/transcript-envelope-v0.1.json", import.meta.url)));

const SEEDS = {
  memberA: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  memberB: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
  outsider: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
} as const;

const RANDOMNESS = {
  cek: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
  wrapM: [
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
  ],
  wrapIv: ["000102030405060708090a0b", "101112131415161718191a1b"],
  iv: "f0f1f2f3f4f5f6f7f8f9fafb",
} as const;

const CLAIM_A = "dacs:claim:member-a";
const CLAIM_B = "dacs:claim:member-b";
const CLAIM_OUTSIDER = "dacs:claim:outsider";
const CHANNEL_ID = "dacs:channel:transcript-envelope-vector";

const fromHex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "hex"));

type ExpectedOutcome = { ok: boolean; step?: number; reason?: string };

function expectedOpen(result: OpenResult): ExpectedOutcome {
  return result.ok ? { ok: true } : { ok: false, step: result.step, reason: result.reason };
}

function mutateBinary(envelope: Envelope, field: "ciphertext" | "tag"): Envelope {
  const copy = structuredClone(envelope);
  const bytes = Buffer.from(copy[field], "base64url");
  bytes[0] = bytes[0]! ^ 1;
  copy[field] = bytes.toString("base64url");
  return copy;
}

function rehash(envelope: Envelope): Envelope {
  const copy = structuredClone(envelope);
  copy.contentHash = computeContentHash(copy);
  return copy;
}

export function generateVectors(): object {
  const keyA = deriveMemberKeys(fromHex(SEEDS.memberA));
  const keyB = deriveMemberKeys(fromHex(SEEDS.memberB));
  const outsider = deriveMemberKeys(fromHex(SEEDS.outsider));
  const transcript = {
    transcriptVersion: "1",
    channelId: CHANNEL_ID,
    members: [CLAIM_A, CLAIM_B],
    messages: [
      { sequence: 1, sender: CLAIM_A, bodyHash: "11".repeat(32) },
      { sequence: 2, sender: CLAIM_B, bodyHash: "22".repeat(32) },
    ],
    generatedAt: 1735689600,
    signatures: [],
  };
  const inputs = {
    seeds: { memberA: SEEDS.memberA, memberB: SEEDS.memberB, outsider: SEEDS.outsider },
    randomness: RANDOMNESS,
    transcript,
    channelId: CHANNEL_ID,
    members: [
      { claim: CLAIM_A, seed: "memberA" },
      { claim: CLAIM_B, seed: "memberB" },
    ],
  };
  const sealed = sealEnvelope({
    transcript,
    channelId: CHANNEL_ID,
    members: [
      { claim: CLAIM_A, ek: keyA.ek },
      { claim: CLAIM_B, ek: keyB.ek },
    ],
    randomness: {
      cek: fromHex(RANDOMNESS.cek),
      wrapM: RANDOMNESS.wrapM.map(fromHex),
      wrapIv: RANDOMNESS.wrapIv.map(fromHex),
      iv: fromHex(RANDOMNESS.iv),
    },
  });

  const tampered = mutateBinary(sealed, "ciphertext");
  const tamperedRehashed = rehash(tampered);
  const aadMismatch = structuredClone(sealed);
  aadMismatch.channelId = `${CHANNEL_ID}:edited`;
  const aadMismatchRehashed = rehash(aadMismatch);
  const memberSetMismatch = structuredClone(sealed);
  memberSetMismatch.memberSetHash = "00".repeat(32);
  const memberKeySwap = structuredClone(sealed);
  const memberBKey = memberKeySwap.memberKeys.find(({ claim }) => claim === CLAIM_B)!;
  memberBKey.publicKey = Buffer.from(outsider.ek).toString("base64url");

  const bothMembers = [
    { name: "member-a/correct-dk", claim: CLAIM_A, keySeed: "memberA", dk: keyA.dk },
    { name: "member-b/correct-dk", claim: CLAIM_B, keySeed: "memberB", dk: keyB.dk },
  ];
  const variants: Array<{
    name: string;
    description: string;
    envelope: Envelope;
    recipients: Array<{ name: string; claim: string; keySeed: string; dk: Uint8Array }>;
  }> = [
    { name: "success", description: "Both roster members open the deterministic envelope.", envelope: sealed, recipients: bothMembers },
    { name: "tamper-ciphertext", description: "One ciphertext bit is changed without updating contentHash; public step 4 returns first.", envelope: tampered, recipients: bothMembers },
    { name: "tamper-ciphertext-rehashed", description: "One ciphertext bit is changed and contentHash is recomputed; content AEAD fails at step 6.", envelope: tamperedRehashed, recipients: bothMembers },
    { name: "wrong-claim", description: "A claim absent from the roster has no recipient wrap and never decapsulates.", envelope: sealed, recipients: [
      { name: "outsider/absent-claim", claim: CLAIM_OUTSIDER, keySeed: "outsider", dk: outsider.dk },
    ] },
    { name: "wrong-dk", description: "Member A's in-roster claim is opened with the outsider dk; the wrap authentication fails.", envelope: sealed, recipients: [
      { name: "member-a/outsider-dk", claim: CLAIM_A, keySeed: "outsider", dk: outsider.dk },
    ] },
    { name: "aad-mismatch", description: "The header channelId is changed without recomputing contentHash; public step 4 returns first.", envelope: aadMismatch, recipients: bothMembers },
    { name: "aad-mismatch-rehashed", description: "The header channelId is changed and contentHash recomputed; content AAD authentication fails at step 6.", envelope: aadMismatchRehashed, recipients: bothMembers },
    { name: "member-set-mismatch", description: "The memberSetHash is changed after envelope construction; step 3 returns first.", envelope: memberSetMismatch, recipients: bothMembers },
    { name: "member-key-swap", description: "Member B's advertised public key is replaced while wraps and memberKeysHash remain unchanged.", envelope: memberKeySwap, recipients: bothMembers },
  ];

  return {
    vectorVersion: "0.1",
    suiteId: sealed.suiteId,
    notes: {
      keyDerivation: "Raw ML-KEM-768 keygen with the listed 64-byte seeds; no SDK HKDF derivation.",
      memberKeyBinding: "Advertised {claim, kem, publicKey} entries are committed by memberKeysHash.",
      keySig: "keySig and stale-key verification are specified but out of scope; verification step 2 is skipped because it needs the DACS signer.",
      contentHash: "SHA-256 over UTF8(JCS(header)) || iv || ciphertext || tag.",
    },
    vectors: variants.map((variant) => ({
      name: variant.name,
      description: variant.description,
      inputs,
      envelope: variant.envelope,
      expected: {
        integrity: verifyEnvelopeIntegrity(variant.envelope),
        recipients: variant.recipients.map(({ name, claim, keySeed, dk }) => ({
          name,
          claim,
          keySeed,
          outcome: expectedOpen(openEnvelope(variant.envelope, { claim, dk })),
        })),
      },
    })),
  };
}

export function serializeVectors(): string {
  return `${JSON.stringify(generateVectors(), null, 2)}\n`;
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--check") || args.filter((arg) => arg === "--check").length > 1) {
    console.error("usage: npx tsx conformance/transcript-envelope/generate-vectors.mts [--check]");
    process.exitCode = 2;
    return;
  }
  const generated = serializeVectors();
  if (args[0] === "--check") {
    let existing: string;
    try {
      existing = readFileSync(VECTOR_PATH, "utf8");
    } catch {
      console.error(`missing vector file: ${VECTOR_PATH}`);
      process.exitCode = 1;
      return;
    }
    if (existing !== generated) {
      console.error(`vector file differs: ${VECTOR_PATH}`);
      process.exitCode = 1;
      return;
    }
    console.log(`vector file is current: ${VECTOR_PATH}`);
    return;
  }
  writeFileSync(VECTOR_PATH, generated);
  console.log(`wrote ${VECTOR_PATH}`);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main();
