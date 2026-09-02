import assert from "node:assert/strict";
import { createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { ml_kem768 } from "@noble/post-quantum/ml-kem";

import {
  deriveMemberKeys,
  openEnvelope,
  sealEnvelope,
  verifyEnvelopeIntegrity,
  type Envelope,
} from "../../conformance/transcript-envelope/envelope.mjs";
import {
  generateVectors,
  serializeVectors,
} from "../../conformance/transcript-envelope/generate-vectors.mjs";

const VECTOR_PATH = new URL("../../conformance/vectors/transcript-envelope-v0.1.json", import.meta.url);
const CLAIM_A = "dacs:claim:member-a";

interface Outcome {
  ok: boolean;
  step?: number;
  reason?: string;
}

interface VectorRecord {
  name: string;
  inputs: {
    seeds: Record<string, string>;
    randomness: { cek: string; wrapM: string[]; wrapIv: string[]; iv: string };
    transcript: object;
    channelId: string;
    members: Array<{ claim: string; seed: string }>;
  };
  envelope: Envelope;
  expected: {
    integrity: Outcome;
    recipients: Array<{ name: string; claim: string; keySeed: string; outcome: Outcome }>;
  };
}

interface VectorFile {
  vectors: VectorRecord[];
}

const fromHex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "hex"));
const vectors = JSON.parse(readFileSync(VECTOR_PATH, "utf8")) as VectorFile;

function keysFor(vector: VectorRecord): Record<string, { ek: Uint8Array; dk: Uint8Array }> {
  return Object.fromEntries(Object.entries(vector.inputs.seeds).map(([name, seed]) => [
    name,
    deriveMemberKeys(fromHex(seed)),
  ]));
}

function outcome(result: ReturnType<typeof openEnvelope>): Outcome {
  return result.ok ? { ok: true } : { ok: false, step: result.step, reason: result.reason };
}

test("transcript-envelope vectors regenerate byte-identically", () => {
  assert.equal(serializeVectors(), readFileSync(VECTOR_PATH, "utf8"));
  assert.deepEqual(generateVectors(), vectors);
});

test("transcript-envelope expected verification outcomes are reproduced", () => {
  for (const vector of vectors.vectors) {
    assert.deepEqual(verifyEnvelopeIntegrity(vector.envelope), vector.expected.integrity, vector.name);
    const keys = keysFor(vector);
    for (const recipient of vector.expected.recipients) {
      assert.deepEqual(
        outcome(openEnvelope(vector.envelope, {
          claim: recipient.claim,
          dk: keys[recipient.keySeed]!.dk,
        })),
        recipient.outcome,
        `${vector.name}: ${recipient.name}`,
      );
    }
  }
});

test("an in-roster claim with the wrong dk fails wrap authentication at step 5", () => {
  const success = vectors.vectors.find(({ name }) => name === "success")!;
  const outsider = keysFor(success).outsider!;
  assert.deepEqual(openEnvelope(success.envelope, { claim: CLAIM_A, dk: outsider.dk }), {
    ok: false,
    step: 5,
    reason: "recipient wrap authentication failed",
  });
});

test("ML-KEM and wrap field sizes match the profile", () => {
  const success = vectors.vectors.find(({ name }) => name === "success")!;
  for (const memberKey of success.envelope.memberKeys) {
    assert.equal(Buffer.from(memberKey.publicKey, "base64url").length, 1184);
  }
  for (const wrap of success.envelope.wraps) {
    assert.equal(Buffer.from(wrap.kemCiphertext, "base64url").length, 1088);
    assert.equal(Buffer.from(wrap.wrapped, "base64url").length, 12 + 32 + 16);
  }
});

test("sealing the same inputs is byte-identical", () => {
  const vector = vectors.vectors.find(({ name }) => name === "success")!;
  const keys = keysFor(vector);
  const resealed = sealEnvelope({
    transcript: vector.inputs.transcript,
    channelId: vector.inputs.channelId,
    members: vector.inputs.members.map(({ claim, seed }) => ({ claim, ek: keys[seed]!.ek })),
    randomness: {
      cek: fromHex(vector.inputs.randomness.cek),
      wrapM: vector.inputs.randomness.wrapM.map(fromHex),
      wrapIv: vector.inputs.randomness.wrapIv.map(fromHex),
      iv: fromHex(vector.inputs.randomness.iv),
    },
  });
  assert.deepEqual(resealed, vector.envelope);
});

test("a tag tamper fails at step 4 before decapsulation", () => {
  const success = vectors.vectors.find(({ name }) => name === "success")!;
  const envelope = structuredClone(success.envelope);
  const tag = Buffer.from(envelope.tag, "base64url");
  tag[0] = tag[0]! ^ 1;
  envelope.tag = tag.toString("base64url");
  assert.deepEqual(openEnvelope(envelope, { claim: envelope.wraps[0]!.claim, dk: new Uint8Array() }), {
    ok: false,
    step: 4,
    reason: "contentHash mismatch",
  });
});

test("wrap framing opens with SDK-shaped 12/-16 slicing", () => {
  const vector = vectors.vectors.find(({ name }) => name === "success")!;
  const keys = keysFor(vector);
  const firstMember = vector.inputs.members[0]!;
  const wrap = vector.envelope.wraps.find(({ claim }) => claim === firstMember.claim)!;
  const framed = Buffer.from(wrap.wrapped, "base64url");
  const iv = framed.subarray(0, 12);
  const encryptedMessage = framed.subarray(12, -16);
  const authTag = framed.subarray(-16);
  const sharedSecret = ml_kem768.decapsulate(
    Buffer.from(wrap.kemCiphertext, "base64url"),
    keys[firstMember.seed]!.dk,
  );
  const decipher = createDecipheriv("aes-256-gcm", sharedSecret, iv);
  decipher.setAuthTag(authTag);
  const cek = Buffer.concat([decipher.update(encryptedMessage), decipher.final()]);
  assert.deepEqual(cek, Buffer.from(vector.inputs.randomness.cek, "hex"));
});
