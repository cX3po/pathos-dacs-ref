import { createCipheriv, createDecipheriv, createHash } from "node:crypto";

import { ml_kem768 } from "@noble/post-quantum/ml-kem";

import { jcsCanonical, jcsHashHex } from "../../src/jcs.js";

export const SUITE_ID = "dacs-transcript-mlkem768-a256gcm/1";

const KEM = "ml-kem-768" as const;
const VERSION = "1" as const;
const HASH_RE = /^[0-9a-f]{64}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export interface MemberKey {
  claim: string;
  kem: typeof KEM;
  publicKey: string;
}

export interface RecipientWrap {
  claim: string;
  kemCiphertext: string;
  wrapped: string;
}

export interface Envelope {
  envelopeVersion: typeof VERSION;
  suiteId: typeof SUITE_ID;
  channelId: string;
  memberSetHash: string;
  memberKeysHash: string;
  plaintextHash: string;
  memberKeys: MemberKey[];
  wraps: RecipientWrap[];
  iv: string;
  ciphertext: string;
  tag: string;
  contentHash: string;
}

export type OpenResult =
  | { ok: true; transcript: object }
  | { ok: false; step: 1 | 3 | 4 | 5 | 6 | 7 | 8; reason: string };

type IntegrityResult = { ok: true } | { ok: false; step: 1 | 3 | 4; reason: string };

const b64u = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const sha256Hex = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");

function compareClaims(a: string, b: string): number {
  // Claims are already CF-2 canonical ClaimReferences. This profile only orders
  // their UTF-8 bytes; it performs no CF-2 canonicalisation here.
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function decodeBase64url(value: unknown, length: number | undefined): Uint8Array | undefined {
  if (typeof value !== "string" || !BASE64URL_RE.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || (length !== undefined && decoded.length !== length)) {
    return undefined;
  }
  return decoded;
}

function encryptGcm(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  if (aad !== undefined) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

function decryptGcm(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  if (aad !== undefined) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

type HeaderFields = Pick<Envelope,
  "suiteId" | "channelId" | "memberSetHash" | "memberKeysHash" | "plaintextHash">;

function headerOf(envelope: HeaderFields): object {
  return {
    suiteId: envelope.suiteId,
    transcriptVersion: VERSION,
    channelId: envelope.channelId,
    memberSetHash: envelope.memberSetHash,
    memberKeysHash: envelope.memberKeysHash,
    plaintextHash: envelope.plaintextHash,
  };
}

export function computeContentHash(envelope: HeaderFields & Pick<Envelope,
  "iv" | "ciphertext" | "tag">): string {
  return sha256Hex(Buffer.concat([
    jcsCanonical(headerOf(envelope)),
    decodeBase64url(envelope.iv, 12)!,
    decodeBase64url(envelope.ciphertext, undefined)!,
    decodeBase64url(envelope.tag, 16)!,
  ]));
}

/**
 * Derive a deterministic raw ML-KEM-768 key pair from noble's 64-byte seed path.
 * This is the raw-keypair vector path allowed by profile section 10; it is not the
 * SDK's HKDF derivation from a wallet master seed.
 */
export function deriveMemberKeys(seed: Uint8Array): { ek: Uint8Array; dk: Uint8Array } {
  if (seed.length !== 64) throw new Error("ML-KEM-768 keygen seed must be 64 bytes");
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { ek: publicKey, dk: secretKey };
}

/**
 * Seal a profile envelope. `keySig` is absent because the DACS
 * ComponentSignature signer is outside this conformance harness.
 */
export function sealEnvelope(input: {
  transcript: object;
  channelId: string;
  members: { claim: string; ek: Uint8Array }[];
  randomness: { cek: Uint8Array; wrapM: Uint8Array[]; wrapIv: Uint8Array[]; iv: Uint8Array };
}): Envelope {
  const { cek, wrapM, wrapIv, iv } = input.randomness;
  if (cek.length !== 32) throw new Error("cek must be 32 bytes");
  if (iv.length !== 12) throw new Error("content iv must be 12 bytes");
  if (wrapM.length !== input.members.length || wrapIv.length !== input.members.length) {
    throw new Error("wrap randomness count must equal member count");
  }

  const members = [...input.members].sort((a, b) => compareClaims(a.claim, b.claim)).map((member, index) => ({
    ...member,
    m: wrapM[index]!,
    iv: wrapIv[index]!,
  }));
  if (new Set(members.map(({ claim }) => claim)).size !== members.length) {
    throw new Error("member claims must be unique");
  }
  for (const member of members) {
    if (member.ek.length !== 1184) throw new Error("member public key must be 1184 bytes");
    if (member.m.length !== 32) throw new Error("encapsulation randomness must be 32 bytes");
    if (member.iv.length !== 12) throw new Error("wrap iv must be 12 bytes");
  }

  const claims = members.map(({ claim }) => claim);
  const memberSetHash = jcsHashHex(claims);
  const memberKeys: MemberKey[] = members.map(({ claim, ek }) => ({
    claim,
    kem: KEM,
    publicKey: b64u(ek),
  }));
  const memberKeysHash = jcsHashHex(memberKeys);
  const plaintextHash = jcsHashHex(input.transcript);
  const header = {
    suiteId: SUITE_ID,
    transcriptVersion: VERSION,
    channelId: input.channelId,
    memberSetHash,
    memberKeysHash,
    plaintextHash,
  };
  const content = encryptGcm(cek, iv, jcsCanonical(input.transcript), jcsCanonical(header));

  const wraps: RecipientWrap[] = [];
  for (const member of members) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(member.ek, member.m);
    const encryptedCek = encryptGcm(sharedSecret, member.iv, cek);
    wraps.push({
      claim: member.claim,
      kemCiphertext: b64u(cipherText),
      wrapped: b64u(Buffer.concat([member.iv, encryptedCek.ciphertext, encryptedCek.tag])),
    });
  }

  const envelope: Envelope = {
    envelopeVersion: VERSION,
    suiteId: SUITE_ID,
    channelId: input.channelId,
    memberSetHash,
    memberKeysHash,
    plaintextHash,
    memberKeys,
    wraps,
    iv: b64u(iv),
    ciphertext: b64u(content.ciphertext),
    tag: b64u(content.tag),
    contentHash: "",
  };
  envelope.contentHash = computeContentHash(envelope);
  return envelope;
}

function verifyShape(value: unknown): { ok: true; envelope: Envelope } | { ok: false; reason: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, reason: "envelope must be an object" };
  }
  const envelope = value as Partial<Envelope>;
  if (envelope.envelopeVersion !== VERSION || envelope.suiteId !== SUITE_ID) {
    return { ok: false, reason: "unsupported envelope version or suite" };
  }
  if (typeof envelope.channelId !== "string" || !HASH_RE.test(envelope.memberSetHash ?? "") ||
      !HASH_RE.test(envelope.memberKeysHash ?? "") ||
      !HASH_RE.test(envelope.plaintextHash ?? "") || !HASH_RE.test(envelope.contentHash ?? "")) {
    return { ok: false, reason: "invalid header or hash encoding" };
  }
  if (!Array.isArray(envelope.memberKeys) || envelope.memberKeys.length === 0 ||
      !Array.isArray(envelope.wraps) || envelope.wraps.length !== envelope.memberKeys.length) {
    return { ok: false, reason: "memberKeys and wraps must be non-empty matched arrays" };
  }
  const claims: string[] = [];
  for (let i = 0; i < envelope.memberKeys.length; i += 1) {
    const key = envelope.memberKeys[i];
    const wrap = envelope.wraps[i];
    if (key === null || typeof key !== "object" || wrap === null || typeof wrap !== "object" ||
        typeof key.claim !== "string" || key.kem !== KEM || wrap.claim !== key.claim ||
        decodeBase64url(key.publicKey, 1184) === undefined ||
        decodeBase64url(wrap.kemCiphertext, 1088) === undefined ||
        decodeBase64url(wrap.wrapped, 60) === undefined) {
      return { ok: false, reason: "invalid member key or wrap" };
    }
    claims.push(key.claim);
  }
  if (new Set(claims).size !== claims.length ||
      claims.some((claim, index) => index > 0 && compareClaims(claims[index - 1]!, claim) >= 0)) {
    return { ok: false, reason: "member claims must be unique and in UTF-8 byte order" };
  }
  if (decodeBase64url(envelope.iv, 12) === undefined ||
      decodeBase64url(envelope.ciphertext, undefined) === undefined ||
      decodeBase64url(envelope.tag, 16) === undefined) {
    return { ok: false, reason: "invalid content encoding" };
  }
  try {
    jcsCanonical({ channelId: envelope.channelId, claims });
  } catch {
    return { ok: false, reason: "header or claims are not JCS-encodable" };
  }
  return { ok: true, envelope: envelope as Envelope };
}

export function verifyEnvelopeIntegrity(envelope: unknown):
  { ok: boolean; step?: number; reason?: string } {
  const shape = verifyShape(envelope);
  if (!shape.ok) return { ok: false, step: 1, reason: shape.reason };
  const checked = shape.envelope;
  const claims = checked.memberKeys.map(({ claim }) => claim);
  if (jcsHashHex(claims) !== checked.memberSetHash) {
    return { ok: false, step: 3, reason: "memberSetHash mismatch" };
  }
  if (jcsHashHex(checked.memberKeys.map(({ claim, kem, publicKey }) => ({ claim, kem, publicKey }))) !==
      checked.memberKeysHash) {
    return { ok: false, step: 3, reason: "memberKeysHash mismatch" };
  }
  if (computeContentHash(checked) !== checked.contentHash) {
    return { ok: false, step: 4, reason: "contentHash mismatch" };
  }
  return { ok: true };
}

export function openEnvelope(envelope: Envelope, me: { claim: string; dk: Uint8Array }): OpenResult {
  const integrity = verifyEnvelopeIntegrity(envelope) as IntegrityResult;
  if (!integrity.ok) return integrity;

  const wrap = envelope.wraps.find(({ claim }) => claim === me.claim);
  if (wrap === undefined) return { ok: false, step: 5, reason: "recipient wrap not found" };

  let cek: Uint8Array;
  try {
    const sharedSecret = ml_kem768.decapsulate(
      decodeBase64url(wrap.kemCiphertext, 1088)!,
      me.dk,
    );
    const framed = decodeBase64url(wrap.wrapped, 60)!;
    cek = decryptGcm(sharedSecret, framed.subarray(0, 12), framed.subarray(12, -16), framed.subarray(-16));
  } catch {
    return { ok: false, step: 5, reason: "recipient wrap authentication failed" };
  }

  let transcript: object;
  try {
    const plaintext = decryptGcm(
      cek,
      decodeBase64url(envelope.iv, 12)!,
      decodeBase64url(envelope.ciphertext, undefined)!,
      decodeBase64url(envelope.tag, 16)!,
      jcsCanonical(headerOf(envelope)),
    );
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    transcript = parsed as object;
  } catch {
    return { ok: false, step: 6, reason: "content authentication or JSON decoding failed" };
  }

  try {
    if (jcsHashHex(transcript) !== envelope.plaintextHash) {
      return { ok: false, step: 7, reason: "plaintextHash mismatch" };
    }
  } catch {
    return { ok: false, step: 7, reason: "plaintext is not JCS-encodable" };
  }
  const record = transcript as Record<string, unknown>;
  const roster = envelope.memberKeys.map(({ claim }) => claim);
  if (record.channelId !== envelope.channelId || !Array.isArray(record.members) ||
      record.members.length !== roster.length || record.members.some((claim, index) => claim !== roster[index])) {
    return { ok: false, step: 8, reason: "plaintext channelId or roster mismatch" };
  }
  return { ok: true, transcript };
}
