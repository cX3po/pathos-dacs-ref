/**
 * SecureChannel — L2PS degrade-to-local secure-channel reference
 *
 * PATH-OS Labs extension — NOT part of the normative DACS v0.7 §7.7 spec list.
 * This apprentices the L2PS (Layer-2 Private Subnet) private-channel PATTERN
 * without depending on KyneSys' L2PS PoC: it presents one channel interface with
 * two interchangeable backends.
 *
 *   (1) L2PSChannel       — placeholder backend that WOULD route over an L2PS
 *                            private subnet when one is available. v0.1 ships it as
 *                            a typed stub whose channelStatus() reports
 *                            'l2ps-unavailable' and whose send()/receive() throw
 *                            'not-yet-available'. When the real L2PS lands, this is
 *                            the only file that changes; callers keep the same API.
 *
 *   (2) LocalSecureChannel — the always-available fallback. A self-contained
 *                            secure channel built on @noble/hashes + @noble/ed25519:
 *                              - per-message FRESH NONCE AEAD (encrypt-then-MAC; the
 *                                message key + keystream + MAC key are all HKDF-derived
 *                                from the static shared secret AND the per-message
 *                                nonce, so no static IV is ever reused);
 *                              - ed25519-signed envelopes (§7.7 domain-separated via
 *                                src/lib/sign.ts) binding the sender's public key;
 *                              - a MONOTONIC sequence number per (channel,sender) that
 *                                the receiver tracks to reject replays / reorders.
 *
 * SecureChannel wraps the two so a caller calls one channelStatus()/send()/receive()
 * API and the channel DEGRADES GRACEFULLY: if the L2PS backend is unavailable, it
 * routes over LocalSecureChannel and marks every delivered message 'degraded-local'.
 *
 * Conformance maintained:
 *   - Every envelope signature uses the §7.7 domain-separated ed25519 pattern via
 *     src/lib/sign.ts. CHANNEL_MSG is the DACS-3 separator for channel messages.
 *   - The envelope's signed body is JCS-canonical (RFC 8785) via src/jcs.ts, so
 *     sender and receiver compute the same signed_bytes.
 *
 * Crypto note — why HMAC/HKDF and not a packaged AEAD:
 *   The repo's declared deps (package.json) are @kynesyslabs/demosdk, @noble/ed25519,
 *   @noble/hashes, canonicalize — NO @noble/ciphers. To stay self-contained on the
 *   allowed deps, LocalSecureChannel builds an encrypt-then-MAC AEAD from primitives
 *   that ARE available: HKDF-SHA-256 for key derivation and an HMAC-SHA-256 keystream
 *   (counter-mode PRG) for confidentiality, with a separate HMAC-SHA-256 tag for
 *   integrity. This is a reference construction for the degrade PATTERN, not a
 *   drop-in for a hardware-accelerated production AEAD (ChaCha20-Poly1305 / AES-GCM);
 *   a deployment SHOULD swap the keystream+tag for a vetted AEAD once @noble/ciphers
 *   (or equivalent) is an approved dependency. The replay/sequence/signature/
 *   fresh-nonce DISCIPLINE this module enforces is the part that transfers verbatim.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { jcsCanonical } from '../jcs.js';
import { sign, verify as edVerify } from './sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { bytesToHex, hexToBytes } from './verify-bundle.js';

/* -------------------------------------------------------------------------- */
/*  Channel status                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Backend the channel is currently routing over.
 *   - 'l2ps'             — the L2PS private subnet is live; messages route over it.
 *   - 'degraded-local'   — L2PS unavailable; routing over LocalSecureChannel.
 */
export type ChannelMode = 'l2ps' | 'degraded-local';

/** What channelStatus() reports about a backend's readiness. */
export interface ChannelStatus {
  mode: ChannelMode;
  /** True iff this backend can currently carry traffic. */
  available: boolean;
  /** Human-readable reason, e.g. 'l2ps-unavailable' or 'local-fallback-ready'. */
  reason: string;
}

/* -------------------------------------------------------------------------- */
/*  Wire types                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The AEAD ciphertext payload for one message. Every field is hex/string so the
 * whole envelope JCS-canonicalises deterministically across implementations.
 */
export interface SealedPayload {
  /** Fresh per-message nonce (hex, 24 bytes). NEVER reused; drives all key derivation. */
  nonce: string;
  /** Encrypt-then-MAC ciphertext (hex). */
  ciphertext: string;
  /** HMAC-SHA-256 tag (hex) over (nonce-context || ciphertext) under the per-message MAC key. */
  tag: string;
}

/**
 * A signed channel envelope. The signature is ed25519 over
 * (CHANNEL_MSG || JCS(envelope-sans-signature)) — §7.7 discipline via src/lib/sign.ts.
 *
 * `senderPubkey` BINDS the envelope to its author: the receiver verifies the
 * signature against exactly this key, so a message cannot be re-attributed to a
 * different sender. `seq` is the per-(channel,sender) monotonic counter the
 * receiver tracks to reject replays.
 */
export interface ChannelEnvelope {
  v: 'pathos-secure-channel-envelope:0.1';
  /** Stable channel identifier both parties share (sender binding context). */
  channelId: string;
  /** Sender's ed25519 public key (hex) — bound into the signature + the AEAD AAD. */
  senderPubkey: string;
  /** Monotonic per-(channel,sender) sequence number. Strictly increasing; replay guard. */
  seq: number;
  /** The AEAD-sealed message body. */
  payload: SealedPayload;
  /** ed25519 signature (hex) over (CHANNEL_MSG || JCS(this-envelope-without-signature)). */
  signature: string;
}

/** A message handed to send()/returned from receive() before/after sealing. */
export interface PlainMessage {
  /** Opaque application bytes (UTF-8 here for the reference; any bytes work). */
  plaintext: Uint8Array;
}

/**
 * What receive() returns on success. `mode` records which backend delivered it so
 * the caller can SEE the degrade ('degraded-local' when the L2PS path was down).
 */
export interface ReceivedMessage {
  plaintext: Uint8Array;
  /** Sender public key (hex) recovered + signature-verified from the envelope. */
  senderPubkey: string;
  seq: number;
  mode: ChannelMode;
}

/* -------------------------------------------------------------------------- */
/*  Key material                                                               */
/* -------------------------------------------------------------------------- */

/** One side's signing identity + the channel's shared secret. */
export interface ChannelKeys {
  /** This party's ed25519 private key (32 bytes) — signs every outbound envelope. */
  signPrivKey: Uint8Array;
  /** This party's ed25519 public key (32 bytes) — stamped into senderPubkey. */
  signPubKey: Uint8Array;
  /**
   * Symmetric channel secret shared by both parties (>=32 bytes recommended).
   * In a real deployment this is the output of an ed25519/X25519 key agreement or
   * an L2PS-provisioned channel key; v0.1 takes it as given so the local backend
   * is testable in isolation.
   */
  sharedSecret: Uint8Array;
}

/* -------------------------------------------------------------------------- */
/*  SecureChannel backend interface                                            */
/* -------------------------------------------------------------------------- */

/** The one interface both backends implement. */
export interface SecureChannelBackend {
  readonly mode: ChannelMode;
  channelStatus(): ChannelStatus;
  /** Seal + sign a message into an envelope (advances the local send sequence). */
  send(message: PlainMessage): ChannelEnvelope;
  /** Verify + open an envelope (enforces signature, sender binding, monotonic seq, AEAD). */
  receive(envelope: ChannelEnvelope): ReceivedMessage;
}

/* -------------------------------------------------------------------------- */
/*  AEAD primitives (encrypt-then-MAC over an HMAC keystream)                  */
/* -------------------------------------------------------------------------- */

const NONCE_BYTES = 24;
const TAG_BYTES = 32;

/**
 * Derive the per-message encryption key + MAC key from the static shared secret
 * AND the fresh nonce via HKDF-SHA-256. Because the nonce is fresh per message and
 * fed into the salt, every message gets a DIFFERENT key pair — there is no static
 * IV/key reuse even though the shared secret is static.
 */
function deriveMessageKeys(
  sharedSecret: Uint8Array,
  nonce: Uint8Array,
  channelId: string,
  senderPubkey: string,
  seq: number
): { encKey: Uint8Array; macKey: Uint8Array } {
  // `info` binds the derived keys to the channel + sender + sequence so the same
  // (secret,nonce) can never produce usable keys in a different context.
  const info = new TextEncoder().encode(
    `pathos-secure-channel:v1:${channelId}:${senderPubkey}:${seq}`
  );
  // 64 bytes out: first 32 = encryption key, next 32 = MAC key.
  const okm = hkdf(sha256, sharedSecret, nonce, info, 64);
  return { encKey: okm.slice(0, 32), macKey: okm.slice(32, 64) };
}

/**
 * HMAC-SHA-256 counter-mode keystream of `length` bytes under `encKey`, seeded by
 * `nonce`. Block i = HMAC(encKey, nonce || u32be(i)); blocks are concatenated and
 * truncated to `length`. Distinct nonce ⇒ distinct keystream.
 */
function keystream(encKey: Uint8Array, nonce: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const ctr = new Uint8Array(4);
    ctr[0] = (counter >>> 24) & 0xff;
    ctr[1] = (counter >>> 16) & 0xff;
    ctr[2] = (counter >>> 8) & 0xff;
    ctr[3] = counter & 0xff;
    const block = hmac(sha256, encKey, concat(nonce, ctr));
    const take = Math.min(block.length, length - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter++;
  }
  return out;
}

/** Concatenate byte arrays. */
function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison of two byte arrays (length-checked first). */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * Seal `plaintext` under the shared secret with a FRESH nonce. Encrypt-then-MAC:
 *   c   = plaintext XOR keystream(encKey, nonce)
 *   tag = HMAC(macKey, aad || nonce || c)
 * where `aad` binds the ciphertext to its channel/sender/seq context, so a tag
 * from one context cannot be replayed into another.
 */
function seal(
  keys: ChannelKeys,
  channelId: string,
  senderPubkey: string,
  seq: number,
  plaintext: Uint8Array
): SealedPayload {
  const nonce = randomBytes(NONCE_BYTES);
  const { encKey, macKey } = deriveMessageKeys(keys.sharedSecret, nonce, channelId, senderPubkey, seq);
  const ks = keystream(encKey, nonce, plaintext.length);
  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) ciphertext[i] = (plaintext[i] ?? 0) ^ (ks[i] ?? 0);
  const aad = aadBytes(channelId, senderPubkey, seq);
  const tag = hmac(sha256, macKey, concat(aad, nonce, ciphertext));
  return { nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext), tag: bytesToHex(tag) };
}

/**
 * Open a SealedPayload. Verifies the MAC (encrypt-then-MAC: authenticate BEFORE
 * decrypt) under the per-message MAC key, then XORs out the keystream. Throws on
 * any tampering (wrong tag, wrong length, bad hex).
 */
function open(
  keys: ChannelKeys,
  channelId: string,
  senderPubkey: string,
  seq: number,
  payload: SealedPayload
): Uint8Array {
  const nonce = hexToBytes(payload.nonce);
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`secure-channel: nonce length ${nonce.length}, expected ${NONCE_BYTES}`);
  }
  const ciphertext = hexToBytes(payload.ciphertext);
  const tag = hexToBytes(payload.tag);
  if (tag.length !== TAG_BYTES) {
    throw new Error(`secure-channel: tag length ${tag.length}, expected ${TAG_BYTES}`);
  }
  const { encKey, macKey } = deriveMessageKeys(keys.sharedSecret, nonce, channelId, senderPubkey, seq);
  const aad = aadBytes(channelId, senderPubkey, seq);
  const expectedTag = hmac(sha256, macKey, concat(aad, nonce, ciphertext));
  if (!timingSafeEqual(tag, expectedTag)) {
    throw new Error('secure-channel: AEAD tag mismatch — ciphertext tampered or wrong key');
  }
  const ks = keystream(encKey, nonce, ciphertext.length);
  const plaintext = new Uint8Array(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i++) plaintext[i] = (ciphertext[i] ?? 0) ^ (ks[i] ?? 0);
  return plaintext;
}

/** Additional authenticated data binding a payload to its channel/sender/seq. */
function aadBytes(channelId: string, senderPubkey: string, seq: number): Uint8Array {
  return new TextEncoder().encode(`pathos-secure-channel-aad:v1:${channelId}:${senderPubkey}:${seq}`);
}

/* -------------------------------------------------------------------------- */
/*  Envelope signing (§7.7 domain-separated)                                   */
/* -------------------------------------------------------------------------- */

/** The envelope body that gets JCS-canonicalised + signed (everything but the sig). */
type UnsignedEnvelope = Omit<ChannelEnvelope, 'signature'>;

function signEnvelope(unsigned: UnsignedEnvelope, privKey: Uint8Array): string {
  const body = jcsCanonical(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.CHANNEL_MSG, body, privKey);
  return bytesToHex(sig);
}

function verifyEnvelopeSignature(envelope: ChannelEnvelope, pubKey: Uint8Array): boolean {
  const { signature, ...unsigned } = envelope;
  const body = jcsCanonical(unsigned);
  let sig: Uint8Array;
  try {
    sig = hexToBytes(signature);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  return edVerify(DOMAIN_SEPARATORS.CHANNEL_MSG, sig, body, pubKey);
}

/* -------------------------------------------------------------------------- */
/*  LocalSecureChannel — the always-available fallback backend                 */
/* -------------------------------------------------------------------------- */

/**
 * Self-contained secure channel: fresh-nonce AEAD + ed25519-signed envelopes +
 * monotonic per-sender sequence numbers. No network, no L2PS — purely local
 * cryptographic discipline, so it is the backend a degraded channel routes over.
 *
 * Sequence model (replay protection):
 *   - The SENDER advances `nextSeq` on every send(), stamping it into the envelope.
 *   - The RECEIVER tracks the highest seq it has accepted PER SENDER PUBKEY and
 *     rejects any envelope whose seq is <= the last accepted (replay or reorder).
 *     A fresh sender starts at seq 0 being accepted; subsequent must strictly
 *     increase.
 */
export class LocalSecureChannel implements SecureChannelBackend {
  readonly mode: ChannelMode = 'degraded-local';
  private nextSeq = 0;
  /** Highest seq accepted per remote sender pubkey-hex. -1 = none yet. */
  private readonly lastAcceptedSeq = new Map<string, number>();

  constructor(
    private readonly channelId: string,
    private readonly keys: ChannelKeys
  ) {}

  channelStatus(): ChannelStatus {
    return { mode: 'degraded-local', available: true, reason: 'local-fallback-ready' };
  }

  send(message: PlainMessage): ChannelEnvelope {
    const senderPubkey = bytesToHex(this.keys.signPubKey);
    const seq = this.nextSeq++;
    const payload = seal(this.keys, this.channelId, senderPubkey, seq, message.plaintext);
    const unsigned: UnsignedEnvelope = {
      v: 'pathos-secure-channel-envelope:0.1',
      channelId: this.channelId,
      senderPubkey,
      seq,
      payload,
    };
    const signature = signEnvelope(unsigned, this.keys.signPrivKey);
    return { ...unsigned, signature };
  }

  receive(envelope: ChannelEnvelope): ReceivedMessage {
    if (envelope.channelId !== this.channelId) {
      throw new Error(
        `secure-channel: envelope channelId="${envelope.channelId}" does not match this channel "${this.channelId}"`
      );
    }

    // 1. Sender binding — recover the declared pubkey and verify the signature against it.
    let senderPubKeyBytes: Uint8Array;
    try {
      senderPubKeyBytes = hexToBytes(envelope.senderPubkey);
    } catch (e) {
      throw new Error(`secure-channel: senderPubkey is not valid hex: ${(e as Error).message}`);
    }
    if (senderPubKeyBytes.length !== 32) {
      throw new Error(`secure-channel: senderPubkey length ${senderPubKeyBytes.length}, expected 32`);
    }
    if (!verifyEnvelopeSignature(envelope, senderPubKeyBytes)) {
      throw new Error(
        'secure-channel: envelope signature did NOT verify against its senderPubkey ' +
        '(tampered envelope or sender mis-binding)'
      );
    }

    // 2. Monotonic sequence — reject replays / reorders BEFORE decrypting.
    const last = this.lastAcceptedSeq.get(envelope.senderPubkey) ?? -1;
    if (!Number.isInteger(envelope.seq) || envelope.seq < 0) {
      throw new Error(`secure-channel: envelope seq=${envelope.seq} is not a non-negative integer`);
    }
    if (envelope.seq <= last) {
      throw new Error(
        `secure-channel: replay/reorder rejected — seq=${envelope.seq} <= last accepted ${last} ` +
        `for sender ${envelope.senderPubkey.slice(0, 12)}…`
      );
    }

    // 3. AEAD open (authenticate-then-decrypt). Throws on tamper.
    const plaintext = open(this.keys, this.channelId, envelope.senderPubkey, envelope.seq, envelope.payload);

    // Commit the sequence only after EVERYTHING above passed.
    this.lastAcceptedSeq.set(envelope.senderPubkey, envelope.seq);

    return { plaintext, senderPubkey: envelope.senderPubkey, seq: envelope.seq, mode: this.mode };
  }
}

/* -------------------------------------------------------------------------- */
/*  L2PSChannel — typed stub for the (not-yet-available) L2PS private subnet    */
/* -------------------------------------------------------------------------- */

/** Raised by the L2PS backend until a real L2PS subnet is wired in. */
export class L2PSUnavailableError extends Error {
  constructor(message = 'not-yet-available') {
    super(`L2PS: ${message}`);
    this.name = 'L2PSUnavailableError';
  }
}

/**
 * Placeholder for the L2PS-routed backend. v0.1 is a typed stub: channelStatus()
 * reports unavailable, and send()/receive() throw L2PSUnavailableError. When the
 * real L2PS lands, this class is the only thing that changes — it will seal/route
 * over the private subnet and report mode 'l2ps'.
 */
export class L2PSChannel implements SecureChannelBackend {
  readonly mode: ChannelMode = 'l2ps';

  constructor(private readonly channelId: string) {}

  channelStatus(): ChannelStatus {
    return {
      mode: 'l2ps',
      available: false,
      reason: `l2ps-unavailable (channel ${this.channelId}; L2PS PoC not wired in this reference)`,
    };
  }

  send(_message: PlainMessage): ChannelEnvelope {
    throw new L2PSUnavailableError('send over L2PS is not-yet-available; degrade to LocalSecureChannel');
  }

  receive(_envelope: ChannelEnvelope): ReceivedMessage {
    throw new L2PSUnavailableError('receive over L2PS is not-yet-available; degrade to LocalSecureChannel');
  }
}

/* -------------------------------------------------------------------------- */
/*  SecureChannel — the degrade-aware façade                                   */
/* -------------------------------------------------------------------------- */

/**
 * One channelStatus()/send()/receive() API over two backends. Prefers L2PS when
 * available; otherwise DEGRADES to LocalSecureChannel and marks delivered messages
 * 'degraded-local' so the caller can observe the degrade.
 */
export class SecureChannel {
  private readonly l2ps: L2PSChannel;
  private readonly local: LocalSecureChannel;

  constructor(channelId: string, keys: ChannelKeys) {
    this.l2ps = new L2PSChannel(channelId);
    this.local = new LocalSecureChannel(channelId, keys);
  }

  /** Which backend is currently live. L2PS if available, else the local fallback. */
  private activeBackend(): SecureChannelBackend {
    return this.l2ps.channelStatus().available ? this.l2ps : this.local;
  }

  /**
   * Report the effective channel status. When L2PS is down, this reports the
   * degraded-local backend so the caller SEES the degrade in channelStatus().
   */
  channelStatus(): ChannelStatus {
    const l2psStatus = this.l2ps.channelStatus();
    if (l2psStatus.available) return l2psStatus;
    const localStatus = this.local.channelStatus();
    return {
      mode: 'degraded-local',
      available: localStatus.available,
      reason: `l2ps-unavailable → ${localStatus.reason}`,
    };
  }

  /** Seal + sign a message over the active backend. */
  send(message: PlainMessage): ChannelEnvelope {
    return this.activeBackend().send(message);
  }

  /**
   * Receive over the active backend. The returned message's `mode` is
   * 'degraded-local' whenever the L2PS path was unavailable, so the degrade is
   * always visible at the message level (not just channelStatus()).
   */
  receive(envelope: ChannelEnvelope): ReceivedMessage {
    return this.activeBackend().receive(envelope);
  }
}
