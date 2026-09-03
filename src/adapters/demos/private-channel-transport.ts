/**
 * Private-channel byte transports.
 *
 * Recommended defaults: use the paired in-process FIFO for local/test work;
 * keep live delivery disabled unless the exact operator flag is present and a
 * pre-provisioned encryptor plus a minimal messaging peer are injected.
 */

import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../../jcs.js';

export type PrivateChannelMode = 'local' | 'l2ps-live';

export interface PrivateChannelOpenRequest {
  manifestHash: string;
  nonce: Uint8Array;
  sender: PrivateChannelOpenMember;
  peer: PrivateChannelOpenMember;
  signEnvelopeHash(hash: string): Promise<Uint8Array>;
  verifyEnvelopeHash(claim: string, hash: string, signature: Uint8Array): boolean | Promise<boolean>;
}

export interface PrivateChannelOpenMember {
  seatId: string;
  claim: string;
  peerId?: string;
}

export interface PrivateChannelTransport {
  readonly mode: PrivateChannelMode;
  open(request: PrivateChannelOpenRequest): Promise<Uint8Array>;
  send(frame: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array>;
  close(): Promise<void>;
}

interface HandshakeSide {
  request?: Pick<PrivateChannelOpenRequest, 'manifestHash' | 'nonce'>;
  resolve?: (nonce: Uint8Array) => void;
  reject?: (error: Error) => void;
}

interface PairState {
  handshakes: [HandshakeSide, HandshakeSide];
  mailboxes: [ByteMailbox, ByteMailbox];
}

class ByteMailbox {
  private readonly queued: Uint8Array[] = [];
  private readonly waiting: Array<{ resolve: (frame: Uint8Array) => void; reject: (error: Error) => void }> = [];
  private ended = false;
  private failure?: Error;

  push(frame: Uint8Array): void {
    if (this.ended) throw new Error('Private-channel mailbox is closed');
    const copy = frame.slice();
    const waiter = this.waiting.shift();
    if (waiter) waiter.resolve(copy);
    else this.queued.push(copy);
  }

  next(): Promise<Uint8Array> {
    const frame = this.queued.shift();
    if (frame) return Promise.resolve(frame.slice());
    if (this.ended) return Promise.reject(this.failure ?? new Error('Private-channel mailbox is closed'));
    return new Promise((resolve, reject) => this.waiting.push({ resolve, reject }));
  }

  end(): void {
    this.ended = true;
    for (const waiter of this.waiting.splice(0)) waiter.reject(new Error('Private-channel mailbox is closed'));
  }

  fail(error: Error): void {
    if (this.ended) return;
    this.failure = error;
    this.ended = true;
    this.queued.length = 0;
    for (const waiter of this.waiting.splice(0)) waiter.reject(error);
  }
}

/** Paired FIFO mailboxes. Every boundary copies bytes; injectFrame is deterministic and inbound. */
export class InProcessPrivateChannelTransport implements PrivateChannelTransport {
  readonly mode = 'local' as const;
  private opened = false;
  private closed = false;

  private constructor(private readonly pair: PairState, private readonly side: 0 | 1) {}

  static pair(): [InProcessPrivateChannelTransport, InProcessPrivateChannelTransport] {
    const state: PairState = {
      handshakes: [{}, {}],
      mailboxes: [new ByteMailbox(), new ByteMailbox()],
    };
    return [new this(state, 0), new this(state, 1)];
  }

  async open(request: PrivateChannelOpenRequest): Promise<Uint8Array> {
    if (this.opened || this.closed) throw new Error('Private-channel transport cannot be opened');
    this.opened = true;
    const mine = this.pair.handshakes[this.side];
    mine.request = { manifestHash: request.manifestHash, nonce: request.nonce.slice() };
    const result = new Promise<Uint8Array>((resolve, reject) => {
      mine.resolve = resolve;
      mine.reject = reject;
    });
    const otherSide = this.side === 0 ? 1 : 0;
    const other = this.pair.handshakes[otherSide];
    if (other.request) {
      const sides = this.pair.handshakes;
      if (other.request.manifestHash !== request.manifestHash) {
        const error = new Error('Private-channel membership manifests differ');
        sides[0].reject?.(error);
        sides[1].reject?.(error);
      } else {
        // Side zero's cryptographically fresh proposal is the shared channel nonce.
        const agreed = sides[0].request!.nonce.slice();
        sides[0].resolve?.(agreed.slice());
        sides[1].resolve?.(agreed.slice());
      }
    }
    return result;
  }

  async send(frame: Uint8Array): Promise<void> {
    if (!this.opened || this.closed) throw new Error('Private-channel transport is not open');
    this.pair.mailboxes[this.side === 0 ? 1 : 0].push(frame);
  }

  receive(): Promise<Uint8Array> {
    if (!this.opened || this.closed) return Promise.reject(new Error('Private-channel transport is not open'));
    return this.pair.mailboxes[this.side].next();
  }

  /** Add one copied frame to this endpoint's inbound FIFO (negative-vector seam). */
  injectFrame(frame: Uint8Array): void {
    if (!this.opened || this.closed) throw new Error('Private-channel transport is not open');
    this.pair.mailboxes[this.side].push(frame);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.pair.mailboxes[this.side].end();
  }
}

export interface ProvisionedSubnetEncryptor {
  encryptBytes(bytes: Uint8Array): Promise<unknown>;
  decryptBytes(encrypted: unknown): Promise<Uint8Array>;
}

export interface StructuralMessagingPeer {
  send(to: string, encrypted: unknown, messageHash: string): Promise<unknown>;
  onMessage(handler: (payload: { from: string; encrypted: unknown; messageHash: string }) => void): void;
}

export interface L2psPrivateChannelTransportOptions {
  encryptor: ProvisionedSubnetEncryptor;
  peer?: StructuralMessagingPeer;
  recipient: string;
}

interface ChannelOpenPayload {
  kind: 'channel-open';
  v: 'pathos-private-channel-open:1';
  manifestHash: string;
  nonceShare: string;
  sender: { seatId: string; claim: string };
  peerId: string;
}

interface SignedChannelOpen {
  payload: ChannelOpenPayload;
  signature: string;
}

export class PrivateChannelRefusalError extends Error {
  override readonly name = 'PrivateChannelRefusalError';
}

export class PrivateChannelFatalError extends Error {
  override readonly name = 'PrivateChannelFatalError';
}

const LIVE_CAPABILITIES = ['encryptBytes', 'decryptBytes'] as const;
const PEER_CAPABILITIES = ['send', 'onMessage'] as const;
const OPEN_VERSION = 'pathos-private-channel-open:1' as const;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(value: unknown, length: number, label: string): Uint8Array {
  if (typeof value !== 'string') throw new PrivateChannelRefusalError(`${label} is invalid`);
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (bytes.length !== length || bytesToBase64(bytes) !== value) {
    throw new PrivateChannelRefusalError(`${label} is invalid`);
  }
  return bytes;
}

function assertExactCapabilities(value: object, allowed: readonly string[], label: string): void {
  const ownKeys = Reflect.ownKeys(value);
  const actual = ownKeys.filter((key): key is string => typeof key === 'string').sort();
  const expected = [...allowed].sort();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (ownKeys.length !== expected.length || actual.length !== expected.length
    || actual.some((name, index) => name !== expected[index])
    || expected.some((name) => descriptors[name]?.get !== undefined || typeof descriptors[name]?.value !== 'function')) {
    throw new PrivateChannelRefusalError(`${label} does not match the private-channel capability allowlist`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function parseSignedOpen(frame: Uint8Array): SignedChannelOpen {
  let raw: unknown;
  try {
    raw = JSON.parse(dec.decode(frame)) as unknown;
  } catch {
    throw new PrivateChannelRefusalError('Live channel-open frame is invalid');
  }
  if (!isRecord(raw) || !exactKeys(raw, ['payload', 'signature']) || !isRecord(raw.payload)
    || !exactKeys(raw.payload, ['kind', 'v', 'manifestHash', 'nonceShare', 'sender', 'peerId'])
    || !isRecord(raw.payload.sender) || !exactKeys(raw.payload.sender, ['seatId', 'claim'])
    || raw.payload.kind !== 'channel-open' || raw.payload.v !== OPEN_VERSION
    || typeof raw.payload.manifestHash !== 'string' || typeof raw.payload.peerId !== 'string'
    || typeof raw.payload.sender.seatId !== 'string' || typeof raw.payload.sender.claim !== 'string'
    || typeof raw.signature !== 'string') {
    throw new PrivateChannelRefusalError('Live channel-open frame is invalid');
  }
  base64ToBytes(raw.payload.nonceShare, 32, 'Live channel-open nonce share');
  base64ToBytes(raw.signature, 64, 'Live channel-open signature');
  return raw as unknown as SignedChannelOpen;
}

function ciphertextBytes(encrypted: unknown): Uint8Array {
  if (encrypted instanceof Uint8Array) return encrypted;
  if (typeof encrypted === 'string') return enc.encode(encrypted);
  if (encrypted instanceof ArrayBuffer) return new Uint8Array(encrypted);
  if (ArrayBuffer.isView(encrypted)) {
    return new Uint8Array(encrypted.buffer, encrypted.byteOffset, encrypted.byteLength);
  }
  return enc.encode(JSON.stringify(encrypted));
}

function hashBytes(bytes: Uint8Array): string {
  return Buffer.from(sha256(bytes)).toString('hex');
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  return Buffer.compare(Buffer.from(a), Buffer.from(b));
}

async function sendEncrypted(
  options: L2psPrivateChannelTransportOptions,
  frame: Uint8Array,
): Promise<void> {
  if (!options.peer) throw new Error('Live private-channel transport is not open');
  const encrypted = await options.encryptor.encryptBytes(frame.slice());
  await options.peer.send(options.recipient, encrypted, hashBytes(ciphertextBytes(encrypted)));
}

/** Live encrypted-byte delivery; it cannot create or connect a messaging peer. */
export class L2psPrivateChannelTransport implements PrivateChannelTransport {
  readonly mode = 'l2ps-live' as const;
  private readonly inbox = new ByteMailbox();
  private started = false;
  private opening = false;
  private failure?: Error;

  constructor(private readonly options: L2psPrivateChannelTransportOptions) {}

  async open(request: PrivateChannelOpenRequest): Promise<Uint8Array> {
    if (process.env.PATHOS_L2PS_LIVE !== '1') {
      throw new Error('Live private channels require PATHOS_L2PS_LIVE=1');
    }
    if (!this.options.peer) throw new Error('Live private channels require an injected messaging peer');
    if (this.started || this.opening) throw new PrivateChannelRefusalError('Live private-channel transport cannot be opened');
    assertExactCapabilities(this.options.encryptor, LIVE_CAPABILITIES, 'Subnet encryptor');
    assertExactCapabilities(this.options.peer, PEER_CAPABILITIES, 'Messaging peer');
    if (request.nonce.length !== 32) throw new PrivateChannelRefusalError('Live channel-open nonce share must be 32 bytes');
    if (!request.sender.peerId || !request.peer.peerId || this.options.recipient !== request.peer.peerId) {
      throw new PrivateChannelRefusalError('Live private-channel peer identity is not bound by the manifest');
    }

    this.opening = true;
    let resolveOpen!: (nonce: Uint8Array) => void;
    let rejectOpen!: (error: Error) => void;
    const opened = new Promise<Uint8Array>((resolve, reject) => {
      resolveOpen = resolve;
      rejectOpen = reject;
    });
    this.options.peer.onMessage((payload) => {
      if (payload.from !== request.peer.peerId) {
        if (this.opening) {
          this.opening = false;
          rejectOpen(new PrivateChannelRefusalError('Live channel-open peer identity does not match the manifest'));
        }
        return;
      }
      void this.options.encryptor.decryptBytes(payload.encrypted)
        .then(async (frame) => {
          if (this.opening) {
            try {
              const handshake = parseSignedOpen(frame);
              const expectedSender = request.peer;
              if (handshake.payload.manifestHash !== request.manifestHash) {
                throw new PrivateChannelRefusalError('Live channel-open membership manifests differ');
              }
              if (handshake.payload.sender.seatId !== expectedSender.seatId
                || handshake.payload.sender.claim !== expectedSender.claim
                || handshake.payload.peerId !== expectedSender.peerId) {
                throw new PrivateChannelRefusalError('Live channel-open sender does not match the other manifest member');
              }
              const valid = await request.verifyEnvelopeHash(
                expectedSender.claim,
                hashBytes(jcsCanonical(handshake.payload)),
                base64ToBytes(handshake.signature, 64, 'Live channel-open signature'),
              );
              if (!valid) throw new PrivateChannelRefusalError('Live channel-open CCI signature is invalid');
              const remoteNonce = base64ToBytes(handshake.payload.nonceShare, 32, 'Live channel-open nonce share');
              const shares = [request.nonce.slice(), remoteNonce].sort(compareBytes);
              const combined = new Uint8Array(64);
              combined.set(shares[0]!, 0);
              combined.set(shares[1]!, 32);
              this.opening = false;
              this.started = true;
              resolveOpen(combined);
            } catch (error) {
              this.opening = false;
              rejectOpen(error instanceof Error ? error : new PrivateChannelRefusalError('Live channel-open was refused'));
            }
            return;
          }
          if (this.started) this.inbox.push(frame);
        })
        .catch(() => {
          const error = new PrivateChannelFatalError('Live private-channel ciphertext could not be decrypted');
          this.failure = error;
          if (this.opening) {
            this.opening = false;
            rejectOpen(error);
          } else {
            this.started = false;
            this.inbox.fail(error);
          }
        });
    });

    const openPayload: ChannelOpenPayload = {
      kind: 'channel-open',
      v: OPEN_VERSION,
      manifestHash: request.manifestHash,
      nonceShare: bytesToBase64(request.nonce),
      sender: { seatId: request.sender.seatId, claim: request.sender.claim },
      peerId: request.sender.peerId,
    };
    try {
      const signature = await request.signEnvelopeHash(hashBytes(jcsCanonical(openPayload)));
      const frame = jcsCanonical({ payload: openPayload, signature: bytesToBase64(signature) });
      await sendEncrypted(this.options, frame);
    } catch (error) {
      this.opening = false;
      throw error;
    }
    return opened;
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.failure) throw this.failure;
    if (!this.started) throw new Error('Live private-channel transport is not open');
    await sendEncrypted(this.options, frame);
  }

  receive(): Promise<Uint8Array> {
    if (this.failure) return Promise.reject(this.failure);
    if (!this.started) return Promise.reject(new Error('Live private-channel transport is not open'));
    return this.inbox.next();
  }

  async close(): Promise<void> {
    this.started = false;
    this.opening = false;
    this.inbox.end();
  }
}

/** Generates nonce bytes without consulting configuration or credentials. */
export function freshPrivateChannelNonce(): Uint8Array {
  return randomBytes(32);
}
