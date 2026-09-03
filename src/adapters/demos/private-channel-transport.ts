/**
 * Private-channel byte transports.
 *
 * Recommended defaults: use the paired in-process FIFO for local/test work;
 * keep live delivery disabled unless the exact operator flag is present and a
 * pre-provisioned encryptor plus a minimal messaging peer are injected.
 */

import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2';

export type PrivateChannelMode = 'local' | 'l2ps-live';

export interface PrivateChannelOpenRequest {
  manifestHash: string;
  nonce: Uint8Array;
}

export interface PrivateChannelTransport {
  readonly mode: PrivateChannelMode;
  open(request: PrivateChannelOpenRequest): Promise<Uint8Array>;
  send(frame: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array>;
  close(): Promise<void>;
}

interface HandshakeSide {
  request?: PrivateChannelOpenRequest;
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
    if (this.ended) return Promise.reject(new Error('Private-channel mailbox is closed'));
    return new Promise((resolve, reject) => this.waiting.push({ resolve, reject }));
  }

  end(): void {
    this.ended = true;
    for (const waiter of this.waiting.splice(0)) waiter.reject(new Error('Private-channel mailbox is closed'));
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

const LIVE_CAPABILITIES = new Set(['encryptBytes', 'decryptBytes']);
const PEER_CAPABILITIES = new Set(['send', 'onMessage']);

function ownAndPrototypeFunctionNames(value: object): string[] {
  const names = new Set<string>();
  let cursor: object | null = value;
  while (cursor && cursor !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(cursor)) {
      if (name !== 'constructor' && typeof (value as Record<string, unknown>)[name] === 'function') names.add(name);
    }
    cursor = Object.getPrototypeOf(cursor) as object | null;
  }
  return [...names];
}

function assertMinimalCapabilities(value: object, allowed: ReadonlySet<string>, label: string): void {
  const extras = ownAndPrototypeFunctionNames(value).filter((name) => !allowed.has(name));
  if (extras.length > 0) throw new Error(`${label} exposes capabilities outside the private-channel allowlist`);
}

/** Live encrypted-byte delivery; it cannot create or connect a messaging peer. */
export class L2psPrivateChannelTransport implements PrivateChannelTransport {
  readonly mode = 'l2ps-live' as const;
  private readonly inbox = new ByteMailbox();
  private started = false;

  constructor(private readonly options: L2psPrivateChannelTransportOptions) {}

  async open(request: PrivateChannelOpenRequest): Promise<Uint8Array> {
    if (process.env.PATHOS_L2PS_LIVE !== '1') {
      throw new Error('Live private channels require PATHOS_L2PS_LIVE=1');
    }
    if (!this.options.peer) throw new Error('Live private channels require an injected messaging peer');
    assertMinimalCapabilities(this.options.encryptor, LIVE_CAPABILITIES, 'Subnet encryptor');
    assertMinimalCapabilities(this.options.peer, PEER_CAPABILITIES, 'Messaging peer');

    // Deliberately delayed until after flag and peer checks. This is the sole SDK import.
    const sdk = await import('@kynesyslabs/demosdk/l2ps');
    const capabilities = Object.keys(sdk).sort();
    if (capabilities.join(',') !== ['L2PS', 'anchor', 'binding', 'channel'].sort().join(',')) {
      throw new Error('Loaded L2PS namespace does not match the reviewed capability inventory');
    }
    this.options.peer.onMessage((payload) => {
      void this.options.encryptor.decryptBytes(payload.encrypted)
        .then((frame) => this.inbox.push(frame))
        .catch(() => this.inbox.end());
    });
    this.started = true;
    return request.nonce.slice();
  }

  async send(frame: Uint8Array): Promise<void> {
    if (!this.started || !this.options.peer) throw new Error('Live private-channel transport is not open');
    const copy = frame.slice();
    const encrypted = await this.options.encryptor.encryptBytes(copy);
    const messageHash = Buffer.from(sha256(copy)).toString('hex');
    await this.options.peer.send(this.options.recipient, encrypted, messageHash);
  }

  receive(): Promise<Uint8Array> {
    if (!this.started) return Promise.reject(new Error('Live private-channel transport is not open'));
    return this.inbox.next();
  }

  async close(): Promise<void> {
    this.started = false;
    this.inbox.end();
  }
}

/** Generates nonce bytes without consulting configuration or credentials. */
export function freshPrivateChannelNonce(): Uint8Array {
  return randomBytes(32);
}
