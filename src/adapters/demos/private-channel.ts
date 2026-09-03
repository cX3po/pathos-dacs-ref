/**
 * Non-value private-channel adapter.
 *
 * Recommended defaults taken from the reviewed design: local paired transport,
 * exact per-sender sequencing from one, adapter-owned transcript ordering, the
 * registered session-record extension for closing commitments, and live mode
 * off unless explicitly enabled. Opaque payloads remain inert message bytes.
 */

import { sha256, sha512 } from '@noble/hashes/sha2';
import * as ed25519 from '@noble/ed25519';
import { jcsCanonical, jcsHashHex } from '../../jcs.js';
import {
  assertEmittableSeparator,
  assertKnownSeparator,
  buildSignedBytes,
  DACS_X_EXTENSION_SEPARATORS,
  REVIEWED_DACS_X_EXTENSION_SEPARATORS,
  type DomainSeparator,
} from '../../domain-sep.js';
import {
  freshPrivateChannelNonce,
  type PrivateChannelMode,
  type PrivateChannelTransport,
} from './private-channel-transport.js';

export type ClaimReference = `${string}:${string}`;

export interface PrivateChannelIdentity {
  claim: ClaimReference;
  demos: {
    readonly walletConnected: boolean;
    getEd25519Address(): Promise<string>;
    crypto: {
      sign(algorithm: string, payload: Uint8Array): Promise<{ signature: Uint8Array | ArrayLike<number> }>;
    };
  };
}

export type PrivateChannelContentKind =
  | 'agent-message'
  | 'channel-close'
  | 'transcript-signature';

export interface ChannelMember {
  seatId: string;
  claim: ClaimReference;
  peerId?: string;
}

export interface MembershipBinding extends ChannelMember {
  signature: string;
}

export interface MembershipManifest {
  v: 'pathos-private-channel-membership:1';
  coordinatorClaim: ClaimReference;
  members: readonly MembershipBinding[];
}

export interface PrivateChannelEnvelope {
  v: 'pathos-private-channel-envelope:1';
  channelId: string;
  kind: PrivateChannelContentKind;
  sender: ChannelMember;
  sequence: number;
  payloadBase64: string;
  sentAt: string;
  signature: string;
}

export interface ClosingSignature {
  sender: ChannelMember;
  transcriptHash: string;
  signature: string;
}

export interface ChannelCounter {
  claim: ClaimReference;
  sequence: number;
}

export interface ChannelTranscript {
  v: 'pathos-private-channel-transcript:1';
  mode: PrivateChannelMode;
  channelId: string;
  nonceBase64: string;
  membership: MembershipManifest;
  envelopes: PrivateChannelEnvelope[];
  finalCounters: ChannelCounter[];
  closingSignatures: ClosingSignature[];
}

export interface ReceivedMessage {
  bytes: Uint8Array;
  sender: ChannelMember;
  sequence: number;
  sentAt: string;
}

export interface ChannelTranscriptVerifier {
  verifyMembershipSignature?(
    claim: ClaimReference,
    bindingBytes: Uint8Array,
    signature: Uint8Array,
  ): boolean | Promise<boolean>;
  verifyDomainSignature?(
    claim: ClaimReference,
    domain: DomainSeparator,
    hash: string,
    signature: Uint8Array,
  ): boolean | Promise<boolean>;
}

export interface CreatePrivateChannelOptions {
  identity: PrivateChannelIdentity;
  membership: MembershipManifest;
  transport: PrivateChannelTransport;
  mode: PrivateChannelMode;
}

type UnsignedEnvelope = Omit<PrivateChannelEnvelope, 'signature'>;
type UnknownRecord = Record<string, unknown>;

const ENVELOPE_VERSION = 'pathos-private-channel-envelope:1' as const;
const TRANSCRIPT_VERSION = 'pathos-private-channel-transcript:1' as const;
const KINDS: ReadonlySet<string> = new Set([
  'agent-message',
  'channel-close',
  'transcript-signature',
]);
const EMPTY = new Uint8Array();
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

ed25519.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...messages));

export class PrivateChannelManifestError extends Error {
  override readonly name = 'PrivateChannelManifestError';
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${label} must be canonical base64`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (bytesToBase64(bytes) !== value) throw new Error(`${label} must be canonical base64`);
  return bytes;
}

function exactKeys(value: UnknownRecord, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has an invalid schema`);
  }
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function parseMember(value: unknown, label: string): ChannelMember {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  exactKeys(value, ['seatId', 'claim'], label);
  return {
    seatId: requireString(value.seatId, `${label}.seatId`),
    claim: requireString(value.claim, `${label}.claim`) as ClaimReference,
  };
}

function normalizedDemosAddress(value: string): string {
  const hex = value.replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Private-channel CCI claim is invalid');
  return `0x${hex.toLowerCase()}`;
}

function publicKeyForClaim(claim: ClaimReference): Uint8Array {
  const colon = claim.indexOf(':');
  if (colon < 1 || claim.slice(0, colon) !== 'demos') throw new Error('Private-channel CCI claim is unsupported');
  return new Uint8Array(Buffer.from(normalizedDemosAddress(claim.slice(colon + 1)).slice(2), 'hex'));
}

function domainHashBytes(domain: DomainSeparator, hash: string, signing: boolean): Uint8Array {
  if (signing) assertEmittableSeparator(domain);
  else assertKnownSeparator(domain);
  return buildSignedBytes(domain, enc.encode(hash));
}

async function signDomainHash(
  identity: PrivateChannelIdentity,
  domain: DomainSeparator,
  hash: string,
): Promise<Uint8Array> {
  if (!identity.demos.walletConnected) throw new Error('Private-channel CCI wallet is not connected');
  const connected = normalizedDemosAddress(await identity.demos.getEd25519Address());
  const claimed = normalizedDemosAddress(identity.claim.slice(identity.claim.indexOf(':') + 1));
  if (!identity.claim.startsWith('demos:') || connected !== claimed) {
    throw new Error('Private-channel CCI claim does not match the connected wallet');
  }
  const signed = await identity.demos.crypto.sign('ed25519', domainHashBytes(domain, hash, true));
  return signed.signature instanceof Uint8Array ? signed.signature : Uint8Array.from(signed.signature);
}

function verifyDomainHash(
  claim: ClaimReference,
  domain: DomainSeparator,
  hash: string,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, domainHashBytes(domain, hash, false), publicKeyForClaim(claim));
  } catch {
    return false;
  }
}

function verifyMembershipSignature(claim: ClaimReference, bytes: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(
      signature,
      buildSignedBytes(DACS_X_EXTENSION_SEPARATORS.AGENT_IDENTITY, bytes),
      publicKeyForClaim(claim),
    );
  } catch {
    return false;
  }
}

function unsignedMembershipBinding(manifest: MembershipManifest, binding: ChannelMember): object {
  const unsigned: Record<string, unknown> = {
    v: manifest.v,
    coordinatorClaim: manifest.coordinatorClaim,
    seatId: binding.seatId,
    claim: binding.claim,
  };
  if (binding.peerId !== undefined) unsigned.peerId = binding.peerId;
  return unsigned;
}

/** Canonical membership bytes members sign through the CCI identity boundary. */
export function membershipBindingBytes(manifest: MembershipManifest, binding: ChannelMember): Uint8Array {
  return jcsCanonical(unsignedMembershipBinding(manifest, binding));
}

function assertFrozenManifest(manifest: MembershipManifest): void {
  if (!Object.isFrozen(manifest) || !Object.isFrozen(manifest.members)) {
    throw new Error('Private-channel membership manifest must be frozen');
  }
  if (manifest.v !== 'pathos-private-channel-membership:1') throw new Error('Unsupported membership manifest version');
  requireString(manifest.coordinatorClaim, 'Membership coordinatorClaim');
  if (manifest.members.length !== 2) throw new PrivateChannelManifestError('Private-channel membership requires exactly two members');
  const seats = new Set<string>();
  const claims = new Set<string>();
  const peerIds = new Set<string>();
  for (const member of manifest.members) {
    if (!Object.isFrozen(member)) throw new Error('Private-channel membership bindings must be frozen');
    requireString(member.seatId, 'Membership seatId');
    requireString(member.claim, 'Membership claim');
    if (member.peerId !== undefined) {
      requireString(member.peerId, 'Membership peerId');
      if (peerIds.has(member.peerId)) throw new Error('Membership peer identities must be unique');
      peerIds.add(member.peerId);
    }
    base64ToBytes(member.signature, 'Membership signature');
    if (seats.has(member.seatId) || claims.has(member.claim)) throw new Error('Membership seats and claims must be unique');
    seats.add(member.seatId);
    claims.add(member.claim);
  }
}

function memberKey(member: ChannelMember): string {
  return `${member.seatId}\u0000${member.claim}`;
}

function assertExactMembership(manifest: MembershipManifest, opened: readonly ChannelMember[]): void {
  if (opened.length !== manifest.members.length) throw new Error('Open membership does not equal the frozen manifest');
  const expected = new Set(manifest.members.map(memberKey));
  const actual = new Set(opened.map(memberKey));
  if (actual.size !== opened.length || expected.size !== actual.size || [...expected].some((key) => !actual.has(key))) {
    throw new Error('Open membership does not equal the frozen manifest');
  }
}

function findManifestMember(manifest: MembershipManifest, member: ChannelMember): MembershipBinding | undefined {
  return manifest.members.find((candidate) => candidate.seatId === member.seatId && candidate.claim === member.claim);
}

function envelopeHash(envelope: UnsignedEnvelope): string {
  return jcsHashHex(envelope);
}

function channelIdFor(nonce: Uint8Array, manifest: MembershipManifest): string {
  const manifestHash = Buffer.from(jcsHashHex(manifest), 'hex');
  const joined = new Uint8Array(nonce.length + manifestHash.length);
  joined.set(nonce);
  joined.set(manifestHash, nonce.length);
  return Buffer.from(sha256(joined)).toString('hex');
}

function parseEnvelope(frame: Uint8Array): PrivateChannelEnvelope {
  let raw: unknown;
  try {
    raw = JSON.parse(dec.decode(frame)) as unknown;
  } catch {
    throw new Error('Private-channel frame is not valid UTF-8 JSON');
  }
  if (!isRecord(raw)) throw new Error('Private-channel envelope must be an object');
  exactKeys(raw, ['v', 'channelId', 'kind', 'sender', 'sequence', 'payloadBase64', 'sentAt', 'signature'], 'Envelope');
  if (raw.v !== ENVELOPE_VERSION) throw new Error('Unsupported private-channel envelope version');
  const channelId = requireString(raw.channelId, 'Envelope channelId');
  if (typeof raw.kind !== 'string' || !KINDS.has(raw.kind)) throw new Error('Envelope kind is not allowed');
  const sender = parseMember(raw.sender, 'Envelope sender');
  if (!Number.isSafeInteger(raw.sequence) || (raw.sequence as number) < 1) throw new Error('Envelope sequence must be a positive safe integer');
  // Empty is legal: channel-close frames carry no payload (checked per kind below).
  if (typeof raw.payloadBase64 !== 'string') throw new Error('Envelope payloadBase64 must be a string');
  const payloadBase64 = raw.payloadBase64;
  base64ToBytes(payloadBase64, 'Envelope payloadBase64');
  const sentAt = requireString(raw.sentAt, 'Envelope sentAt');
  if (new Date(sentAt).toISOString() !== sentAt) throw new Error('Envelope sentAt must be a canonical ISO timestamp');
  const signature = requireString(raw.signature, 'Envelope signature');
  base64ToBytes(signature, 'Envelope signature');
  return {
    v: ENVELOPE_VERSION,
    channelId,
    kind: raw.kind as PrivateChannelContentKind,
    sender,
    sequence: raw.sequence as number,
    payloadBase64,
    sentAt,
    signature,
  };
}

function unsignedEnvelope(envelope: PrivateChannelEnvelope): UnsignedEnvelope {
  const { signature: _signature, ...unsigned } = envelope;
  return unsigned;
}

function envelopeOrder(a: PrivateChannelEnvelope, b: PrivateChannelEnvelope): number {
  return a.sequence - b.sequence
    || a.sender.claim.localeCompare(b.sender.claim)
    || a.sender.seatId.localeCompare(b.sender.seatId)
    || a.kind.localeCompare(b.kind);
}

function sortedEnvelopes(envelopes: readonly PrivateChannelEnvelope[]): PrivateChannelEnvelope[] {
  return [...envelopes].sort(envelopeOrder);
}

function countersFor(envelopes: readonly PrivateChannelEnvelope[]): ChannelCounter[] {
  const counters = new Map<ClaimReference, number>();
  for (const envelope of envelopes) counters.set(envelope.sender.claim, envelope.sequence);
  return [...counters].map(([claim, sequence]) => ({ claim, sequence }))
    .sort((a, b) => a.claim.localeCompare(b.claim));
}

function transcriptCommitment(transcript: ChannelTranscript): object {
  const committed = transcript.envelopes.filter((envelope) => envelope.kind !== 'transcript-signature');
  return {
    v: transcript.v,
    mode: transcript.mode,
    channelId: transcript.channelId,
    nonceBase64: transcript.nonceBase64,
    membership: transcript.membership,
    envelopes: committed,
    finalCounters: countersFor(committed),
  };
}

function defaultVerifier(): Required<ChannelTranscriptVerifier> {
  return {
    verifyMembershipSignature,
    verifyDomainSignature: (claim, domain, hash, signature) =>
      verifyDomainHash(claim, domain, hash, signature),
  };
}

function resolvedVerifier(verifier: ChannelTranscriptVerifier): Required<ChannelTranscriptVerifier> {
  const fallback = defaultVerifier();
  return {
    verifyMembershipSignature: verifier.verifyMembershipSignature ?? fallback.verifyMembershipSignature,
    verifyDomainSignature: verifier.verifyDomainSignature ?? fallback.verifyDomainSignature,
  };
}

async function verifyManifest(manifest: MembershipManifest, verifier: Required<ChannelTranscriptVerifier>): Promise<boolean> {
  try {
    assertFrozenManifest(manifest);
    for (const binding of manifest.members) {
      const valid = await verifier.verifyMembershipSignature(
        binding.claim,
        membershipBindingBytes(manifest, binding),
        base64ToBytes(binding.signature, 'Membership signature'),
      );
      if (!valid) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function frozenManifestCopy(manifest: MembershipManifest): MembershipManifest {
  const members = Object.freeze(manifest.members.map((member) => Object.freeze({ ...member })));
  return Object.freeze({ v: manifest.v, coordinatorClaim: manifest.coordinatorClaim, members });
}

function assertTransportBoundary(transport: PrivateChannelTransport, mode: PrivateChannelMode): void {
  if (transport.mode !== mode) throw new Error('Private-channel mode and transport mode differ');
  const required = ['open', 'send', 'receive', 'close'] as const;
  for (const method of required) {
    if (typeof transport[method] !== 'function') throw new Error('Private-channel transport is incomplete');
  }
  if (mode === 'l2ps-live') {
    const allowed = new Set<string>(required);
    let cursor: object | null = transport;
    while (cursor && cursor !== Object.prototype) {
      for (const name of Object.getOwnPropertyNames(cursor)) {
        if (name !== 'constructor'
          && typeof (transport as unknown as Record<string, unknown>)[name] === 'function'
          && !allowed.has(name)) {
          throw new Error('Live transport exposes capabilities outside the private-channel allowlist');
        }
      }
      cursor = Object.getPrototypeOf(cursor) as object | null;
    }
  }
}

export function createPrivateChannel(options: CreatePrivateChannelOptions): {
  open(members: readonly ChannelMember[]): Promise<void>;
  send(bytes: Uint8Array): Promise<void>;
  receive(): Promise<ReceivedMessage>;
  close(): Promise<void>;
  transcript(): ChannelTranscript;
} {
  assertFrozenManifest(options.membership);
  assertTransportBoundary(options.transport, options.mode);
  const membership = frozenManifestCopy(options.membership);
  const own = membership.members.find((member) => member.claim === options.identity.claim);
  let state: 'new' | 'open' | 'closing' | 'closed' | 'fatal' = 'new';
  let channelId = '';
  let nonce: Uint8Array = EMPTY;
  let sendSequence = 0;
  const accepted = new Map<ClaimReference, number>();
  const envelopes: PrivateChannelEnvelope[] = [];
  const closingSignatures: ClosingSignature[] = [];
  let sendTail: Promise<unknown> = Promise.resolve();
  const drainedMessages: ReceivedMessage[] = [];
  const drainWaiters: Array<{
    resolve: (message: ReceivedMessage) => void;
    reject: (error: Error) => void;
  }> = [];

  function snapshot(): ChannelTranscript {
    return {
      v: TRANSCRIPT_VERSION,
      mode: options.mode,
      channelId,
      nonceBase64: bytesToBase64(nonce),
      membership,
      envelopes: sortedEnvelopes(envelopes).map((envelope) => ({ ...envelope, sender: { ...envelope.sender } })),
      finalCounters: countersFor(envelopes),
      closingSignatures: closingSignatures.map((signature) => ({ ...signature, sender: { ...signature.sender } })),
    };
  }

  async function emitNow(kind: PrivateChannelContentKind, payload: Uint8Array): Promise<PrivateChannelEnvelope> {
    if (!own) throw new Error('Channel identity does not own a membership seat');
    const nextSequence = sendSequence + 1;
    const unsigned: UnsignedEnvelope = {
      v: ENVELOPE_VERSION,
      channelId,
      kind,
      sender: { seatId: own.seatId, claim: own.claim },
      sequence: nextSequence,
      payloadBase64: bytesToBase64(payload),
      sentAt: new Date().toISOString(),
    };
    try {
      const signature = await signDomainHash(
        options.identity,
        REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
        envelopeHash(unsigned),
      );
      const envelope = { ...unsigned, signature: bytesToBase64(signature) };
      await options.transport.send(jcsCanonical(envelope));
      sendSequence = nextSequence;
      envelopes.push(envelope);
      accepted.set(envelope.sender.claim, envelope.sequence);
      return envelope;
    } catch (error) {
      state = 'fatal';
      throw error;
    }
  }

  function emit(kind: PrivateChannelContentKind, payload: Uint8Array): Promise<PrivateChannelEnvelope> {
    const operation = sendTail.then(() => emitNow(kind, payload));
    sendTail = operation;
    return operation;
  }

  async function accept(expectedKind?: PrivateChannelContentKind): Promise<PrivateChannelEnvelope> {
    try {
      const envelope = parseEnvelope(await options.transport.receive());
      if (envelope.channelId !== channelId) throw new Error('Envelope channelId does not match this channel');
      const listed = findManifestMember(membership, envelope.sender);
      if (!listed) throw new Error('Envelope sender is not a listed seat and claim');
      const signatureValid = verifyDomainHash(
        envelope.sender.claim,
        REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
        envelopeHash(unsignedEnvelope(envelope)),
        base64ToBytes(envelope.signature, 'Envelope signature'),
      );
      if (!signatureValid) throw new Error('Envelope CCI signature is invalid');
      const expectedSequence = (accepted.get(envelope.sender.claim) ?? 0) + 1;
      if (envelope.sequence !== expectedSequence) {
        throw new Error(envelope.sequence < expectedSequence
          ? 'Duplicate private-channel sequence is fatal'
          : 'Private-channel sequence gap is fatal');
      }
      if (expectedKind && envelope.kind !== expectedKind) throw new Error(`Expected ${expectedKind} control envelope`);
      if (envelope.kind === 'channel-close' && envelope.payloadBase64 !== '') throw new Error('Channel-close payload must be empty');
      accepted.set(envelope.sender.claim, envelope.sequence);
      envelopes.push(envelope);
      return envelope;
    } catch (error) {
      state = 'fatal';
      throw error;
    }
  }

  function receivedMessage(envelope: PrivateChannelEnvelope): ReceivedMessage {
    return {
      bytes: base64ToBytes(envelope.payloadBase64, 'Envelope payloadBase64'),
      sender: { ...envelope.sender },
      sequence: envelope.sequence,
      sentAt: envelope.sentAt,
    };
  }

  function drain(envelope: PrivateChannelEnvelope): void {
    const message = receivedMessage(envelope);
    const waiter = drainWaiters.shift();
    if (waiter) waiter.resolve(message);
    else drainedMessages.push(message);
  }

  function endDrain(error: Error): void {
    for (const waiter of drainWaiters.splice(0)) waiter.reject(error);
  }

  return {
    async open(members): Promise<void> {
      if (state !== 'new') throw new Error('Private channel has already been opened');
      if (options.mode === 'l2ps-live' && process.env.PATHOS_L2PS_LIVE !== '1') {
        throw new Error('Live private channels require PATHOS_L2PS_LIVE=1');
      }
      assertExactMembership(membership, members);
      if (!own) throw new Error('Channel identity does not own a membership seat');
      if (!await verifyManifest(membership, defaultVerifier())) throw new Error('Membership CCI signature verification failed');
      const proposed = freshPrivateChannelNonce();
      const peer = membership.members.find((member) => member.claim !== own.claim)!;
      nonce = await options.transport.open({
        manifestHash: jcsHashHex(membership),
        nonce: proposed,
        sender: { seatId: own.seatId, claim: own.claim, peerId: own.peerId },
        peer: { seatId: peer.seatId, claim: peer.claim, peerId: peer.peerId },
        signEnvelopeHash: (hash) => signDomainHash(
          options.identity,
          REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
          hash,
        ),
        verifyEnvelopeHash: (claim, hash, signature) => verifyDomainHash(
          claim as ClaimReference,
          REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
          hash,
          signature,
        ),
      });
      if (nonce.length < 16) throw new Error('Private-channel nonce is too short');
      channelId = channelIdFor(nonce, membership);
      state = 'open';
    },

    async send(bytes): Promise<void> {
      if (state !== 'open') throw new Error('Private channel is not open');
      if (!(bytes instanceof Uint8Array)) throw new Error('Private-channel payload must be bytes');
      await emit('agent-message', bytes.slice());
    },

    async receive(): Promise<ReceivedMessage> {
      const buffered = drainedMessages.shift();
      if (buffered) return buffered;
      if (state === 'closing') {
        return new Promise((resolve, reject) => drainWaiters.push({ resolve, reject }));
      }
      if (state !== 'open') throw new Error('Private channel is not open');
      const envelope = await accept('agent-message');
      return receivedMessage(envelope);
    },

    async close(): Promise<void> {
      if (state !== 'open') throw new Error('Private channel is not open');
      state = 'closing';
      try {
        await emit('channel-close', EMPTY);
        for (;;) {
          const envelope = await accept();
          if (envelope.kind === 'agent-message') {
            drain(envelope);
            continue;
          }
          if (envelope.kind !== 'channel-close') {
            throw new Error('Expected channel-close control envelope');
          }
          break;
        }
        const beforeClosingSignature = snapshot();
        const transcriptHash = jcsHashHex(transcriptCommitment(beforeClosingSignature));
        const signatureBytes = await signDomainHash(
          options.identity,
          DACS_X_EXTENSION_SEPARATORS.SESSION_RECORD,
          transcriptHash,
        );
        const localSignature: ClosingSignature = {
          sender: { seatId: own!.seatId, claim: own!.claim },
          transcriptHash,
          signature: bytesToBase64(signatureBytes),
        };
        closingSignatures.push(localSignature);
        await emit('transcript-signature', jcsCanonical(localSignature));
        const peerEnvelope = await accept('transcript-signature');
        let peerSignature: unknown;
        try {
          peerSignature = JSON.parse(dec.decode(base64ToBytes(peerEnvelope.payloadBase64, 'Transcript-signature payload')));
        } catch {
          throw new Error('Transcript-signature payload is invalid');
        }
        if (!isRecord(peerSignature)) throw new Error('Transcript-signature payload is invalid');
        exactKeys(peerSignature, ['sender', 'transcriptHash', 'signature'], 'Closing signature');
        const parsed: ClosingSignature = {
          sender: parseMember(peerSignature.sender, 'Closing signature sender'),
          transcriptHash: requireString(peerSignature.transcriptHash, 'Closing signature transcriptHash'),
          signature: requireString(peerSignature.signature, 'Closing signature signature'),
        };
        if (memberKey(parsed.sender) !== memberKey(peerEnvelope.sender) || parsed.transcriptHash !== transcriptHash) {
          throw new Error('Closing signature does not commit to this transcript');
        }
        if (!verifyDomainHash(
          parsed.sender.claim,
          DACS_X_EXTENSION_SEPARATORS.SESSION_RECORD,
          transcriptHash,
          base64ToBytes(parsed.signature, 'Closing signature'),
        )) {
          throw new Error('Closing transcript signature is invalid');
        }
        closingSignatures.push(parsed);
        closingSignatures.sort((a, b) => a.sender.claim.localeCompare(b.sender.claim));
        state = 'closed';
        endDrain(new Error('Private channel is closed'));
        await options.transport.close();
      } catch (error) {
        state = 'fatal';
        const fatal = error instanceof Error ? error : new Error('Private-channel close failed');
        endDrain(fatal);
        throw fatal;
      }
    },

    transcript: snapshot,
  };
}

/** Cold verification: no transport, SDK live state, or mutable channel state is consulted. */
export async function verifyChannelTranscript(
  transcript: ChannelTranscript,
  verifier: ChannelTranscriptVerifier = {},
): Promise<boolean> {
  try {
    if (!isRecord(transcript) || transcript.v !== TRANSCRIPT_VERSION) return false;
    exactKeys(transcript as unknown as UnknownRecord,
      ['v', 'mode', 'channelId', 'nonceBase64', 'membership', 'envelopes', 'finalCounters', 'closingSignatures'],
      'Transcript');
    if (transcript.mode !== 'local' && transcript.mode !== 'l2ps-live') return false;
    const nonce = base64ToBytes(transcript.nonceBase64, 'Transcript nonce');
    if (nonce.length < 16 || channelIdFor(nonce, transcript.membership) !== transcript.channelId) return false;
    const frozen = frozenManifestCopy(transcript.membership);
    const checks = resolvedVerifier(verifier);
    if (!await verifyManifest(frozen, checks)) return false;
    if (!Array.isArray(transcript.envelopes) || transcript.envelopes.length === 0) return false;
    const reparsed = transcript.envelopes.map((envelope) => parseEnvelope(jcsCanonical(envelope)));
    const canonicalOrder = sortedEnvelopes(reparsed);
    if (jcsHashHex(reparsed) !== jcsHashHex(canonicalOrder)) return false;
    const counters = new Map<ClaimReference, number>();
    const stages = new Map<ClaimReference, 'messages' | 'closed' | 'signed'>();
    const closeClaims = new Set<ClaimReference>();
    const signaturePayloads: ClosingSignature[] = [];
    for (const envelope of reparsed) {
      if (envelope.channelId !== transcript.channelId || !findManifestMember(frozen, envelope.sender)) return false;
      const expected = (counters.get(envelope.sender.claim) ?? 0) + 1;
      if (envelope.sequence !== expected) return false;
      const valid = await checks.verifyDomainSignature(
        envelope.sender.claim,
        REVIEWED_DACS_X_EXTENSION_SEPARATORS.CHANNEL_ENVELOPE,
        envelopeHash(unsignedEnvelope(envelope)),
        base64ToBytes(envelope.signature, 'Envelope signature'),
      );
      if (!valid) return false;
      counters.set(envelope.sender.claim, envelope.sequence);
      const stage = stages.get(envelope.sender.claim) ?? 'messages';
      if (envelope.kind === 'agent-message') {
        if (stage !== 'messages') return false;
      } else if (envelope.kind === 'channel-close') {
        if (stage !== 'messages' || envelope.payloadBase64 !== '') return false;
        stages.set(envelope.sender.claim, 'closed');
        closeClaims.add(envelope.sender.claim);
      } else {
        if (stage !== 'closed') return false;
        stages.set(envelope.sender.claim, 'signed');
      }
      if (envelope.kind === 'transcript-signature') {
        const parsed = JSON.parse(dec.decode(base64ToBytes(envelope.payloadBase64, 'Transcript-signature payload'))) as unknown;
        if (!isRecord(parsed)) return false;
        exactKeys(parsed, ['sender', 'transcriptHash', 'signature'], 'Closing signature');
        const closing: ClosingSignature = {
          sender: parseMember(parsed.sender, 'Closing signature sender'),
          transcriptHash: requireString(parsed.transcriptHash, 'Closing signature transcriptHash'),
          signature: requireString(parsed.signature, 'Closing signature signature'),
        };
        if (memberKey(closing.sender) !== memberKey(envelope.sender)) return false;
        signaturePayloads.push(closing);
      }
    }
    if (jcsHashHex(transcript.finalCounters) !== jcsHashHex(countersFor(reparsed))) return false;
    const commitmentHash = jcsHashHex(transcriptCommitment({ ...transcript, membership: frozen, envelopes: reparsed }));
    if (signaturePayloads.length !== frozen.members.length
      || transcript.closingSignatures.length !== signaturePayloads.length
      || closeClaims.size !== frozen.members.length
      || [...stages.values()].some((stage) => stage !== 'signed')) return false;
    const orderedSignatures = [...transcript.closingSignatures].sort((a, b) => a.sender.claim.localeCompare(b.sender.claim));
    if (jcsHashHex(transcript.closingSignatures) !== jcsHashHex(orderedSignatures)
      || jcsHashHex(signaturePayloads.sort((a, b) => a.sender.claim.localeCompare(b.sender.claim))) !== jcsHashHex(orderedSignatures)) return false;
    for (const closing of orderedSignatures) {
      if (closing.transcriptHash !== commitmentHash || !findManifestMember(frozen, closing.sender)) return false;
      if (!await checks.verifyDomainSignature(
        closing.sender.claim,
        DACS_X_EXTENSION_SEPARATORS.SESSION_RECORD,
        commitmentHash,
        base64ToBytes(closing.signature, 'Closing signature'),
      )) return false;
    }
    return true;
  } catch {
    return false;
  }
}
