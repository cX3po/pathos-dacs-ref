/**
 * DACS §8.3.3 / CH-6 — channel-message replay defence (matrix #14). GAP vector.
 *
 * The cross-session / in-channel offer-replay defence: a `ChannelMessage` is signed over
 * `"dacs-channelmsg:v1:" || sha256(JCS(envelope−signature))`, carries a per-session-unique `channelId`
 * (CH-6) and a per-channel monotonic `sequence` (starts at 1, §8.3.3). A consumer admits a message only if:
 *   • the session's `channelId` was NOT reused from a prior session (CH-6) — else the whole session is rejected;
 *   • the message's `channelId` equals the session channelId (a foreign-channel message → excluded);
 *   • the signature verifies against the sender's key (self-describing `cci:<hex>`); and
 *   • `sequence` is strictly greater than the highest already seen in this channel (a duplicate / decrease is replay).
 * A cross-session replay fails BOTH ways: keep the old channelId → channel mismatch; rewrite it → the signature
 * (computed over the original channelId) breaks.
 *
 * Decision (§7.5.1, never collapsed): pass (admit) · fail (CH-6 reuse / foreign channel / bad sig / replayed
 * sequence) · indeterminate (sender key unresolvable) · error (malformed). `dacs-channelmsg:v1:` is the spec's separator.
 * Pure, offline, deterministic, dep-free.
 */
import { createPublicKey, createPrivateKey, sign as nodeSign, verify as nodeVerify, createHash } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const MSG_SEP = 'dacs-channelmsg:v1:';
const CCI = /^cci:(?:0x)?([0-9a-fA-F]{64})$/;
const isHex = (s: unknown, b: number): s is string => typeof s === 'string' && new RegExp(`^[0-9a-fA-F]{${b * 2}}$`).test(s);

export function privKeyObj(seedHex: string) { return createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' }); }
function pubKeyObj(rawHex: string) { return createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawHex, 'hex')]), format: 'der', type: 'spki' }); }
export function pubRawFromSeed(seedHex: string): string { const der = createPublicKey(privKeyObj(seedHex)).export({ format: 'der', type: 'spki' }); return Buffer.from(der.subarray(der.length - 32)).toString('hex'); }
export function edSign(msg: Buffer, seedHex: string): string { return nodeSign(null, msg, privKeyObj(seedHex)).toString('hex'); }
function edVerify(msg: Buffer, sigHex: string, pubHex: string): boolean { if (!isHex(sigHex, 64) || !isHex(pubHex, 32)) return false; try { return nodeVerify(null, msg, pubKeyObj(pubHex), Buffer.from(sigHex, 'hex')); } catch { return false; } }

/** Minimal injective canonical JSON (sorted keys) over JSON values; throws on non-JSON. */
export function canon(v: unknown): string {
  if (v === undefined || typeof v === 'function' || typeof v === 'symbol') throw new Error('canon: non-JSON');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canon: non-finite');
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) if (!(i in v)) throw new Error('canon: sparse'); return `[${v.map(canon).join(',')}]`; }
  const proto = Object.getPrototypeOf(v); if (proto !== Object.prototype && proto !== null) throw new Error('canon: non-plain');
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`;
}

export interface ChannelMessage { channelId: string; sequence: number; sender: string; sentAt: number; type: string; body: unknown; refs?: unknown; signature: string }
export interface ChannelCtx { sessionChannelId: string; lastSequence: number; priorChannelIds: string[] }
export interface Check { id: string; ok: boolean | null; detail: string }
export interface MsgVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

/** envelope_hash = sha256(JCS(message − signature)); signed_bytes = "dacs-channelmsg:v1:" || envelope_hash. */
export function channelSignedBytes(m: ChannelMessage): Buffer {
  const { signature: _omit, ...env } = m; void _omit;
  const envHash = createHash('sha256').update(Buffer.from(canon(env), 'utf8')).digest();
  return Buffer.concat([Buffer.from(MSG_SEP, 'utf8'), envHash]);
}
function senderKey(claim: string): string | null { const m = typeof claim === 'string' ? CCI.exec(claim) : null; return m ? m[1]!.toLowerCase() : null; }

export function checkChannelMessage(msg: ChannelMessage, ctx: ChannelCtx): MsgVerdict {
  const checks: Check[] = [];
  const out = (d: MsgVerdict['decision']): MsgVerdict => ({ decision: d, checks });
  // [0] structural
  if (!msg || typeof msg !== 'object' || typeof msg.channelId !== 'string' || typeof msg.sequence !== 'number' ||
      !Number.isInteger(msg.sequence) || typeof msg.sender !== 'string' || typeof msg.signature !== 'string' ||
      !ctx || typeof ctx.sessionChannelId !== 'string' || typeof ctx.lastSequence !== 'number' ||
      !Number.isInteger(ctx.lastSequence) || ctx.lastSequence < 0 ||
      !Array.isArray(ctx.priorChannelIds) || !ctx.priorChannelIds.every((c) => typeof c === 'string')) {
    checks.push({ id: 'structural', ok: false, detail: 'malformed channel message / ctx (ctx.lastSequence must be a non-negative integer; priorChannelIds must be strings)' }); return out('error');
  }
  if (msg.sequence < 1) { checks.push({ id: 'sequence-min', ok: false, detail: 'sequence < 1 (must start at 1, §8.3.3)' }); return out('error'); }
  // [0b] the envelope MUST be canonicalisable (JCS) — a non-JSON / non-injective body is a malformed artifact,
  // not a signature failure. Compute the signed scope up front so a canon throw maps to `error`, never `fail`.
  let signedBytes: Buffer;
  try { signedBytes = channelSignedBytes(msg); }
  catch (e) { checks.push({ id: 'envelope-canon', ok: false, detail: `envelope not canonicalisable (${(e as Error).message}) — malformed artifact` }); return out('error'); }
  checks.push({ id: 'structural', ok: true, detail: 'well-formed' });

  // [1] CH-6 — the session's channelId MUST NOT be one reused from a prior session
  if (ctx.priorChannelIds.includes(ctx.sessionChannelId)) {
    checks.push({ id: 'ch-6', ok: false, detail: 'session channelId reused from a prior session — session rejected (CH-6)' }); return out('fail');
  }
  // [2] channel binding — the message MUST belong to this session's channel
  if (msg.channelId !== ctx.sessionChannelId) {
    checks.push({ id: 'channel-binding', ok: false, detail: 'message channelId ≠ session channelId — foreign-channel message (cross-session replay)' }); return out('fail');
  }
  // [3] signature over the §8.3.3 signed scope, by the sender's self-describing key
  const key = senderKey(msg.sender);
  if (key == null) { checks.push({ id: 'sender-key', ok: null, detail: 'sender claim is not a resolvable cci key — cannot verify signature' }); return out('indeterminate'); }
  let sigOk = false;
  try { sigOk = edVerify(signedBytes, msg.signature, key); } catch { sigOk = false; }
  checks.push({ id: 'signature', ok: sigOk, detail: sigOk ? 'signature valid over dacs-channelmsg:v1: || envelope_hash' : 'signature invalid (tampered / re-channelled / wrong key)' });
  if (!sigOk) return out('fail');
  // [4] monotonic sequence — strictly greater than the highest already seen in this channel
  if (msg.sequence <= ctx.lastSequence) {
    checks.push({ id: 'monotonic-sequence', ok: false, detail: `sequence ${msg.sequence} ≤ last-seen ${ctx.lastSequence} — duplicate/replayed/out-of-order` }); return out('fail');
  }
  checks.push({ id: 'monotonic-sequence', ok: true, detail: `sequence ${msg.sequence} > last-seen ${ctx.lastSequence}` });
  return out('pass');
}
