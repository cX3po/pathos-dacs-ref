/**
 * Typed CCI identity boundary for configured DACS agents.
 *
 * This is the only importer of @kynesyslabs/demosdk/identity. Callers must use
 * the types and functions exported here rather than depending on SDK CCI types.
 * The boundary is testnet-only and never accepts inline secret material.
 *
 * Blast radius: new agent config, adapter tests, and CLI files; two edits to
 * existing modules (an optional env parameter on mnemonicFromEnv with its
 * default unchanged, and one added DACS_X_EXTENSION_SEPARATORS key). The first
 * caller is src/cli/dacs-agents.ts. Existing entry points have no runtime
 * behaviour changes.
 */

import { readFileSync } from 'node:fs';
import { cci } from '@kynesyslabs/demosdk/identity';
import {
  connectDemos,
  mnemonicFromEnv,
  type DemosHandle,
} from '../../demos/connection.js';
import {
  assertEmittableSeparator,
  assertKnownSeparator,
  buildSignedBytes,
  DACS_X_EXTENSION_SEPARATORS,
  type DomainSeparator,
} from '../../domain-sep.js';

export type AgentRole = 'buyer-reviewer' | 'seller';
export type ClaimReference = `${string}:${string}`;

export interface ParsedClaim {
  scheme: string;
  identifier: string;
}

export interface AgentIdentityConfig {
  role: AgentRole;
  mnemonicEnv: string;
  claimRef: ClaimReference | null;
  notes: string;
}

export interface AgentsConfig {
  schemaVersion: 1;
  network: 'testnet';
  rpc: string;
  agents: Record<string, AgentIdentityConfig>;
}

export interface ResolvedAgent {
  name: string;
  role: AgentRole;
  mnemonicEnv: string;
  hasSecret: boolean;
}

export interface UnlockedAgent extends DemosHandle {
  name: string;
  role: AgentRole;
  mnemonicEnv: string;
  claim: ClaimReference;
}

export interface UnlockAgentDependencies {
  connect: (mnemonic: string, rpc: string) => Promise<DemosHandle>;
}

type Environment = Readonly<Record<string, string | undefined>>;
type UnknownRecord = Record<string, unknown>;

const ENV_NAME = /^[A-Z][A-Z0-9_]+$/;

export const TESTNET_RPC_HOSTS = ['demosnode.discus.sh'] as const;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isInlineSecretField(field: string): boolean {
  const normalized = field.replace(/[_-]/g, '').toLowerCase();
  return normalized === 'mnemonic' || normalized === 'seed' || normalized === 'privatekey';
}

function looksLikeSeedWords(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const words = value.trim().split(/\s+/);
  return words.length >= 12 && words.every((word) => /^[a-z]+$/i.test(word));
}

function rejectInlineSecrets(agentName: string, value: unknown, fieldPath = ''): void {
  if (looksLikeSeedWords(value)) {
    throw new Error(`Agent "${agentName}" contains forbidden inline secret field "${fieldPath || '(root)'}"`);
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectInlineSecrets(agentName, item, `${fieldPath}[${index}]`));
    return;
  }
  if (!isRecord(value)) return;

  for (const [field, child] of Object.entries(value)) {
    const path = fieldPath ? `${fieldPath}.${field}` : field;
    if (isInlineSecretField(field)) {
      throw new Error(`Agent "${agentName}" contains forbidden inline secret field "${path}"`);
    }
    rejectInlineSecrets(agentName, child, path);
  }
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function parseAgent(name: string, raw: unknown): AgentIdentityConfig {
  if (!isRecord(raw)) throw new Error(`Agent "${name}" must be an object`);
  rejectInlineSecrets(name, raw);

  const role = raw.role;
  if (role !== 'buyer-reviewer' && role !== 'seller') {
    throw new Error(`Agent "${name}" has an unsupported role`);
  }
  const mnemonicEnv = requireString(raw.mnemonicEnv, `Agent "${name}" mnemonicEnv`);
  if (!ENV_NAME.test(mnemonicEnv)) {
    throw new Error(`Agent "${name}" mnemonicEnv must be an upper-snake environment variable name`);
  }

  const rawClaim = raw.claimRef;
  if (rawClaim !== null && typeof rawClaim !== 'string') {
    throw new Error(`Agent "${name}" claimRef must be a string or null`);
  }
  let claimRef: ClaimReference | null = null;
  if (rawClaim !== null) {
    try {
      claimRef = claimRefFor(cci.demosAddressFromClaim(rawClaim as ClaimReference));
    } catch {
      throw new Error(`Agent "${name}" claimRef is not a valid demos claim`);
    }
  }

  return {
    role,
    mnemonicEnv,
    claimRef,
    notes: requireString(raw.notes, `Agent "${name}" notes`),
  };
}

export function loadAgentsConfig(path: string): AgentsConfig {
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!isRecord(raw)) throw new Error('Agents config must be an object');
  if (raw.schemaVersion !== 1) throw new Error('Agents config schemaVersion must be 1');
  if (raw.network !== 'testnet') throw new Error('Agents config network must be "testnet"');
  const rpc = requireString(raw.rpc, 'Agents config rpc');
  let rpcHostname: string;
  try {
    rpcHostname = new URL(rpc).hostname;
  } catch {
    throw new Error('Agents config rpc must use a sanctioned testnet RPC host');
  }
  if (!(TESTNET_RPC_HOSTS as readonly string[]).includes(rpcHostname)) {
    throw new Error(`Agents config rpc host "${rpcHostname}" is not a sanctioned testnet RPC host`);
  }
  // Scan the document root with the agents subtree excluded: each agent is scanned by
  // parseAgent under its own name, so an agent-level finding names the agent, not the file.
  const { agents: rawAgents, ...rootWithoutAgents } = raw;
  rejectInlineSecrets('(config)', rootWithoutAgents);
  if (!isRecord(rawAgents)) throw new Error('Agents config agents must be an object');

  const agents: Record<string, AgentIdentityConfig> = {};
  for (const [name, agent] of Object.entries(rawAgents)) {
    agents[name] = parseAgent(name, agent);
  }
  return { schemaVersion: 1, network: 'testnet', rpc, agents };
}

export function claimRefFor(address: string): ClaimReference {
  return cci.demosClaimRefForAddress(address) as ClaimReference;
}

const PUBKEY_HEX = /^[0-9a-f]{64}$/;

/** Claim forms of one controlling key. A Demos address is the lowercase hex of the wallet's ed25519 public
 *  key. This repository's verifiers resolve public keys from `cci:<pubkey>` party claims; the DACS-1 v0.1
 *  registry accepts `key:` (not `cci:`, not `demos:`) for listing addresses; the SDK's CCI boundary signs and
 *  verifies only `demos:`. The helpers below move between those forms without changing the key. */
export function pubkeyHexOfAddress(address: string): string {
  const hex = address.startsWith('0x') ? address.slice(2) : address;
  if (!PUBKEY_HEX.test(hex)) throw new Error('Demos address is not a lowercase 64-hex ed25519 public key');
  return hex;
}

export function cciClaimForAddress(address: string): ClaimReference {
  return `cci:${pubkeyHexOfAddress(address)}` as ClaimReference;
}

export function keyClaimForAddress(address: string): ClaimReference {
  return `key:${pubkeyHexOfAddress(address)}` as ClaimReference;
}

/** Map a `cci:<pubkey>` or `key:<pubkey>` claim to the `demos:0x<pubkey>` claim the CCI signer and verifier accept; `demos:` passes through. */
export function demosClaimForPubkeyClaim(claim: ClaimReference | string): ClaimReference {
  const text = String(claim);
  if (text.startsWith('demos:')) return text as ClaimReference;
  const m = /^(cci|key):(?:0x)?([0-9a-f]{64})$/.exec(text);
  if (!m) throw new Error('only cci:<64-hex public key> or key:<64-hex public key> claims map to a Demos claim');
  return `demos:0x${m[2]}` as ClaimReference;
}

/** The DACS-1 listing address takes the registered `key:` form of the same public key that the party claims carry as `cci:`. */
export function keyClaimForPubkeyClaim(claim: ClaimReference | string): ClaimReference {
  const text = String(claim);
  const m = /^(cci|key|demos):(?:0x)?([0-9a-f]{64})$/.exec(text);
  if (!m) throw new Error('only cci:/key:/demos: claims over a 64-hex public key map to a key: claim');
  return `key:${m[2]}` as ClaimReference;
}

export function parseClaim(ref: ClaimReference | string): ParsedClaim {
  const parsed = cci.parseClaimRef(ref as ClaimReference);
  return { scheme: parsed.scheme, identifier: parsed.identifier };
}

function configuredAgent(config: AgentsConfig, name: string): AgentIdentityConfig {
  const agent = config.agents[name];
  if (!agent) throw new Error(`Unknown agent "${name}"`);
  return agent;
}

export function resolveAgent(
  config: AgentsConfig,
  name: string,
  env: Environment = process.env,
): ResolvedAgent {
  const agent = configuredAgent(config, name);
  return {
    name,
    role: agent.role,
    mnemonicEnv: agent.mnemonicEnv,
    hasSecret: Boolean(env[agent.mnemonicEnv]),
  };
}

export async function unlockAgent(
  config: AgentsConfig,
  name: string,
  env: Environment = process.env,
  deps: UnlockAgentDependencies = { connect: connectDemos },
): Promise<UnlockedAgent> {
  const agent = configuredAgent(config, name);
  // Keep the credential local to this network-requiring operation.
  const mnemonic = mnemonicFromEnv(agent.mnemonicEnv, env);
  const connected = await deps.connect(mnemonic, config.rpc);
  const derived = claimRefFor(connected.address);
  // Fail closed: a configured claim that is not this wallet's claim would let a caller sign
  // under one identity with another wallet's key. Error names the agent, never the values.
  if (agent.claimRef !== null && agent.claimRef !== derived) {
    throw new Error(`Agent "${name}" configured claimRef does not match the unlocked wallet`);
  }
  return { ...connected, name, role: agent.role, mnemonicEnv: agent.mnemonicEnv, claim: derived };
}

function identitySigningBytes(payload: Uint8Array): Uint8Array {
  assertEmittableSeparator(DACS_X_EXTENSION_SEPARATORS.AGENT_IDENTITY);
  return buildSignedBytes(DACS_X_EXTENSION_SEPARATORS.AGENT_IDENTITY, payload);
}

export function signAsAgent(handle: UnlockedAgent, payload: Uint8Array): Promise<Uint8Array> {
  return cci.signWithPrimaryClaim(handle.claim, identitySigningBytes(payload), handle.demos);
}

export function verifyAgentSignature(
  claim: ClaimReference,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  return cci.verifyPrimaryClaimSignature(claim, identitySigningBytes(payload), signature);
}

/** Sign the adapter-wide `domain || UTF8(hex-hash)` contract through the CCI boundary. */
export function signDomainHashAsAgent(
  handle: UnlockedAgent,
  domain: DomainSeparator,
  hash: string,
): Promise<Uint8Array> {
  assertEmittableSeparator(domain);
  return cci.signWithPrimaryClaim(
    handle.claim,
    buildSignedBytes(domain, new TextEncoder().encode(hash)),
    handle.demos,
  );
}

/** Verify the adapter-wide `domain || UTF8(hex-hash)` contract through CCI. */
export function verifyDomainHashAgentSignature(
  claim: ClaimReference,
  domain: DomainSeparator,
  hash: string,
  signature: Uint8Array,
): boolean {
  assertKnownSeparator(domain);
  // `cci:`/`key:` claims carry the same public key as the wallet's `demos:` claim; the CCI verifier only speaks `demos:`.
  const text = String(claim);
  return cci.verifyPrimaryClaimSignature(
    text.startsWith('cci:') || text.startsWith('key:') ? demosClaimForPubkeyClaim(claim) : claim,
    buildSignedBytes(domain, new TextEncoder().encode(hash)),
    signature,
  );
}
