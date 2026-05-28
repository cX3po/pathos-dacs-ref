/**
 * Demos SDK connection helper
 *
 * Thin wrapper over @kynesyslabs/demosdk/websdk that hides the connect/connectWallet
 * dance and surfaces a typed handle the rest of the codebase uses.
 *
 * Spec context: this module IS the substrate dependency surface (SR-1, SR-2 backing).
 * Keeping it in one file means the rest of the codebase doesn't import the SDK directly,
 * which makes swapping substrates (per DACS §11.3 second-substrate goal) tractable.
 */

import { Demos } from '@kynesyslabs/demosdk/websdk';

export interface DemosHandle {
  /** Connected Demos instance — pass to DemosTransactions.* statics */
  demos: Demos;
  /** The wallet's 0x-prefixed hex address (CCI key) */
  address: string;
  /** The RPC endpoint actually connected to */
  rpc: string;
}

const DEFAULT_RPC = 'https://demosnode.discus.sh/';

/**
 * Connect to a Demos node and unlock a wallet from mnemonic.
 *
 * @param mnemonic 12-word BIP-39 mnemonic
 * @param rpc Demos node URL (defaults to demosnode.discus.sh)
 * @throws If mnemonic is empty, malformed, or RPC unreachable
 */
export async function connectDemos(mnemonic: string, rpc: string = DEFAULT_RPC): Promise<DemosHandle> {
  if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
    throw new Error('mnemonic must be a 12-word BIP-39 phrase');
  }
  const demos = new Demos();
  await demos.connect(rpc);
  await demos.connectWallet(mnemonic.trim());
  const address = demos.getAddress();
  if (!address) {
    throw new Error('Demos.getAddress() returned empty after connectWallet');
  }
  return { demos, address, rpc };
}

/** Generate a fresh 12-word mnemonic (for first-run wallet creation). */
export function newMnemonic(): string {
  const demos = new Demos();
  return demos.newMnemonic(128);
}

/** Load mnemonic from an environment variable. Throws if absent. */
export function mnemonicFromEnv(envVarName: string): string {
  const m = process.env[envVarName];
  if (!m) {
    throw new Error(`Environment variable ${envVarName} is not set`);
  }
  return m;
}
