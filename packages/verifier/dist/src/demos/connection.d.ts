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
/**
 * Connect to a Demos node and unlock a wallet from mnemonic.
 *
 * @param mnemonic 12-word BIP-39 mnemonic
 * @param rpc Demos node URL (defaults to demosnode.discus.sh)
 * @throws If mnemonic is empty, malformed, or RPC unreachable
 */
export declare function connectDemos(mnemonic: string, rpc?: string): Promise<DemosHandle>;
/** Generate a fresh 12-word mnemonic (for first-run wallet creation). */
export declare function newMnemonic(): string;
/** Load mnemonic from an environment variable. Throws if absent. */
export declare function mnemonicFromEnv(envVarName: string, env?: Readonly<Record<string, string | undefined>>): string;
