import type { PayDemJournalLease } from './pay-dem-journal.js';
import type { PayPolicy, TransferAuthorization } from './pay-policy.js';
import { authorizeTransfer, spentTodayFromJournal, utcDateOrThrow } from './pay-policy.js';

export interface PayDemOutcome {
  timestamp: string;
  amountOs: string;
  outcome: string;
  /** Identity of the transfer this outcome belongs to, so a rerun can tell an aborted transfer from an unresolved one. */
  settlementKey?: string;
  txHash?: string;
}

/** A settlement resolution row (settled or refunded); carries no amount because it is not spend. */
export interface PayDemResolution {
  timestamp: string;
  resolution: 'settled' | 'refunded';
  settlementKey: string;
  txHash: string;
}

export interface PayDemAuthorizationGate {
  authorize(ctx: { amountOs: bigint; rpcUrl: string }): Promise<TransferAuthorization>;
  journalOutcome(outcome: Readonly<PayDemOutcome | PayDemResolution>): Promise<void>;
  beforeBroadcast(ctx: Readonly<{ authorizationNowIso: string }>): Promise<void>;
}

export function createPayDemAuthorizationGate(opts: {
  policy: PayPolicy;
  journalPath: string;
  acquireLock: (path: string) => PayDemJournalLease;
  readJournal: (path: string) => unknown[];
  killSwitchPresent: (path: string) => boolean;
  resolveKillSwitchPath: (path: string) => string;
  durableOutcomeJournal: (outcome: Readonly<PayDemOutcome | PayDemResolution>) => Promise<void>;
  nowIso?: () => string;
}): PayDemAuthorizationGate {
  let activeLease: { lease: PayDemJournalLease; nowIso: string } | undefined;
  const nowIso = opts.nowIso ?? (() => new Date().toISOString());
  const lockBlocked = (error: unknown): TransferAuthorization => ({
    verdict: 'BLOCK',
    rule: 'journal-lock',
    reason: `payment journal lock is unavailable: ${error instanceof Error ? error.message : String(error)}`,
  });
  const release = (active: { lease: PayDemJournalLease; nowIso: string }): void => {
    if (activeLease === active) activeLease = undefined;
    active.lease.release();
  };
  const releasePending = (lease: PayDemJournalLease): TransferAuthorization | undefined => {
    try {
      lease.release();
      return undefined;
    } catch (error) {
      return lockBlocked(error);
    }
  };

  return {
    async authorize({ amountOs, rpcUrl }) {
      if (activeLease !== undefined) {
        return lockBlocked(new Error('payment journal lock is already active in this process'));
      }

      let lease: PayDemJournalLease;
      try {
        lease = opts.acquireLock(opts.journalPath);
      } catch (error) {
        return lockBlocked(error);
      }

      const authorizationNowIso = nowIso();
      let spentTodayOs: bigint;
      try {
        spentTodayOs = spentTodayFromJournal(opts.readJournal(opts.journalPath), authorizationNowIso);
      } catch (error) {
        const releaseFailure = releasePending(lease);
        if (releaseFailure !== undefined) return releaseFailure;
        return {
          verdict: 'BLOCK',
          rule: 'journal-unreadable',
          reason: `payment journal could not be read: ${error instanceof Error ? error.message : String(error)}`,
        };
      }

      let killSwitchPresent: boolean;
      try {
        killSwitchPresent = opts.killSwitchPresent(opts.resolveKillSwitchPath(opts.policy.killSwitchFile));
      } catch (error) {
        const releaseFailure = releasePending(lease);
        if (releaseFailure !== undefined) return releaseFailure;
        return {
          verdict: 'BLOCK',
          rule: 'kill-switch',
          reason: `kill switch status could not be read: ${error instanceof Error ? error.message : String(error)}`,
        };
      }

      const authorization = authorizeTransfer(opts.policy, {
        amountOs,
        rpcUrl,
        spentTodayOs,
        killSwitchPresent,
        nowIso: authorizationNowIso,
      });
      if (authorization.verdict !== 'PROCEED') {
        const releaseFailure = releasePending(lease);
        return releaseFailure ?? authorization;
      }

      activeLease = { lease, nowIso: authorization.nowIso };
      return authorization;
    },

    async journalOutcome(outcome) {
      // A settlement resolution (settled/refunded) is a durable identity row, not spend accounting: it is appended as is.
      if ('resolution' in outcome) {
        await opts.durableOutcomeJournal(outcome);
        return;
      }
      const active = activeLease;
      if (active === undefined) {
        if (outcome.outcome === 'aborted-before-broadcast') {
          await opts.durableOutcomeJournal(outcome);
          return;
        }
        throw new Error('payment journal lock is unavailable before broadcast');
      }
      try {
        if (outcome.outcome !== 'aborted-before-broadcast') {
          if (outcome.timestamp !== active.nowIso || utcDateOrThrow(nowIso()) !== utcDateOrThrow(active.nowIso)) {
            throw new Error('payment policy authorization expired at UTC day boundary');
          }
          if (opts.killSwitchPresent(opts.resolveKillSwitchPath(opts.policy.killSwitchFile))) {
            throw new Error(`kill switch is present at ${opts.policy.killSwitchFile}`);
          }
        }
        await opts.durableOutcomeJournal(outcome);
      } finally {
        release(active);
      }
    },

    async beforeBroadcast({ authorizationNowIso }) {
      if (utcDateOrThrow(nowIso()) !== utcDateOrThrow(authorizationNowIso)) {
        throw new Error('payment policy authorization expired at UTC day boundary');
      }
      if (opts.killSwitchPresent(opts.resolveKillSwitchPath(opts.policy.killSwitchFile))) {
        throw new Error(`kill switch is present at ${opts.policy.killSwitchFile}`);
      }
    },
  };
}
