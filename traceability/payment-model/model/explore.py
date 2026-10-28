#!/usr/bin/env python3
"""Offline finite-state payment reference model. See README.md for scope and limitations.
No SDK imports, wallet operations, network, or third-party dependencies.
"""
from collections import deque, Counter
from dataclasses import dataclass, replace
import json
import platform
import sys
import time

@dataclass(frozen=True)
class State:
    journal: str = 'deal'
    workers: tuple = ('idle', 'idle')
    reserved: bool = False
    intent: bool = False
    calls: int = 0
    effects: int = 0  # ghost: cumulative monetary effects, never erased by reset
    truth: str = 'none'
    read: str = 'none'
    reset: bool = False
    cancelled: bool = False
    delivery: int = 0  # idempotent external delivery sink, separate from journal
    releases: int = 0
    refunds: int = 0
    proof: bool = False  # definitive non-execution AND revocation of old send authority

TERMINAL = {'released', 'refunded'}
MUTANTS = ('release_on_missing', 'retry_without_identity', 'second_worker_unfenced',
           'cancel_refund_after_broadcast', 'deliver_on_stale', 'crash_forgets_intent',
           'recovery_duplicates_release')

def move(s, i, pc, **kw):
    w = list(s.workers)
    w[i] = pc
    return replace(s, workers=tuple(w), **kw)

def successors(s, variant):
    # Environment events can interleave with every worker microstep.
    if not s.cancelled and s.journal not in TERMINAL:
        yield 'cancel', replace(s, cancelled=True)
    if not s.reset:
        yield 'chain.reset', replace(s, reset=True, read='none')
    for i, pc in enumerate(s.workers):
        prefix = f'w{i}.'
        if pc == 'down':
            yield prefix+'restart', move(s, i, 'idle')
            continue
        if pc == 'idle':
            occupied = any(p not in ('idle', 'down') for p in s.workers)
            if s.journal not in TERMINAL and (not occupied or variant == 'second_worker_unfenced'):
                yield prefix+'acquire', move(s, i, s.journal)
            continue
        # Crash/throw/timeout stop a worker, drop its local permit, keep durable facts.
        changes = {}
        if variant == 'crash_forgets_intent' and s.intent and s.journal == 'intent':
            changes = dict(journal='signed', intent=False)
        yield prefix+'crash', move(s, i, 'down', **changes)
        yield prefix+'throw', move(s, i, 'down', **changes)
        yield prefix+'timeout', move(s, i, 'down', **changes)
        yield prefix+'yield_lease', move(s, i, 'idle')
        if s.cancelled and s.journal not in TERMINAL and not s.delivery and not s.releases:
            if not s.intent or s.proof or (variant == 'cancel_refund_after_broadcast' and s.calls):
                yield prefix+'refund.intent', move(s, i, 'refund_pending', journal='refund_pending')
        if pc == 'deal' and not s.cancelled:
            yield prefix+'reserve', move(s, i, 'reserved', journal='reserved', reserved=True)
        elif pc == 'reserved' and not s.cancelled:
            yield prefix+'sign', move(s, i, 'signed', journal='signed')
            # Wrong key / declined signature is pre-effect and recoverable.
            yield prefix+'sign.reject', move(s, i, 'down')
        elif pc == 'signed' and not s.cancelled:
            yield prefix+'broadcast.intent', move(s, i, 'armed', journal='intent', intent=True)
        elif pc == 'armed':
            if s.cancelled:
                # Intent remains ambiguous even if this worker elects not to send.
                yield prefix+'cancel.fence', move(s, i, 'intent')
            else:
                for outcome in ('included', 'unresolved', 'failed'):
                    yield prefix+'broadcast.'+outcome, move(
                        s, i, 'intent', journal='intent', calls=s.calls+1,
                        effects=s.effects+(outcome == 'included'), truth=outcome, read='none')
        elif pc in ('intent', 'observed'):
            if s.delivery:
                yield prefix+'deliver.recover_ack', move(s, i, 'delivery_ack')
            if s.truth == 'unresolved':
                # A send whose response was lost can land later; no resubmission.
                yield prefix+'chain.late_inclusion', replace(s, truth='included', effects=s.effects+1)
                yield prefix+'chain.final_failure', replace(s, truth='failed')
            reads = ['MISSING', 'ERROR']
            if s.reset:
                reads += ['STALE']
            if s.truth == 'included':
                reads += ['included']
            # A proof is stronger than a lookup result: exact tuple, final failure,
            # AND no still-live armed worker. Raw missing/failed-shaped RPC is not proof.
            if s.truth == 'failed' and 'armed' not in s.workers:
                reads += ['failed_proven']
            for observation in reads:
                verified = observation == 'included'
                proven = observation == 'failed_proven'
                yield prefix+'observe.'+observation, move(
                    s, i, 'observed' if verified or proven else 'intent',
                    journal='observed' if verified or proven else 'intent',
                    read=observation, proof=s.proof or proven)
            if s.read == 'included' or (variant == 'deliver_on_stale' and s.read == 'STALE'):
                if not s.cancelled:
                    yield prefix+'deliver.effect', move(s, i, 'delivery_ack', delivery=1)
            if s.proof and not s.refunds:
                yield prefix+'release.intent', move(s, i, 'release_pending', journal='release_pending')
            if variant == 'release_on_missing' and s.read == 'MISSING':
                yield prefix+'release.intent', move(s, i, 'release_pending', journal='release_pending')
            if variant == 'retry_without_identity' and s.calls and not s.proof:
                yield prefix+'retry.fresh_identity', move(s, i, 'signed', journal='signed')
            # Normal retry is a read-only restart, never a second broadcast.
            yield prefix+'retry.reconcile', move(s, i, 'idle')
        elif pc == 'delivery_ack':
            yield prefix+'deliver.ack', move(s, i, 'delivered', journal='delivered')
        elif pc == 'delivered':
            yield prefix+'release.intent', move(s, i, 'release_pending', journal='release_pending')
        elif pc == 'release_pending':
            yield prefix+'release.effect', move(s, i, 'release_ack', reserved=False, releases=s.releases+1 if variant == 'recovery_duplicates_release' else 1)
        elif pc == 'release_ack':
            yield prefix+'release.ack', move(s, i, 'idle', journal='released')
        elif pc == 'refund_pending':
            yield prefix+'refund.effect', move(s, i, 'refund_ack', reserved=False, refunds=1)
        elif pc == 'refund_ack':
            yield prefix+'refund.ack', move(s, i, 'idle', journal='refunded')

def violation(before, event, after):
    # Ghost truth is independent of observer/journal decisions, including mutations.
    if after.effects > 1:
        return 'no_double_payment'
    if event.endswith('deliver.effect') and (before.read != 'included' or before.truth != 'included'):
        return 'delivery_requires_verified_payment'
    if after.releases > before.releases and not (before.delivery or before.proof):
        return 'release_requires_delivery_or_nonexecution_proof'
    if after.calls > before.calls and before.calls and not before.proof:
        return 'no_rebroadcast_on_unknown_outcome'
    if after.refunds > before.refunds and before.intent and not before.proof:
        return 'cancel_after_intent_requires_nonexecution_proof'
    if event.endswith(('crash', 'throw', 'timeout', 'restart')):
        durable = ('journal', 'reserved', 'intent', 'calls', 'effects', 'truth',
                   'delivery', 'releases', 'refunds', 'proof')
        if any(getattr(before, k) != getattr(after, k) for k in durable):
            return 'crash_recovery_preserves_durable_facts'
    if max(after.delivery, after.releases, after.refunds) > 1 or after.releases+after.refunds > 1:
        return 'idempotent_recovery_effects'
    return None

def explore(variant):
    initial = State()
    queue = deque([initial])
    parent = {initial: None}
    edges = 0
    coverage = Counter()
    crash_points = set()
    milestones = set()
    while queue:
        s = queue.popleft()
        if s.delivery: milestones.add('delivery')
        if s.journal in TERMINAL: milestones.add(s.journal)
        for event, t in successors(s, variant):
            edges += 1
            category = event.split('.', 1)[-1]
            coverage[category] += 1
            if event.endswith('.crash'):
                crash_points.add(s.workers[int(event[1])])
            failure = violation(s, event, t)
            if failure:
                trace = [event]
                cursor = s
                while parent[cursor] is not None:
                    cursor, e = parent[cursor]
                    trace.append(e)
                trace.reverse()
                return dict(variant=variant, status='CAUGHT', invariant=failure,
                            states=len(parent), edges=edges, steps=len(trace), trace=trace)
            if t not in parent:
                parent[t] = (s, event)
                queue.append(t)
    required = {'delivery', 'released', 'refunded'}
    if variant == 'reference':
        assert milestones == required, milestones
        for event in ('observe.MISSING', 'observe.ERROR', 'observe.STALE', 'observe.included',
                      'observe.failed_proven', 'sign.reject', 'throw', 'timeout', 'retry.reconcile'):
            assert coverage[event], event
        assert {'deal', 'reserved', 'signed', 'armed', 'intent', 'observed', 'delivery_ack',
                'delivered', 'release_pending', 'release_ack', 'refund_pending', 'refund_ack'} <= crash_points
    return dict(variant=variant, status='PASS', states=len(parent), edges=edges,
                crash_points=sorted(crash_points), milestones=sorted(milestones),
                coverage=dict(sorted(coverage.items())))

def replay(events):
    s = State()
    for event in events:
        choices = dict(successors(s, 'reference'))
        assert event in choices, (event, s)
        t = choices[event]
        assert violation(s, event, t) is None, event
        s = t
    return s

def regression_checks():
    paid = ['w0.acquire', 'w0.reserve', 'w0.sign', 'w0.broadcast.intent',
            'w0.broadcast.included', 'w0.observe.included', 'w0.deliver.effect']
    # Adversarial pass miss: cancellation between effect and acknowledgement must
    # still recover the delivery receipt and finish the reservation journal.
    s = replay(paid + ['cancel', 'w0.crash', 'w1.acquire', 'w1.deliver.recover_ack',
                      'w1.deliver.ack', 'w1.release.intent', 'w1.release.effect', 'w1.release.ack'])
    assert s.journal == 'released' and s.delivery == 1 and s.refunds == 0
    # Adversarial pass miss: cancellation after budget release cannot credit twice.
    failed = ['w0.acquire', 'w0.reserve', 'w0.sign', 'w0.broadcast.intent',
              'w0.broadcast.failed', 'w0.observe.failed_proven',
              'w0.release.intent', 'w0.release.effect', 'cancel']
    s = replay(failed)
    assert not any(e.endswith('refund.intent') for e, _ in successors(s, 'reference'))
    s = replay(failed + ['w0.crash', 'w1.acquire', 'w1.release.effect', 'w1.release.ack'])
    assert s.releases == 1 and s.refunds == 0
    # All uncertain reads after a reset retain the reservation and cannot send.
    for read in ('MISSING', 'ERROR', 'STALE'):
        s = replay(['w0.acquire', 'w0.reserve', 'w0.sign', 'w0.broadcast.intent',
                    'w0.broadcast.unresolved', 'chain.reset', 'w0.observe.'+read])
        assert s.reserved and not s.proof and s.read == read
        assert not any('.broadcast.' in e for e, _ in successors(s, 'reference'))
    print('regressions=PASS cancellation-after-delivery-effect; no-double-credit; reset-MISSING/ERROR/STALE')

def main():
    if sys.version_info < (3, 10):
        raise SystemExit('Python >=3.10 required')
    started = time.monotonic()
    regression_checks()
    print('runtime=Python '+platform.python_version())
    print('scope=one fixed (railId,jobId,phaseIndex), two workers, at most one reset; finite-state closure; unit-cost BFS')
    results = [explore(v) for v in ('reference',)+MUTANTS]
    for result in results:
        print(json.dumps(result, sort_keys=True))
    assert results[0]['status'] == 'PASS'
    assert all(r['status'] == 'CAUGHT' for r in results[1:]), 'surviving mutation'
    print(f'PASS reference and {len(MUTANTS)} mutation witnesses; elapsed_seconds={time.monotonic()-started:.3f}')

if __name__ == '__main__':
    main()
