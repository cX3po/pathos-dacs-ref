# verifyPeer — an A2A Peer-Trust showcase

A2A's unsolved problem is **trusting a stranger's agent**. A peer hands you an **AgentCard**
(its `.well-known/agent.json`: a name + an identity claim) and asks you to do work. The card is
**discovery evidence, not trust** — anyone can put any name and any identity in their *own* card,
and even self-sign it. Trust has to be earned against something the peer **cannot forge**.

`verifyPeer()` is that gate. Before an agent accepts a task from a stranger, it:

1. runs the §10.4.1 acceptance verifier (`verifyBundleV1`) over the peer's `AttestationBundleV1`, and
2. **binds** the AgentCard's claimed identity to the identity the bundle **cryptographically proves**
   signed it.

```
trusted === (bundle decision === 'accept'  &&  card identity is a DACS-proven signer)
```

Anything else — `reject`, `indeterminate`, `error`, or an **unbound** identity — is `trusted=false`.
An unresolvable/ambiguous reference is `indeterminate`, **never** a borrowed `pass`.

## The #194 doctrine, made concrete

An A2A AgentCard is **evidence DACS binds, not trust it inherits.** DACS records its OWN verifier
act; it never lets the card's self-assertion stand in for a third-party-verifiable proof. The card's
optional `agentCardSignature` is deliberately **not** a trust input here — a self-signature over your
own card is discovery-layer provenance, not trust.

## The showcase

One task handler, wrapped in `withDacsTrust`. Two strangers request the task:

| Peer | AgentCard claims | Bundle proves | Verdict |
|------|------------------|---------------|---------|
| **Honest** | identity `A` | identity `A` (real ed25519 sig) | `accept` → 🟢 **ACCEPTED**, handler runs |
| **Impostor** | identity `X` | identity `Y` (a *different* real key) | `reject` → 🔴 **DECLINED** (`identity-mismatch`), handler never runs |

The impostor's bundle is perfectly valid on its own — it just **proves a different identity than the
card claims**. That is the seam DACS closes: the card is discovery, the bundle is trust, and when they
disagree the peer is declined. The demo prints an **A2A Peer-Trust Log**, emits a machine-readable JSON
result, and exits `0` **only if** honest → accepted **and** impostor → declined.

## Run

```bash
npx tsx showcase/verify-peer/demo.mts
```

Console only. Deterministic (fixed-seed ed25519 keys). Zero network, zero funds, no deployed
identities — mirrors the sibling `showcase/stranger-gauntlet`.

## The primitive

- `src/lib/verify-peer.ts` — `verifyPeer(peer, opts?) → PeerTrustResult` and the
  `withDacsTrust(handler, opts?)` A2A middleware wrapper. Drop-in: import the existing
  `verifyBundleV1` §10.4.1 verifier; no edits to it.
- `test/integration/verify-peer.test.ts` — honest→trusted, impostor→`identity-mismatch`,
  tampered→reject, indeterminate→`trusted===false` (do-not-collapse), and `withDacsTrust`
  never calls the handler for an untrusted peer.
