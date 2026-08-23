# SR-4 replay-coordinate hook — NON-NORMATIVE reference artifact

**This is not a DACS conformance vector set.** It will not be offered as a DACS-Standard PR
unless/until the open question on [DACS-Standard #195][195] is settled. It lives here as the
concrete reference impl of a proposal, nothing more.

## What it demonstrates

On #195, RB parked the L2PS forward-secrecy / nonce-reuse issue as *substrate-side* (the crypto
envelope is implementation-defined — the same line we drew declining the nonce-reuse case in #203),
and asked one genuinely open question:

> *Is a black-box "reject a reused `(channel, epoch, key-id, nonce)`" check expressible without DACS
> normatively defining those envelope fields?*

Our answer ([issuecomment-4847774751][reply]): **yes — but only if DACS defines one abstract
observable, not the fields.** Don't normatively define the tuple. Define an SR-4 **replay coordinate**:
an opaque, substrate-emitted equality token that folds whatever anti-replay inputs the substrate uses,
with a single normative contract —

> *Within one session, two admitted messages MUST NOT share a replay coordinate;
> a re-presented coordinate MUST be rejected.*

The conformance hook then tests the **contract** on the opaque token, never the crypto envelope —
the same move DACS already uses for §7.5.1's abstract decision and the abstract SR-2 anchor in
sealed-envelope: *test the property, not the mechanism.*

## What's here

- `validate.ts` — `checkReplayCoordinate(msg, ctx)`, a pure black-box checker. Coordinates are compared
  by **exact equality** (canonical, injective token emission is the substrate's responsibility, exactly
  as the envelope crypto is). §7.5.1 4-value, never collapsed:
  - **pass** — coordinate fresh for this session → admit
  - **fail** — coordinate already admitted in this session → MUST reject (the nonce-reuse / replay case)
  - **indeterminate** — substrate emitted *no* coordinate → capability unobservable (NOT a violation)
  - **error** — malformed (token present but not a non-empty string; malformed session ctx)
- `run.mts` — 14 reference vectors + 1 robustness assertion (15/15). Reviewed Codex (binding) + qwen.

Session-scoped, not global: a token admitted in session A is fresh in session B (no cross-session
ledger). If the substrate ships an actual forward-secrecy guarantee, the FS property becomes a separate
cross-run; this hook is only the replay-coordinate uniqueness contract.

[195]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/195
[reply]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/195#issuecomment-4847774751
