# Private channels

The private-channel adapter is a message-only protocol for a fixed, CCI-bound
membership. It signs exact wire envelopes, enforces per-sender sequences starting
at one, and produces a self-contained transcript. Payload bytes are opaque: this
module does not interpret them as permissions, value movement, persistence
requests, or executable operations.

Local mode uses paired FIFO mailboxes in one process. It is complete offline and
is the recommended default for tests and integration work. It provides protocol
isolation and byte-copying, not remote confidentiality. Transcripts identify this
mode as `local`.

Live mode accepts an already provisioned subnet byte encryptor and an already
connected, structurally typed messaging peer. The operator must set
`PATHOS_L2PS_LIVE=1` exactly. The flag is checked before the SDK subpath is loaded
or the transport can connect or consult credentials. A missing peer is always an
error. The adapter does not create a peer and exposes no value-transfer or
persistence API.

## Transcript

A transcript is a JCS-canonicalizable object containing:

- its version, mode, channel identifier, and shared nonce;
- the frozen membership manifest and its CCI membership bindings;
- envelopes in canonical receive order;
- final per-claim sequence counters; and
- each member's closing signature over the final transcript commitment.

`verifyChannelTranscript` is a cold verifier. Given claim verification callbacks,
it reconstructs the manifest hash and channel identifier, validates exact schemas
and allowed content kinds, verifies membership and envelope signatures, rebuilds
every per-sender sequence, checks canonical ordering and counters, and verifies
that every closing signature commits to the same transcript hash. It requires no
transport or live SDK state.

The closing commitment excludes its own signature-carrying envelopes to avoid a
self-referential hash. Those envelopes remain in the transcript and are themselves
CCI-signed and sequence-checked.

## Deliberately unavailable

Live subnet negotiation, legacy-ciphertext acceptance, transcript publication,
and SDK negotiation/finalization helpers remain unavailable. They stay off until
the SDK provides a directly exported, audited messaging subpath suitable for this
narrow adapter boundary. The current live transport can only wrap capabilities
that an operator provisions and injects beforehand.
