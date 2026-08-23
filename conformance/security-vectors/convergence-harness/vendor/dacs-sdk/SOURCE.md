# Vendored: dacs-sdk (canonical hasher only)

Verbatim from **DACS-Agent-commerce/dacs-sdk** @ commit `44d8ff2` (cloned 2026-07-06).
Re-implements NOTHING — the convergence harness must compare the REAL independent impl.

Vendored (minimal set for the PRIMARY key-free canonical bundle-hash):
- `canonical/jcs.ts`   — RFC 8785 JCS canonicalization (verbatim)
- `canonical/hash.ts`  — `contentHash` = sha256Hex(canonicalize(stripSignature(doc))) (verbatim)
- `errors.ts`          — DacsError (dependency of jcs.ts) (verbatim)

The adapter (`../../adapters/dacs-sdk.ts`) strips `anchoredByRole` then calls the real
`contentHash`, yielding the §10.4.1 / R5-1 canonical bundle signed-scope hash. Decision (§7.5.1)
is NOT wired here — dacs-sdk's verifier is a 14-file tree; the PRIMARY hash is key-free and is the
cleanest convergence proof, and the corpus is did:demos:* (non-portable) so decision is not compared.
