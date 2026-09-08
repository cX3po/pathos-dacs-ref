# Security policy

pathos-dacs-ref is an independent reference implementation of DACS (Demos Agent
Commerce Standards). This page says where to send a security report, what to
include, and what happens to it.

## Contact

Send security reports to **security@path-os.net**.

Do not open a public issue for a vulnerability. The issue templates are for
conformance failures, wrong exit codes and broken test vectors that are safe to
discuss in the open.

## Supported versions

| Package | Supported version | Where |
| --- | --- | --- |
| `@pathos-labs/dacs-verifier` | 0.1.0 | npm |
| `@pathos-labs/dacs-jcs` | 0.1.0 | npm |
| `@pathos-labs/dacs-fixtures` | 0.1.0 | npm |
| `pathos-dacs-ref` (this repository) | `main` | GitHub |

A fix ships as a new patch version of the affected package and as a commit on
`main`. Earlier versions are not patched.

## What to include

- the package name and version, or the commit of this repository you tested
- the affected surface: verifier walk, JCS canonicalisation, signature scheme,
  listing publisher, recipe, live runner, CLI
- a reproduction: the smallest bundle, vector or command that shows the
  problem, with every credential, mnemonic and private key removed
- the impact as you understand it: what a verifier would wrongly accept or
  reject, or what an operator could lose
- whether the problem is in this implementation or in the DACS specification
  itself; specification gaps go to KyneSys (see `CONTRIBUTING.md`)

Do not send private keys, mnemonics or live credentials, ours or yours. If a
report contains any, we will ask you to rotate them before we continue.

## Triage

1. PATH-OS reads reports sent to security@path-os.net and
   acknowledges receipt. A person and a model review each report together;
   there is no automated responder on this address and no fixed response time.
2. We reproduce the report against the offline verifier and the conformance
   vectors at the reported version.
3. We classify it: a confirmed vulnerability, a conformance bug (moved to a
   public issue with your consent), a specification gap (forwarded to the
   specification's maintainers with your consent), or not a security issue.
4. A confirmed vulnerability is fixed on a private branch and released as a
   patch version and a commit on `main`. Reporters are credited if they wish.
5. After the fix is released, the vulnerability is published as a GitHub
   Security Advisory on this repository, with a disclosure date agreed with
   the reporter.

## Out of scope

- the Demos Network node, the DACS specification and the KyneSys SDK: report
  those to their maintainers
- balances of our own testnet wallets
- findings that need a compromised operator machine
