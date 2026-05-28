---
name: Bug report
about: A spec-conformance failure, wrong CLI exit code, or broken test vector
title: '[bug] '
labels: bug
---

## What's failing

(One sentence — what behavior do you see that you didn't expect.)

## Spec section affected

(Cite the DACS spec § — e.g. "§7.5.1 invariant collapsed to pass" or "§10.4.2
two-sided anchoring not enforced". If you don't know the section, leave blank
and the reviewer will tag.)

## Reproduction

```bash
# Minimal commands to reproduce
git clone <fork>
cd pathos-dacs-ref
npm ci
npx tsx src/cli/verify.ts --bundle-file ./repro.json
# Expected: ...
# Actual:   ...
```

## Repro inputs

(Paste the smallest bundle/listing/command-line that triggers the bug, OR link
to a gist. Strip any private mnemonics first.)

## Environment

- Node version (`node --version`):
- OS:
- pathos-dacs-ref commit (`git log -1 --oneline`):
- Demos SDK version (`cat node_modules/@kynesyslabs/demosdk/package.json | jq -r .version`):
