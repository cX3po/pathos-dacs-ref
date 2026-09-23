# Changelog

## 0.2.0

- MCP verification policy is server-owned; conflicting caller flags return `isError: true`. Callers must configure the server policy instead of overriding signature or anchor checks per request.
- `verifier_info` reports the effective policy. Offline fixture results do not claim live anchoring.
- Includes reproducible verifier artifacts and updated MCP documentation. Portable Node/Python reproduction probes are in the source repository.

This reference verifier release does not establish current DACS-Standard conformance or a hosted deployment.
