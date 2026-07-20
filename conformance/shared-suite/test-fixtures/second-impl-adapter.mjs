#!/usr/bin/env node
/**
 * TEST FIXTURE ONLY — a minimal, independently-coded F3 adapter that declares a DISTINCT
 * repository codebase. It re-implements ONLY the signatureValueVerdict (F3) canonical-unpadded-
 * Base64URL check from scratch (its own decode/re-encode), so that a genuine two-independent-
 * adapter INTEROP-AGREE can be exercised in tests.
 *
 * IMPORTANT: this is a TEST fixture, NOT the "second genuine implementation + manifest pin" that
 * Blocker 4 requires. Blocker 4 remains OUT OF SCOPE and open. This fixture exists only to prove
 * the runner's independence-counting and multi-adapter path behave correctly; it is never
 * registered by the default cross-run and is not WG cross-implementation evidence.
 */
import { createInterface } from 'node:readline';

const PROTOCOL = 'dacs-adapter/1';

const metadata = {
  name: 'second-impl-fixture',
  version: '0.0.1',
  repository: 'https://example.test/independent-dacs-impl',
  revision: 'b'.repeat(40),
  supportedFamilies: ['sig-value-encoding'],
  operations: ['signatureValueVerdict'],
};

// Independent F3 check: accept iff the string is canonical unpadded Base64URL, i.e. it round-
// trips through decode → re-encode (unpadded, URL alphabet) unchanged. No length hardcoding.
function signatureValueVerdict(value) {
  if (typeof value !== 'string') return 'REJECT';
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return 'REJECT'; // URL alphabet, unpadded only
  let buf;
  try { buf = Buffer.from(value, 'base64url'); } catch { return 'REJECT'; }
  const reencoded = buf.toString('base64url'); // node emits unpadded base64url
  return reencoded === value ? 'ACCEPT' : 'REJECT';
}

const impl = { signatureValueVerdict };

function reply(m) { process.stdout.write(JSON.stringify(m) + '\n'); }

createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', (line) => {
  let request;
  try {
    request = JSON.parse(line);
    if (request.protocol !== PROTOCOL) throw new Error(`unsupported protocol: ${request.protocol}`);
    if (request.type === 'metadata') { reply({ protocol: PROTOCOL, id: request.id, ok: true, result: metadata }); return; }
    if (request.type !== 'execute') throw new Error(`unsupported request type: ${request.type}`);
    if (!metadata.operations.includes(request.operation)) throw new Error(`unsupported operation: ${request.operation}`);
    reply({ protocol: PROTOCOL, id: request.id, ok: true, result: impl[request.operation](...(request.params ?? [])) });
  } catch (error) {
    reply({ protocol: PROTOCOL, id: request?.id ?? null, ok: false, error: { code: 'OPERATION-ERROR', message: String(error?.message ?? error) } });
  }
});
