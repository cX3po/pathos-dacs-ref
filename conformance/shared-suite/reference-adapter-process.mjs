#!/usr/bin/env node
import { createInterface } from 'node:readline';
import { referenceAdapter } from './reference-adapter.mjs';
import { PROTOCOL } from './adapter-process-client.mjs';

const implementation = referenceAdapter();
const metadata = {
  name: implementation.name,
  version: '1.0.0',
  repository: 'https://github.com/cX3po/pathos-dacs-ref',
  revision: 'sha256:a56be205546115a7cd5bf7da4db404af9cf85771f50131418035af94e975eecc',
  supportedFamilies: [
    'canonical-accept', 'canonical-reject', 'drift-signed-scope',
    'sig-value-encoding', 'sig-value-legacy-import', 'domain-sep-sign',
  ],
  operations: [
    'canonicalize', 'signedScopeHash', 'signatureValueVerdict',
    'legacySignatureValueImport', 'domainSepSign', 'domainSepVerify',
  ],
};

function decodeProtocolValue(value) {
  if (Array.isArray(value)) return value.map(decodeProtocolValue);
  if (value && typeof value === 'object') {
    if (value.$dacsType === 'bytes' && typeof value.hex === 'string') {
      return new Uint8Array(Buffer.from(value.hex, 'hex'));
    }
    if (value.$dacsType === 'bigint' && typeof value.decimal === 'string') return BigInt(value.decimal);
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decodeProtocolValue(item)]));
  }
  return value;
}

function reply(message) {
  process.stdout.write(JSON.stringify(message) + '\n');
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', async (line) => {
  let request;
  try {
    request = JSON.parse(line);
    if (request.protocol !== PROTOCOL) throw new Error(`unsupported protocol: ${request.protocol}`);
    if (request.type === 'metadata') {
      reply({ protocol: PROTOCOL, id: request.id, ok: true, result: metadata });
      return;
    }
    if (request.type !== 'execute') throw new Error(`unsupported request type: ${request.type}`);
    if (!metadata.operations.includes(request.operation)) throw new Error(`unsupported operation: ${request.operation}`);
    const result = await implementation[request.operation](...decodeProtocolValue(request.params ?? []));
    reply({ protocol: PROTOCOL, id: request.id, ok: true, result });
  } catch (error) {
    reply({
      protocol: PROTOCOL,
      id: request?.id ?? null,
      ok: false,
      error: { code: 'OPERATION-ERROR', message: error instanceof Error ? error.message : String(error) },
    });
  }
});
