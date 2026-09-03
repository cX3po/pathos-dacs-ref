export { jcsCanonical, jcsHash, jcsHashHex } from './jcs.js';

export {
  ADDITIVE_DOMAIN_SEPARATORS,
  DACS_X_EXTENSION_SEPARATORS,
  DOMAIN_SEPARATORS,
  LEGACY_READ_SEPARATORS,
  PATHOS_EXTENSION_SEPARATORS,
  REVIEWED_DACS_X_EXTENSION_SEPARATORS,
  assertEmittableSeparator,
  assertKnownSeparator,
  buildSignedBytes,
  isLegacyReadSeparator,
  type DomainSeparator,
  type DomainSeparatorKey,
} from './domain-sep.js';

export { generateKeypair, sign, verify } from './lib/sign.js';
