import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Hashing } from '@kynesyslabs/demosdk/encryption';

/**
 * Guard for the demosdk UTF-8 sha256 patch (`patches/@kynesyslabs+demosdk+<version>.patch`).
 *
 * THE BUG. demosdk's `Hashing.sha256` calls node-forge's `md.update(message)` with no
 * encoding, so forge treats the string as raw binary and any non-ASCII codepoint hashes
 * to the wrong digest — a live tx hash-mismatch, originally surfaced by an em-dash in a
 * listing (PR #36, root-caused and live-verified). Upstream has NOT fixed it: a pristine
 * `npm pack @kynesyslabs/demosdk@4.0.16` still ships `md.update(message);`. We carry a
 * one-line patch adding `"utf8"`.
 *
 * WHAT THIS GUARD IS *NOT* FOR. An earlier version of this comment claimed patch-package
 * silently stops applying a patch whose filename version does not match the installed
 * version, and that a dependency bump therefore drops this fix unnoticed. That is FALSE
 * and was corrected before it landed. patch-package 8 attempts the patch anyway and
 * succeeds if it still applies, printing a "patch file version mismatch" warning and
 * exiting 0 — verified by reproducing it (package.json at ^4.0.16 against a
 * ...+4.0.10.patch: `@kynesyslabs/demosdk@4.0.10 OK`, fix present). Likewise, if the
 * target line ever MOVES so the patch cannot apply, `npm ci` already exits non-zero on
 * its own; this test is not what catches that.
 *
 * WHAT IT IS FOR, precisely: the case where installation SUCCEEDS but the fix is absent —
 * the patch file deleted, renamed out of discovery, lost in a merge, or the dependency
 * swapped for one without it. Stated precisely, because a looser version of this sentence
 * wrong twice: BEFORE this guard, 14 existing test files touched SHA-256 through other
 * implementations; none asserted demosdk's `Hashing.sha256` behaviour. This file is the
 * 15th and the only one that does.
 * That is a narrower claim than this comment first made, and it is the true one.
 *
 * If this goes red: confirm the patch is present and applied for the installed version
 * (`npx patch-package @kynesyslabs/demosdk` regenerates it under the right filename). If
 * upstream has finally fixed the bug, delete the patch and this guard together, in one
 * commit that says so.
 */
test('demosdk Hashing.sha256 hashes non-ASCII as UTF-8 (patch applied)', () => {
  // An em-dash: one codepoint, three UTF-8 bytes. This is the character that broke a
  // real transaction, not a synthetic edge case.
  const message = 'listing — em-dash';
  const expected = createHash('sha256').update(message, 'utf8').digest('hex');

  assert.equal(
    Hashing.sha256(message),
    expected,
    'demosdk Hashing.sha256 disagrees with UTF-8 sha256 — the patch-package patch is not '
    + 'applied. Check that patches/@kynesyslabs+demosdk+<installed version>.patch matches '
    + 'the version in package.json.',
  );
});

test('the guard would actually catch an unpatched build', () => {
  // Sanity: prove the assertion above is not vacuous by showing the unpatched behaviour
  // (forge's default binary interpretation) differs from the UTF-8 digest.
  const message = 'listing — em-dash';
  const utf8Digest = createHash('sha256').update(message, 'utf8').digest('hex');
  const binaryDigest = createHash('sha256').update(Buffer.from(message, 'binary')).digest('hex');
  assert.notEqual(utf8Digest, binaryDigest,
    'if these ever match, this character no longer distinguishes the bug and the guard is blind');
});
