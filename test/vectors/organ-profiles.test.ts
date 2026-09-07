import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ORGAN_PROFILES, organProfile, profiledOrgans } from '../../src/live/organ-profiles.js';
import { supportedOrgans } from '../../src/live/dacs-testnet-run.mjs';

const run = (args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, ['--import', 'tsx', 'src/live/dacs-testnet-run.mts', ...args], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env } });
const lastJson = (stdout: string) => JSON.parse(stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1) ?? '{}');

test('every profiled organ has a projection and every projected organ has a profile; the table is well formed', () => {
  assert.deepEqual(profiledOrgans().sort(), supportedOrgans().sort());
  for (const [organ, profile] of Object.entries(ORGAN_PROFILES)) {
    assert.equal(profile.tags[0], organ);
    assert.ok(profile.title.startsWith(`proof-organ:${organ}`), profile.title);
    assert.ok(profile.description.includes('committed'), 'the description says what stays committed');
    assert.ok(profile.defaultQuery.length > 0);
  }
  assert.equal(organProfile('constructor'), undefined);
  assert.equal(organProfile('bogus'), undefined);
});

test('the coordinator sells each profiled organ in a dry run with its own parameter hash; default stays nws_alerts', () => {
  const hashes = new Map<string, string>();
  for (const organ of profiledOrgans()) {
    const r = run(['--dry-run', '--json', '--job-id', `profile-${organ}`, '--organ', organ]);
    const result = lastJson(r.stdout);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(result.rollup, 'PASS', JSON.stringify(result.error));
    hashes.set(organ, result.paramHash);
  }
  assert.equal(new Set(hashes.values()).size, profiledOrgans().length, 'parameter hashes differ per organ');
  const byEnv = lastJson(run(['--dry-run', '--json', '--job-id', 'profile-env'], { ORGAN: 'air_quality' }).stdout);
  assert.equal(byEnv.paramHash, hashes.get('air_quality'), 'ORGAN selects the organ');
  const flagWins = lastJson(run(['--dry-run', '--json', '--job-id', 'profile-flag', '--organ', 'drug_info'], { ORGAN: 'air_quality' }).stdout);
  assert.equal(flagWins.paramHash, hashes.get('drug_info'), '--organ wins over ORGAN');
  const dflt = lastJson(run(['--dry-run', '--json', '--job-id', 'profile-default']).stdout);
  assert.equal(dflt.paramHash, hashes.get('nws_alerts'), 'no selection means nws_alerts');
});

test('an organ without a profile or projection is a config refusal before anything runs', () => {
  for (const args of [['--dry-run', '--json', '--organ', 'bogus'], ['--dry-run', '--json', '--organ', 'constructor']]) {
    const r = run(args);
    assert.notEqual(r.status, 0);
    const result = lastJson(r.stdout || r.stderr);
    assert.equal(result.outcome, 'REFUSED'); assert.equal(result.reason, 'config');
  }
  const r = run(['--dry-run', '--json'], { ORGAN: 'nope' });
  assert.notEqual(r.status, 0);
});
