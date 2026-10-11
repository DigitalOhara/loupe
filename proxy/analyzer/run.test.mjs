import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runScan, artifactId } from './run.js';
import { RULES } from './rules/index.js';
import { entry, manifest } from './testkit.mjs';

const META = { id: 'a'.repeat(64), tool: 'jadx 1.5.0', parts: [{ sha256: 'b'.repeat(64) }, { sha256: 'a'.repeat(64) }], errors: 0, partial: false };
const stub = (code) => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'loupe-az-w-')), 'w.mjs');
  fs.writeFileSync(f, `import { parentPort } from 'node:worker_threads';\n${code}`);
  return pathToFileURL(f);
};
const ids = (rec, state) => rec.outcomes.filter((o) => o.state === state).map((o) => o.ruleId);

test('artifactId depends on the APK parts only, in any order', () => {
  const a = artifactId(META), b = artifactId({ ...META, parts: [...META.parts].reverse(), tool: 'other', errors: 3 });
  assert.equal(a, b);
  assert.match(a, /^[a-f0-9]{64}$/);
  assert.notEqual(a, artifactId({ ...META, parts: [{ sha256: 'c'.repeat(64) }] }));
});

test('a real scan reports every rule and finishes complete', async () => {
  const dir = entry({ 'resources/AndroidManifest.xml': manifest({ app: 'android:debuggable="true"' }), 'sources/com/x/app/A.java': 'class A {}' });
  const progress = [];
  const rec = await runScan({ dir, meta: META, sig: { error: 'none' }, onProgress: (p) => progress.push(p.done) });
  assert.equal(rec.status, 'complete');
  assert.deepEqual([...new Set(rec.outcomes.map((o) => o.ruleId))].sort(), RULES.map((r) => r.id).sort());
  assert.ok(ids(rec, 'finding').includes('manifest.debuggable'));
  assert.deepEqual(progress.at(-1), RULES.length);
  assert.equal(rec.artifactId, artifactId(META));
});

test('a worker that never answers times out and every rule becomes an error', async () => {
  const rec = await runScan({ dir: entry({}), meta: META, sig: null, worker: stub('setInterval(() => {}, 1000);'), timeoutMs: 150 });
  assert.equal(rec.status, 'partial');
  assert.equal(ids(rec, 'error').length, RULES.length);
  assert.match(rec.outcomes[0].reason, /timed out/);
});

test('cancelling stops the scan and marks it cancelled', async () => {
  const ac = new AbortController();
  const p = runScan({ dir: entry({}), meta: META, sig: null, worker: stub('setInterval(() => {}, 1000);'), signal: ac.signal });
  setTimeout(() => ac.abort(), 50);
  const rec = await p;
  assert.equal(rec.status, 'cancelled');
  assert.equal(ids(rec, 'error').length, RULES.length);
});

test('a worker crash leaves a partial scan, not a clean one', async () => {
  const rec = await runScan({ dir: entry({}), meta: META, sig: null, worker: stub("throw new Error('boom');") });
  assert.equal(rec.status, 'partial');
  assert.equal(ids(rec, 'error').length, RULES.length);
});

test('worker messages are sanitized and unknown rules are ignored', async () => {
  const worker = stub(`
    parentPort.postMessage({ type: 'rule', ruleId: 'made.up', outcomes: [{ state: 'finding', ruleId: 'made.up' }] });
    parentPort.postMessage({ type: 'rule', ruleId: 'manifest.debuggable', outcomes: [{ state: 'finding', title: '<img src=x onerror=alert(1)>', evil: 1, severity: 'critical' }, 'junk'] });
    parentPort.postMessage({ type: 'done' });`);
  const rec = await runScan({ dir: entry({}), meta: META, sig: null, worker });
  const f = rec.outcomes.find((o) => o.ruleId === 'manifest.debuggable' && o.state === 'finding');
  assert.equal(f.evil, undefined);
  assert.equal(f.severity, null);
  assert.ok(!rec.outcomes.some((o) => o.ruleId === 'made.up'));
  assert.equal(rec.status, 'partial');                                              // the other rules never reported
  assert.equal(ids(rec, 'error').length, RULES.length - 1);
});

test('decompiler errors in the metadata reach the rules, when the code they read is damaged', async () => {
  const dir = entry({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/A.java': 'class A { /* JADX WARN: Method dump skipped */ }' });
  const rec = await runScan({ dir, meta: { ...META, errors: 2 }, sig: null });
  assert.ok(ids(rec, 'inconclusive').includes('code.trust-all-tls'));
  assert.equal(rec.provenance.decompilePartial, true);
});

test('a fingerprint never depends on the secret', async () => {
  const scanWith = async (secret) => {
    const dir = entry({ 'resources/AndroidManifest.xml': manifest(), [`resources/assets/token=${secret}.pem`]: `-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----`, 'sources/com/x/app/C.java': `class C { String s = "xoxb-1234567890-${secret}"; }` });
    return runScan({ dir, meta: META, sig: null });
  };
  const a = await scanWith('Zx9y8w7v6u'), b = await scanWith('Qq1w2e3r4t');
  for (const [rec, secret] of [[a, 'Zx9y8w7v6u'], [b, 'Qq1w2e3r4t']]) assert.ok(rec.outcomes.every((o) => !String(o.fingerprint).includes(secret)), `${secret} must not be in a fingerprint`);
  const fps = (rec) => rec.outcomes.filter((o) => o.state === 'finding').map((o) => o.fingerprint).sort();
  assert.ok(fps(a).length >= 2);
  assert.deepEqual(fps(a), fps(b));
});
