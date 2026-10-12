// Run: npm test. Exercises /__loupe/analyzer/* against a fake decompile cache entry (no Java or jadx needed).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RULES } from './rules/index.js';

// Under the real home on purpose, like jadx.test.mjs: that is where ~/.loupe lives.
process.env.LOUPE_HOME = fs.mkdtempSync(path.join(os.homedir(), '.loupe-test-'));
const { startProxy } = await import('../server.js');
const { TOKEN } = await import('../auth.js');
const { server } = await startProxy({ port: 0, host: '127.0.0.1' });
const base = `http://localhost:${server.address().port}/__loupe/analyzer`;
test.after(() => { server.close(); fs.rmSync(process.env.LOUPE_HOME, { recursive: true, force: true }); });

const H = { Authorization: `Bearer ${TOKEN}` };
const call = async (p, init = {}) => { const r = await fetch(base + p, { ...init, headers: { ...H, ...init.headers } }); return { status: r.status, body: await r.json().catch(() => null) }; };
const post = (p, body) => call(p, { method: 'POST', body: JSON.stringify(body) });

const ID = 'c'.repeat(64);
const MANIFEST = `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x.app">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
  <application android:debuggable="true"/>
</manifest>`;
function cacheEntry() {
  const dir = path.join(process.env.LOUPE_HOME, 'decompiled', ID);
  fs.mkdirSync(path.join(dir, 'out', 'resources'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'out', 'resources', 'AndroidManifest.xml'), MANIFEST);
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({ id: ID, name: 'x.apk', tool: 'jadx 1.5.0', parts: [{ role: 'base', sha256: 'd'.repeat(64) }], errors: 0, partial: false, createdAt: Date.now() }));
}
async function finished() {
  for (let i = 0; i < 100; i++) { const { body } = await call(`/scan?id=${ID}`); if (body.job && body.job.status !== 'running') return body.job; await new Promise((r) => setTimeout(r, 100)); }
  throw new Error('scan did not finish');
}

test('requires the bridge token', async () => {
  const r = await fetch(`${base}/status`);
  assert.equal(r.status, 401);
});

test('status lists the rules', async () => {
  const { body } = await call('/status');
  assert.equal(body.rules.length, RULES.length);
  assert.ok(body.rules.every((r) => r.id && r.title && r.category));
  assert.match(body.standards, /OWASP/);
});

test('scanning an unknown or malformed id fails cleanly', async () => {
  assert.equal((await post('/scan', { id: ID })).status, 404);
  assert.equal((await post('/scan', { id: '../x' })).status, 400);
  assert.equal((await post('/scan', {})).status, 400);
  assert.equal((await call('/results?id=nope')).status, 400);
});

test('scan and results', async () => {
  cacheEntry();
  const start = await post('/scan', { id: ID });
  assert.equal(start.status, 200);
  const job = await finished();
  assert.equal(job.status, 'complete');
  assert.equal(job.progress.done, job.progress.total);

  const { body } = await call(`/results?id=${ID}`);
  assert.equal(body.scan.status, 'complete');
  const dbg = body.scan.outcomes.find((o) => o.ruleId === 'manifest.debuggable' && o.state === 'finding');
  assert.ok(dbg);
  assert.match(dbg.recommendation, /android:debuggable[\s\S]*\./);                                   // looked up when results are read, so old scans get it too
  assert.equal(body.scan.outcomes.find((o) => o.ruleId === 'signature.verdict').reason, 'tool-unavailable');
});

test('scans stored while an info rating existed read back as low, in results and in the summary', async () => {
  const store = await import('./store.js');
  const { body } = await call(`/results?id=${ID}`);
  const f = body.scan.outcomes.find((o) => o.state === 'finding');
  await store.saveScan({ ...body.scan, outcomes: body.scan.outcomes.map((o) => (o === f ? { ...o, severity: 'info' } : o)) });
  const again = (await call(`/results?id=${ID}`)).body.scan;
  assert.ok(!again.outcomes.some((o) => o.severity === 'info'));
  const row = (await call(`/summary?ids=${ID}`)).body.scans[ID].static;
  assert.equal(row.severity.high + row.severity.medium + row.severity.low, row.findings);
  await store.saveScan(body.scan);
});

test('results survive a rescan with the same fingerprints', async () => {
  const first = (await call(`/results?id=${ID}`)).body.scan.outcomes.filter((o) => o.state === 'finding').map((o) => o.fingerprint).sort();
  await post('/scan', { id: ID });
  await finished();
  const second = (await call(`/results?id=${ID}`)).body.scan.outcomes.filter((o) => o.state === 'finding').map((o) => o.fingerprint).sort();
  assert.deepEqual(second, first);
});

test('plan lists what a session may probe', async () => {
  const dir = path.join(process.env.LOUPE_HOME, 'decompiled', ID, 'out', 'resources');
  fs.writeFileSync(path.join(dir, 'AndroidManifest.xml'), MANIFEST.replace('<application android:debuggable="true"/>', `<application>
    <activity android:name=".Main"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <activity android:name=".Open" android:exported="true"/>
    <activity android:name=".Link" android:exported="true"><intent-filter><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="myapp" android:host="open"/></intent-filter></activity>
    <provider android:name=".P" android:authorities="com.x.prov;b" android:exported="true"/>
  </application>`));
  const srcDir = path.join(process.env.LOUPE_HOME, 'decompiled', ID, 'out', 'sources', 'com', 'x', 'app');
  fs.mkdirSync(srcDir, { recursive: true });
  fs.writeFileSync(path.join(srcDir, 'P.java'), 'class P { static { m.addURI(NAME, "users", 1); m.addURI(NAME, "users/*", 2); m.addURI(NAME, "bad path;", 3); } }');
  const { body } = await call(`/plan?id=${ID}`);
  assert.deepEqual([body.package, body.apkSha256s], ['com.x.app', ['d'.repeat(64)]]);
  assert.deepEqual(body.activities, ['com.x.app.Open', 'com.x.app.Link']);
  assert.deepEqual(body.providers, [{ name: 'com.x.app.P', authority: 'com.x.prov', paths: ['users'], readable: true, writable: true }]);
  assert.deepEqual(body.deeplinks, ['myapp://open/']);
  assert.equal((await call('/plan?id=nope')).status, 400);
});

test('a session upload is analyzed and stored beside the static scan', async () => {
  const recording = { pkg: 'com.x.app', uid: 1, startedAt: Date.now(), caps: { logcat: true }, plan: { readonly: false, changing: false, typed: [] }, pids: [7], logcat: [{ t: 1, pid: 7, level: 'D', tag: 'T', msg: 'password=Secret99x' }], evil: 'x' };
  const up = await post('/session', { id: ID, recording });
  assert.equal(up.status, 200);
  const { body } = await call(`/results?id=${ID}`);
  assert.equal(body.dynamic.mode, 'dynamic');
  assert.ok(body.scan);                                                         // the static scan is still there
  const f = body.dynamic.outcomes.find((o) => o.state === 'finding');
  assert.equal(f.ruleId, 'dyn.logcat-secrets');
  assert.ok(JSON.stringify(body.dynamic).includes('Secret99x'));                 // results show the value as it was logged
  assert.equal(body.dynamic.outcomes.find((o) => o.ruleId === 'dyn.cleartext-connection').reason, 'sockets-unattributable');
  assert.equal((await post('/session', { id: 'nope', recording })).status, 400);
});

test('cancel is harmless when nothing is running', async () => {
  assert.equal((await call(`/scan?id=${ID}`, { method: 'DELETE' })).body.ok, true);
});

test('summary lists the apps that have a stored scan, and ignores unknown ids', async () => {
  const { body } = await call(`/summary?ids=${ID},nope`);
  assert.deepEqual(Object.keys(body.scans), [ID]);                                  // earlier tests stored a scan for this app
  assert.ok(body.scans[ID].static || body.scans[ID].dynamic);
  assert.equal(typeof (body.scans[ID].static || body.scans[ID].dynamic).findings, 'number');
});

test('deleting a result removes that mode only', async () => {
  const before = (await call(`/results?id=${ID}`)).body;
  assert.ok(before.scan && before.dynamic);
  assert.equal((await call(`/results?id=${ID}&mode=dynamic`, { method: 'DELETE' })).status, 200);
  const mid = (await call(`/results?id=${ID}`)).body;
  assert.ok(mid.scan && !mid.dynamic);
  assert.equal((await call(`/results?id=${ID}&mode=static`, { method: 'DELETE' })).status, 200);
  const after = (await call(`/results?id=${ID}`)).body;
  assert.ok(!after.scan && !after.dynamic);
  assert.equal((await call('/results?id=nope', { method: 'DELETE' })).status, 400);
});

test('deleting while a scan runs does not let the cancelled scan save its result afterwards', async () => {
  await post('/scan', { id: ID });
  assert.equal((await call(`/results?id=${ID}&mode=static`, { method: 'DELETE' })).status, 200);
  await new Promise((r) => setTimeout(r, 600));                                          // long enough for any late save to land
  assert.equal((await call(`/results?id=${ID}`)).body.scan, null);
});

test('two decompiles of one APK share one running scan, and delete cancels it', async () => {
  const ID2 = 'e'.repeat(64);
  const src = path.join(process.env.LOUPE_HOME, 'decompiled', ID), dst = path.join(process.env.LOUPE_HOME, 'decompiled', ID2);
  fs.cpSync(src, dst, { recursive: true });
  fs.writeFileSync(path.join(dst, 'meta.json'), JSON.stringify({ ...JSON.parse(fs.readFileSync(path.join(src, 'meta.json'))), id: ID2 }));
  const [a, b] = await Promise.all([post('/scan', { id: ID }), post('/scan', { id: ID2 })]);
  assert.equal(a.body.job.startedAt, b.body.job.startedAt);                                  // the second request got the first one's job
  assert.equal((await call(`/scan?id=${ID2}`)).body.job.startedAt, a.body.job.startedAt);   // and its status follows it
  await call(`/results?id=${ID2}`, { method: 'DELETE' });
  assert.equal((await call(`/results?id=${ID}`)).body.scan, null);
  await finished();
  assert.equal((await call(`/results?id=${ID}`)).body.scan, null);                           // the cancelled scan did not bring the result back
});

test('plan marks a provider whose reads need a permission as not readable, even without android:permission', async () => {
  const dir = path.join(process.env.LOUPE_HOME, 'decompiled', ID, 'out', 'resources');
  fs.writeFileSync(path.join(dir, 'AndroidManifest.xml'), MANIFEST.replace('<application android:debuggable="true"/>', `<application>
    <provider android:name=".R" android:authorities="com.x.r" android:exported="true" android:readPermission="com.x.READ"/>
    <provider android:name=".W" android:authorities="com.x.w" android:exported="true" android:writePermission="com.x.WRITE"/>
  </application>`));
  assert.deepEqual((await call(`/plan?id=${ID}`)).body.providers.map((p) => [p.authority, p.readable, p.writable]), [['com.x.r', false, true], ['com.x.w', true, false]]);                 // each direction is judged on its own permission
});

test('a provider with open reads and a write permission is queried but not written', async () => {
  const dir = path.join(process.env.LOUPE_HOME, 'decompiled', ID, 'out', 'resources');
  fs.writeFileSync(path.join(dir, 'AndroidManifest.xml'), MANIFEST.replace('<application android:debuggable="true"/>', '<application><provider android:name=".R" android:authorities="com.x.r" android:exported="true" android:writePermission="com.x.WRITE"/></application>'));
  assert.deepEqual((await call(`/plan?id=${ID}`)).body.providers.map((p) => [p.authority, p.writable]), [['com.x.r', false]]);
});

test('a cancelled or partial rescan does not replace a complete result', async () => {
  await post('/scan', { id: ID });
  assert.equal((await finished()).status, 'complete');
  await post('/scan', { id: ID });
  await call(`/scan?id=${ID}`, { method: 'DELETE' });                    // cancel at once
  const job = await finished();
  const after = (await call(`/results?id=${ID}`)).body.scan;
  assert.equal(after.status, 'complete');
  assert.ok(job.status === 'cancelled' || job.status === 'complete' || job.status === 'partial');
});

test('summary reports severity counts, status, scan id and artifact for the dashboard', async () => {
  await post('/scan', { id: ID });
  assert.equal((await finished()).status, 'complete');
  const row = (await call(`/summary?ids=${ID}`)).body.scans[ID];
  assert.match(row.artifactId, /^[0-9a-f]{64}$/);
  assert.equal(row.static.status, 'complete');
  assert.match(row.static.scanId, /^[0-9a-f]+$/);
  const f = (await call(`/results?id=${ID}`)).body.scan.outcomes.filter((o) => o.state === 'finding');
  assert.deepEqual(row.static.severity, { high: f.filter((o) => o.severity === 'high').length, medium: f.filter((o) => o.severity === 'medium').length, low: f.filter((o) => o.severity === 'low').length });
  assert.equal(row.static.findings, f.length);
});

test('a provider with guarded reads and open writes is in the plan, marked not readable', async () => {
  const dir = path.join(process.env.LOUPE_HOME, 'decompiled', ID, 'out', 'resources');
  fs.writeFileSync(path.join(dir, 'AndroidManifest.xml'), MANIFEST.replace('<application android:debuggable="true"/>', '<application><provider android:name=".G" android:authorities="com.x.g" android:exported="true" android:readPermission="com.x.READ"/></application>'));
  const { body } = await call(`/plan?id=${ID}`);
  assert.deepEqual(body.providers.map((p) => [p.authority, p.readable, p.writable]), [['com.x.g', false, true]]);
});
