import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { openInput } from './files.js';
import { runAll } from './engine.js';
import { RULES } from './rules/index.js';
import { entry, manifest, zipStored, elf64 } from './testkit.mjs';

const OK_SIG = { verified: true, schemes: { v1: { present: true, verified: true }, v2: { present: true, verified: true } }, signers: [{ subject: 'CN=Release' }], errors: [] };
async function scan(files, { sig = OK_SIG, partial = false, input } = {}) {
  return runAll({ input: input || openInput(entry(files)), sig, partial });
}
const of = (out, id) => out.filter((o) => o.ruleId === id);
const one = (out, id) => { const r = of(out, id); assert.equal(r.length, 1, `${id} should have one outcome`); return r[0]; };

test('every rule reports at least one outcome', async () => {
  const out = await scan({ 'resources/AndroidManifest.xml': manifest() });
  for (const r of RULES) assert.ok(of(out, r.id).length >= 1, r.id);
});

test('debuggable and backup', async () => {
  const bad = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:debuggable="true" android:allowBackup="true"' }) });
  const d = one(bad, 'manifest.debuggable');
  assert.deepEqual([d.state, d.severity, d.detection], ['finding', 'high', 'exact']);
  assert.equal(d.evidence[0].ref.path, 'resources/AndroidManifest.xml');
  assert.match(d.evidence[0].excerpt, /debuggable="true"/);
  assert.deepEqual(d.repro.command, ['adb', 'shell', 'run-as', 'com.x.app', 'id']);
  assert.equal(one(bad, 'manifest.backup').severity, 'medium');                      // debuggable keeps adb backup open
  const ok = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:allowBackup="false"' }) });
  assert.equal(one(ok, 'manifest.debuggable').state, 'checked');
  assert.equal(one(ok, 'manifest.backup').state, 'checked');
});

test('backup severity follows the target SDK', async () => {
  const modern = await scan({ 'resources/AndroidManifest.xml': manifest({ app: '' }) });         // targetSdk 33, allowBackup default true
  assert.equal(one(modern, 'manifest.backup').severity, 'low');
  const old = await scan({ 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:targetSdkVersion="28"/>' }) });
  assert.equal(one(old, 'manifest.backup').severity, 'medium');
});

test('exported components, providers and weak permissions', async () => {
  const body = `
    <activity android:name=".Main"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <activity android:name=".Open" android:exported="true"/>
    <activity android:name=".Link" android:exported="true"><intent-filter><category android:name="android.intent.category.BROWSABLE"/></intent-filter></activity>
    <service android:name=".Safe" android:exported="true" android:permission="com.x.SIG"/>
    <service android:name=".Weak" android:exported="true" android:permission="com.x.WEAK"/>
    <receiver android:name=".Hidden" android:exported="false"/>
    <provider android:name=".Prov" android:authorities="com.x.prov" android:exported="true"/>`;
  const top = '<permission android:name="com.x.SIG" android:protectionLevel="signature"/><permission android:name="com.x.WEAK" android:protectionLevel="normal"/>';
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ body, top }) });
  const comps = of(out, 'manifest.exported-components');
  assert.deepEqual(comps.map((c) => c.title.split(': ')[1]).sort(), ['Link', 'Open']);
  assert.equal(comps.find((c) => /Link/.test(c.title)).severity, 'low');
  assert.deepEqual(comps.find((c) => /Open/.test(c.title)).repro.command, ['adb', 'shell', 'am', 'start', '-n', 'com.x.app/com.x.app.Open']);
  const prov = one(out, 'manifest.exported-provider');
  assert.deepEqual([prov.severity, prov.repro.command.at(-1)], ['high', 'content://com.x.prov']);
  const weak = one(out, 'manifest.weak-permission');
  assert.match(weak.title, /Weak/);
});

test('a hostile component name never becomes a command argument', async () => {
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ body: '<activity android:name="x; rm -rf /" android:exported="true"/>' }) });
  assert.deepEqual(one(out, 'manifest.exported-components').repro.command, []);
});

test('cleartext resolves the platform default, the config and the domain exceptions', async () => {
  const old = await scan({ 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:targetSdkVersion="22"/>' }) });
  assert.equal(one(old, 'network.cleartext').state, 'finding');
  const modern = await scan({ 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:targetSdkVersion="30"/>' }) });
  assert.equal(one(modern, 'network.cleartext').state, 'checked');
  const attr = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:usesCleartextTraffic="true"', sdk: '<uses-sdk android:targetSdkVersion="30"/>' }) });
  assert.equal(one(attr, 'network.cleartext').state, 'finding');
  const nsc = (inner) => ({ 'resources/AndroidManifest.xml': manifest({ app: 'android:networkSecurityConfig="@xml/nsc"', sdk: '<uses-sdk android:targetSdkVersion="22"/>' }), 'resources/res/xml/nsc.xml': `<network-security-config>${inner}</network-security-config>` });
  const blocked = await scan(nsc('<base-config cleartextTrafficPermitted="false"/>'));
  assert.equal(one(blocked, 'network.cleartext').state, 'checked');
  const domain = await scan(nsc('<base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="true"><domain>a.example</domain></domain-config>'));
  const dom = one(domain, 'network.cleartext');
  assert.deepEqual([dom.state, dom.severity], ['finding', 'low']);
});

test('a missing or broken network security config is inconclusive, not clean', async () => {
  const mf = manifest({ app: 'android:networkSecurityConfig="@xml/gone"' });
  assert.equal(one(await scan({ 'resources/AndroidManifest.xml': mf }), 'network.cleartext').state, 'inconclusive');
  const broken = await scan({ 'resources/AndroidManifest.xml': mf, 'resources/res/xml/gone.xml': '<network-security-config>' });
  assert.equal(one(broken, 'network.user-ca').state, 'inconclusive');
});

test('user CA trust: explicit config, old target SDK, and the safe default', async () => {
  const mf = (t) => manifest({ app: 'android:networkSecurityConfig="@xml/nsc"', sdk: `<uses-sdk android:targetSdkVersion="${t}"/>` });
  const user = await scan({ 'resources/AndroidManifest.xml': mf(30), 'resources/res/xml/nsc.xml': '<network-security-config><base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>' });
  assert.equal(one(user, 'network.user-ca').severity, 'low');
  const debugOnly = await scan({ 'resources/AndroidManifest.xml': mf(30), 'resources/res/xml/nsc.xml': '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>' });
  assert.equal(one(debugOnly, 'network.user-ca').state, 'checked');
  const old = await scan({ 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:targetSdkVersion="23"/>' }) });
  assert.equal(one(old, 'network.user-ca').severity, 'low');
  assert.equal(one(await scan({ 'resources/AndroidManifest.xml': manifest() }), 'network.user-ca').state, 'checked');
});

test('signature verdict', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:minSdkVersion="21"/>' }) };
  const v1 = { verified: true, schemes: { v1: { present: true, verified: true } }, signers: [{ subject: 'CN=Release' }], errors: [] };
  assert.match(one(await scan(files, { sig: v1 }), 'signature.verdict').title, /v1/);
  assert.equal(one(await scan(files, { sig: OK_SIG }), 'signature.verdict').state, 'checked');
  const debug = of(await scan(files, { sig: { ...OK_SIG, signers: [{ subject: 'CN=Android Debug, O=Android' }] } }), 'signature.verdict');
  assert.deepEqual(debug.map((o) => [o.title, o.severity]), [['Signed with a debug certificate', 'low']]);
  assert.ok(!/anyone can sign/i.test(debug[0].summary));
  const bad = one(await scan(files, { sig: { ...OK_SIG, verified: false, errors: ['DIGEST_MISMATCH'] } }), 'signature.verdict');
  assert.deepEqual([bad.severity, /DIGEST_MISMATCH/.test(bad.evidence[0].excerpt)], ['high', true]);
  const none = one(await scan(files, { sig: { error: 'the Java toolchain is not installed' } }), 'signature.verdict');
  assert.deepEqual([none.state, none.reason], ['not_tested', 'tool-unavailable']);
});

test('secrets are found and shown in the evidence, and a bare PEM marker is not a key', async () => {
  const key = 'AKIA' + 'ABCDEFGHIJKLMNOP', secret = 'abcdefghijklmnopqrstuvwxyz' + '0123456789ABCD';
  const out = await scan({
    'resources/AndroidManifest.xml': manifest(),
    'sources/com/x/app/Cfg.java': `class Cfg { String id = "${key}"; String s = "${secret}"; String slack = "xoxb-1234567890-abcdefghij"; }`,
    'resources/assets/k.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAyZk3JQmN8wX5vP0rTq2LhGfDsA9bUcVnXeYiKoMl7PzHtRw1\n-----END RSA PRIVATE KEY-----'
  });
  const f = of(out, 'secrets.private-material');
  assert.deepEqual(f.map((x) => x.title.split(' in ')[0]).sort(), ['AWS secret access key', 'Private key', 'Slack token']);
  const all = JSON.stringify(f);
  assert.ok(all.includes(secret) && all.includes('xoxb-1234567890-abcdefghij') && all.includes('MIIEowIBAAKCAQEA'));
  assert.ok(f.every((x) => x.severity === 'high'));
  const marker = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/K.java': 'class K { String s(String k) { return k.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", ""); } }' });
  assert.equal(of(marker, 'secrets.private-material').filter((o) => o.state === 'finding').length, 0);          // code that strips the markers holds no key
});

test('trust-all TLS: app code is high, library code is low', async () => {
  const empty = 'class T implements X509TrustManager { public void checkServerTrusted(X509Certificate[] c, String s) throws CertificateException {\n    } }';
  const out = await scan({
    'resources/AndroidManifest.xml': manifest(),
    'sources/com/x/app/Trust.java': empty,
    'sources/org/lib/Trust.java': empty,
    'sources/com/x/app/Host.java': 'class H { boolean verify(String h, SSLSession s) { return true; } }'
  });
  const f = of(out, 'code.trust-all-tls');
  assert.equal(f.length, 3);
  assert.deepEqual(f.map((x) => x.severity).sort(), ['high', 'high', 'low']);
});

test('an inverted debug guard is still reported', async () => {
  const out = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/N.java': 'class N { void f() { if (!BuildConfig.DEBUG) { WebView.setWebContentsDebuggingEnabled(true); } } }' });
  assert.equal(of(out, 'code.webview-debugging').length, 1);
});

test('webview debugging is skipped when a debug check guards it', async () => {
  const out = await scan({
    'resources/AndroidManifest.xml': manifest(),
    'sources/com/x/app/A.java': 'class A { void f() { WebView.setWebContentsDebuggingEnabled(true); } }',
    'sources/com/x/app/B.java': 'class B { void f() { if (BuildConfig.DEBUG) { WebView.setWebContentsDebuggingEnabled(true); } } }'
  });
  assert.deepEqual(of(out, 'code.webview-debugging').map((o) => o.evidence[0].ref.path), ['sources/com/x/app/A.java']);
  assert.equal(of(out, 'code.webview-debugging')[0].evidence[0].ref.hitLine, 1);
});

test('damaged files turn clean code checks into inconclusive, and leave manifest checks and undamaged code alone', async () => {
  const bad = { 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/A.java': 'class A { /* JADX WARN: Code restructure failed: missing block */ }' };
  const out = await scan(bad, { partial: true });
  assert.equal(one(out, 'code.trust-all-tls').state, 'inconclusive');
  assert.equal(one(out, 'manifest.debuggable').state, 'checked');
  const fine = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/A.java': 'class A {}', 'sources/okio/B.java': '/* JADX WARN: Code restructure failed */' }, { partial: true });
  assert.equal(one(fine, 'code.sensitive-logging').state, 'checked');                                  // the damage is in a library the rule skips
});

test('a spent scan budget is inconclusive, never checked', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest(), ...Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`sources/com/x/app/F${i}.java`, 'class F {}'])) };
  const out = await scan(files, { input: openInput(entry(files), { maxFiles: 5 }) });
  assert.equal(one(out, 'code.trust-all-tls').state, 'inconclusive');
});

test('an oversized source file makes a clean code check inconclusive', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/Big.java': 'x'.repeat(200), 'sources/com/x/app/Ok.java': 'class Ok {}' };
  const out = await scan(files, { input: openInput(entry(files), { maxFileBytes: 100 }) });
  const r = one(out, 'code.trust-all-tls');
  assert.equal(r.state, 'inconclusive');
  assert.match(r.reason, /too large or unreadable/);
});

test('an unreadable source directory makes a clean code check inconclusive', async () => {
  const dir = entry({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/Ok.java': 'class Ok {}', 'sources/hidden/H.java': 'class H {}' });
  fs.chmodSync(path.join(dir, 'out/sources/hidden'), 0o000);
  try { assert.equal(one(await scan({}, { input: openInput(dir) }), 'code.trust-all-tls').state, 'inconclusive'); }
  finally { fs.chmodSync(path.join(dir, 'out/sources/hidden'), 0o755); }
});

test('missing inputs are reported as not tested with a reason', async () => {
  const out = await scan({ 'sources/A.java': 'class A {}' });
  const m = one(out, 'manifest.debuggable');
  assert.deepEqual([m.state, m.reason], ['not_tested', 'manifest-unreadable']);
  const out2 = await scan({ 'resources/AndroidManifest.xml': manifest() });
  assert.equal(one(out2, 'code.trust-all-tls').reason, 'no-sources');
  assert.equal(one(out2, 'native.hardening').reason, 'apk-missing');
});

test('a rule that throws becomes an error outcome and the scan carries on', async () => {
  const bad = RULES.find((r) => r.id === 'manifest.backup');
  const run = bad.run; bad.run = () => { throw new Error('boom'); };
  try {
    const out = await scan({ 'resources/AndroidManifest.xml': manifest() });
    assert.deepEqual([one(out, 'manifest.backup').state, one(out, 'manifest.backup').reason], ['error', 'boom']);
    assert.equal(one(out, 'manifest.debuggable').state, 'checked');
  } finally { bad.run = run; }
});

test('fingerprints survive line shifts', async () => {
  const body = '<activity android:name=".Open" android:exported="true"/>';
  const a = await scan({ 'resources/AndroidManifest.xml': manifest({ body }) });
  const b = await scan({ 'resources/AndroidManifest.xml': '\n\n<!-- shifted -->\n' + manifest({ body }).replace('<?xml version="1.0" encoding="utf-8"?>\n', '') });
  assert.equal(one(a, 'manifest.exported-components').fingerprint, one(b, 'manifest.exported-components').fingerprint);
  assert.notEqual(one(a, 'manifest.exported-components').evidence[0].ref.startLine, one(b, 'manifest.exported-components').evidence[0].ref.startLine);
});

test('native hardening: weak libraries are flagged, hardened ones and APKs without libraries are not', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest() };
  const apk = zipStored({ 'lib/arm64-v8a/weak.so': elf64({ stackFlags: 7, relro: false, bindNow: false, canary: false }), 'lib/arm64-v8a/good.so': elf64(), 'lib/arm64-v8a/notelf.so': 'junk', 'classes.dex': 'x' });
  const out = await scan(files, { input: openInput(entry(files, apk)) });
  const f = of(out, 'native.hardening').filter((o) => o.state === 'finding');
  assert.deepEqual(f.map((o) => o.evidence[0].ref.path), ['lib/arm64-v8a/weak.so']);
  assert.ok(of(out, 'native.hardening').some((o) => o.state === 'inconclusive'));                       // the unparsable library is a gap, and the finding does not hide it
  assert.match(f[0].title, /non-executable stack/);
  assert.equal(f[0].severity, 'low');
  const none = await scan(files, { input: openInput(entry(files, zipStored({ 'classes.dex': 'x' }))) });
  assert.equal(one(none, 'native.hardening').state, 'not_applicable');
});

test('native hardening: a weak library after many hardened ones is still found, and unparsable or surplus libraries are inconclusive', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest() };
  const many = Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`lib/arm64-v8a/h${i}.so`, elf64()]));
  const late = await scan(files, { input: openInput(entry(files, zipStored({ ...many, 'lib/arm64-v8a/zweak.so': elf64({ stackFlags: 7, relro: false, bindNow: false, canary: false }) }))) });
  assert.deepEqual(of(late, 'native.hardening').map((o) => o.evidence[0].ref.path), ['lib/arm64-v8a/zweak.so']);
  const junk = await scan(files, { input: openInput(entry(files, zipStored({ 'lib/arm64-v8a/a.so': elf64(), 'lib/arm64-v8a/b.so': 'junk' }))) });
  assert.equal(one(junk, 'native.hardening').state, 'inconclusive');
  const surplus = await scan(files, { input: openInput(entry(files, zipStored(Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`lib/arm64-v8a/h${i}.so`, elf64()]))))) });
  assert.equal(one(surplus, 'native.hardening').state, 'inconclusive');
});

test('app-code rules: backdoor, crypto, WebView, URLs, logs; libraries and the key value stay out', async () => {
  const app = 'sources/com/x/app/';
  const out = await scan({
    'resources/AndroidManifest.xml': manifest(),
    [`${app}A.java`]: 'class A { String key = "SuperSecretKey123"; byte[] iv = {0, 0, 0, 0}; void f(String username, String password) { if (username.equals("devadmin")) {} Log.d("t", "pw=" + password); String u = "http://api.example.com/x"; w.loadUrl("file://" + Environment.getExternalStorageDirectory()); w.getSettings().setJavaScriptEnabled(true); Cipher.getInstance("AES/CBC/PKCS5Padding"); } }',
    'sources/androidx/lib/B.java': 'class B { void f(String username) { username.equals("libadmin"); Log.d("t", "password"); } }'
  });
  const ids = out.filter((o) => o.state === 'finding').map((o) => o.ruleId);
  for (const id of ['code.hardcoded-credential', 'code.weak-crypto', 'code.webview-js-local', 'code.cleartext-url', 'code.sensitive-logging', 'code.external-storage', 'code.no-tamper-check']) assert.ok(ids.includes(id), id);
  assert.ok(JSON.stringify(out).includes('SuperSecretKey123') && !JSON.stringify(out).includes('libadmin'));       // shown as in the code; the library is skipped
  assert.equal(of(out, 'code.webview-js-local').find((o) => o.state === 'finding').severity, 'high');
});

test('rules ported from other scanners: positives, and the negatives that matter', async () => {
  const app = 'sources/com/x/app/';
  const bad = await scan({
    'resources/AndroidManifest.xml': manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/network_security_config"' }).replace('</application>', '<activity android:name=".A" android:taskAffinity="com.evil" android:exported="false"/><provider android:name=".P" android:authorities="a.b" android:exported="false" android:grantUriPermissions="true"/><meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false"/></application>'),
    'resources/res/xml/paths.xml': '<paths><root-path name="r" path=""/></paths>',
    'resources/res/xml/network_security_config.xml': '<network-security-config><domain-config><domain>a.com</domain><pin-set expiration="2020-01-01"><pin digest="SHA-256">x</pin></pin-set></domain-config></network-security-config>',
    [`${app}A.java`]: 'class A { void f(Context c, WebView w, Cursor q, SQLiteDatabase db, String id, ZipEntry e) { c.openFileOutput("f", Context.MODE_WORLD_READABLE); w.addJavascriptInterface(o, "x"); w.getSettings().setAllowUniversalAccessFromFileURLs(true); String token = "" + new Random().nextLong(); prefs.edit().putString("auth_token", t); new DexClassLoader(p, o, null, l); PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_MUTABLE); db.rawQuery("select * from t where id=" + id, null); File out = new File(dir, e.getName()); SSLContext.getInstance("SSLv3"); k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES"); } public void onReceivedSslError(WebView v, SslErrorHandler h, SslError er) { h.proceed(); } }',
    [`${app}Cfg.java`]: 'class Cfg { String a = "AIzaSyA1234567890abcdefghijklmnopqrstuv"; String u = "ftp://files.example.com/x"; String b = "https://user:hunter2pw@api.example.com/";\n k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES"); }'
  });
  const hit = (id) => of(bad, id).some((o) => o.state === 'finding');
  for (const id of ['manifest.task-affinity', 'manifest.grant-uri', 'manifest.safe-browsing-off', 'manifest.sdk-levels', 'network.expired-pins', 'code.fileprovider-root', 'code.world-readable-file', 'code.webview-settings', 'code.insecure-random', 'code.plaintext-token-prefs', 'code.dynamic-execution', 'code.intent-safety', 'code.sql-concatenation', 'code.zip-slip', 'code.legacy-tls', 'code.trust-all-tls', 'code.weak-crypto', 'code.cleartext-url', 'secrets.private-material']) assert.ok(hit(id), id);
  const all = JSON.stringify(bad);
  assert.ok(all.includes('AIzaSyA1234567890abcdefghijklmnopqrstuv') && all.includes('hunter2pw') && all.includes('0123456789abcdef'));
  const ok = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}A.java`]: 'class A { void f(ZipEntry e, File d) throws Exception { File out = new File(d, e.getName()); if (!out.getCanonicalPath().startsWith(d.getCanonicalPath())) throw new Exception(); SecureRandom r = new SecureRandom(); } }' });
  for (const id of ['code.zip-slip', 'code.insecure-random', 'code.world-readable-file']) assert.equal(one(ok, id).state, 'checked', id);
});

test('app code under any package is scanned, only well-known libraries are pruned, and finding no classes is inconclusive', async () => {
  const out = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/Harmless.java': 'class Harmless {}', 'sources/org/other/ui/Main.java': 'class Main { void f() { Log.d("t", "password=" + password); } }' });
  assert.equal(of(out, 'code.sensitive-logging').filter((o) => o.state === 'finding').length, 1);          // not the manifest package, still scanned
  const none = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/androidx/lib/L.java': 'class L {}' });
  for (const id of ['code.sensitive-logging', 'code.weak-crypto', 'code.no-tamper-check', 'code.no-flag-secure']) assert.equal(one(none, id).state, 'inconclusive', id);
});

test('native libraries and signatures in split APKs are examined', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest() };
  const dir = entry(files, zipStored({ 'classes.dex': 'x' }));
  fs.writeFileSync(path.join(dir, 'in', 'split-1.apk'), zipStored({ 'lib/arm64-v8a/weak.so': elf64({ stackFlags: 7, relro: false, bindNow: false, canary: false }) }));
  const f = of(await scan(files, { input: openInput(dir) }), 'native.hardening');
  assert.deepEqual(f.map((o) => o.evidence[0].ref.path), ['split-1.apk!lib/arm64-v8a/weak.so']);
  fs.writeFileSync(path.join(dir, 'in', 'split-2.apk'), 'not a zip');
  const out = await scan(files, { input: openInput(dir) });
  assert.deepEqual(of(out, 'native.hardening').map((o) => o.state).sort(), ['finding', 'inconclusive']);          // the finding stands, and the unreadable part is reported next to it
  const lone = entry(files, zipStored({ 'classes.dex': 'x' }));
  fs.writeFileSync(path.join(lone, 'in', 'split-1.apk'), 'not a zip');
  assert.equal(one(await scan(files, { input: openInput(lone) }), 'native.hardening').state, 'inconclusive');
  const signed = (splits) => scan(files, { sig: { ...OK_SIG, splits } });
  assert.equal(of(await signed([{ file: 'split-1.apk', ...OK_SIG, verified: false }]), 'signature.verdict').some((o) => /does not verify/.test(o.title)), true);
  assert.equal(of(await signed([{ file: 'split-1.apk', ...OK_SIG, signers: [{ subject: 'CN=Other' }] }]), 'signature.verdict').some((o) => /different certificate/.test(o.title)), true);
  assert.equal(one(await signed([{ file: 'split-1.apk', error: 'timed out' }]), 'signature.verdict').state, 'inconclusive');
  assert.equal(one(await signed([{ file: 'split-1.apk', ...OK_SIG }]), 'signature.verdict').state, 'checked');
});

test('a network security config with resource-qualified variants is inconclusive', async () => {
  const app = 'android:networkSecurityConfig="@xml/nsc"';
  const cfg = '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>';
  const base = { 'resources/AndroidManifest.xml': manifest({ app }), 'resources/res/xml/nsc.xml': cfg };
  assert.equal(one(await scan(base), 'network.cleartext').state, 'checked');
  const out = await scan({ ...base, 'resources/res/xml-v24/nsc.xml': cfg.replace('false', 'true') });
  for (const id of ['network.cleartext', 'network.user-ca', 'network.expired-pins']) { assert.equal(one(out, id).state, 'inconclusive', id); assert.match(one(out, id).reason, /resource-qualified variants/); }
});

test('weak permissions: platform normal permissions, provider directions, signature and unknown ones', async () => {
  const body = [
    '<activity android:name=".Net" android:exported="true" android:permission="android.permission.INTERNET"/>',
    '<service android:name=".Bind" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE"/>',
    '<provider android:name=".P" android:authorities="a.p" android:exported="true" android:readPermission="com.x.app.SIG" android:writePermission="android.permission.VIBRATE"/>'
  ].join('');
  const top = '<permission android:name="com.x.app.SIG" android:protectionLevel="signature"/>';
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ body, top }) });
  const t = of(out, 'manifest.weak-permission').filter((o) => o.state === 'finding').map((o) => o.title).sort();
  assert.deepEqual(t, ['Weak permission on Net', 'Weak permission on P']);                       // BIND_* and the signature read permission are fine; the write side is not
  const unknown = await scan({ 'resources/AndroidManifest.xml': manifest({ body: '<activity android:name=".U" android:exported="true" android:permission="com.other.PERM"/>' }) });
  assert.equal(one(unknown, 'manifest.weak-permission').state, 'inconclusive');
});

test('rules ported from apkAnalyzer: deep links, backup rules, permission use, broadcasts, clipboard, FLAG_SECURE, keyboard cache', async () => {
  const app = 'sources/com/x/app/';
  const body = '<activity android:name=".L" android:exported="true"><intent-filter><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="myapp" android:host="*.x.com"/></intent-filter></activity>';
  const top = '<uses-permission android:name="android.permission.READ_CONTACTS"/><uses-permission android:name="android.permission.CAMERA"/>';
  const bad = await scan({
    'resources/AndroidManifest.xml': manifest({ body, top, app: 'android:fullBackupContent="@xml/bk"' }),
    'resources/res/xml/bk.xml': '<full-backup-content><exclude domain="database" path="."/></full-backup-content>',
    'resources/res/layout/a.xml': '<LinearLayout><EditText android:id="@+id/pin_field" android:inputType="number"/><EditText android:id="@+id/pw" android:inputType="textPassword"/><EditText android:id="@+id/name"/></LinearLayout>',
    [`${app}A.java`]: 'class A { void f(Context c, Intent i) { c.sendBroadcast(i); c.sendBroadcast(i, "com.x.PERM"); LocalBroadcastManager.getInstance(c).sendBroadcast(i); cm.setPrimaryClip(clip); PendingIntent.getActivity(c, 0, i, 0); Camera cam = android.hardware.Camera.open(); } }'
  });
  const titles = (id) => of(bad, id).filter((o) => o.state === 'finding').map((o) => o.title);
  assert.equal(titles('manifest.deeplinks').length, 1);
  assert.equal(of(bad, 'manifest.deeplinks').find((o) => o.state === 'finding').severity, 'medium');            // wildcard host
  assert.match(one(bad, 'manifest.backup').summary, /still back up: full-backup-content: sharedpref/);
  assert.deepEqual(titles('code.unused-permissions'), ['Declared but no matching API found: READ_CONTACTS']);   // CAMERA is used
  assert.equal(titles('code.intent-safety').filter((t) => /Broadcast sent/.test(t)).length, 1);               // not the two-argument form, not the local one
  assert.ok(titles('code.intent-safety').some((t) => /without a mutability flag/.test(t)));
  assert.equal(titles('code.clipboard-write').length, 1);
  assert.equal(titles('code.no-flag-secure').length, 1);
  assert.equal(titles('code.keyboard-cache').length, 1);                                                      // the PIN field only
  const ok = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:fullBackupContent="@xml/bk"' }), 'resources/res/xml/bk.xml': '<full-backup-content><exclude domain="database"/><exclude domain="sharedpref"/></full-backup-content>', [`${app}A.java`]: 'class A { void f(Activity a) { a.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, 1); } }' });
  assert.equal(of(ok, 'code.no-flag-secure').filter((o) => o.state === 'finding').length, 0);
  assert.equal(one(ok, 'manifest.backup').severity, 'low');
});

test('backup rules are read per context: domains are independent, includes are allowlists, cloud and device transfer differ', async () => {
  const run = async (xml, attr = 'fullBackupContent') => one(await scan({ 'resources/AndroidManifest.xml': manifest({ app: `android:${attr}="@xml/bk"` }), 'resources/res/xml/bk.xml': xml }), 'manifest.backup');
  const root = await run('<full-backup-content><exclude domain="root"/></full-backup-content>');
  assert.match(root.summary, /sharedpref, database/);                                                         // excluding root does not exclude the others
  const allow = await run('<full-backup-content><include domain="file" path="keep"/></full-backup-content>');
  assert.equal(allow.severity, 'low');                                                                        // an allowlist that names neither domain leaves both out
  const some = await run('<full-backup-content><exclude domain="sharedpref" path="a.xml"/><exclude domain="database"/></full-backup-content>');
  assert.match(some.summary, /sharedpref \(only some paths excluded\)/);
  const split = await run('<data-extraction-rules><cloud-backup><exclude domain="sharedpref"/><exclude domain="database"/></cloud-backup></data-extraction-rules>', 'dataExtractionRules');
  assert.match(split.summary, /device-transfer: sharedpref, database/);                                       // the missing section backs everything up
  assert.equal(split.severity, 'medium');
  const bad = await run('<not-backup/>');
  assert.match(bad.summary, /could not be read or understood/);
});

test('data elements of one intent filter are combined, as Android does', async () => {
  const body = '<activity android:name=".L" android:exported="true"><intent-filter><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https"/><data android:host="*.x.com"/><data android:pathPrefix="/a"/></intent-filter></activity>';
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ body }) });
  const f = of(out, 'manifest.deeplinks').find((o) => o.state === 'finding');
  assert.ok(f && f.severity === 'medium' && /wildcard host/.test(f.summary));
});

test('absence claims need a complete decompile, a status code is not a credential, and the file budget is per rule', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest({ top: '<uses-permission android:name="android.permission.CAMERA"/>' }), 'sources/com/x/app/A.java': 'class A { void f(String dupulicateLoginCode) { if (dupulicateLoginCode.equals("900")) {} } }' };
  const partial = await scan({ ...files, 'sources/com/x/app/B.java': 'class B { /* JADX WARN: Method dump skipped */ }' }, { partial: true });
  for (const id of ['code.unused-permissions', 'code.no-tamper-check', 'code.no-flag-secure']) assert.equal(one(partial, id).state, 'inconclusive', id);
  const full = await scan(files);
  assert.equal(of(full, 'code.unused-permissions').filter((o) => o.state === 'finding').length, 1);
  assert.equal(of(full, 'code.hardcoded-credential').filter((o) => o.state === 'finding').length, 0);          // "LoginCode" is not a login
  const many = { 'resources/AndroidManifest.xml': manifest() };
  for (let i = 0; i < 30; i++) many[`sources/com/x/app/C${i}.java`] = `class C${i} { void f() { Log.d("t", "password=" + password); } }`;
  const input = openInput(entry(many), { maxFiles: 40 });                                                         // far less than 40 files x 40 rules
  const out = await scan(many, { input });
  assert.ok(of(out, 'code.sensitive-logging').some((o) => o.state === 'finding'));
  assert.equal(of(out, 'code.world-readable-file')[0].state, 'checked');                                           // a late rule still got its whole budget
});

test('hardcoded values by name and key-shaped constants in dex and native strings', async () => {
  const dex = Buffer.concat([Buffer.from('\u0000\u0000zero'), Buffer.from('\u0000q3Zs9Fh2Lk8Xw1Rt5Yp7Nb4Vc6Mx0A=\u0000'), Buffer.from('Lcom/example/ui/ViewHolder;\u0000'), Buffer.from('7a5b85d3ee2e0991ca3502602e9389a98f55c0576b887125894a7ec03823f8d3')]);
  const files = {
    'resources/AndroidManifest.xml': manifest(),
    'resources/res/values/strings.xml': '<resources><string name="api_secret">kJ8dh38DJ2kd93JdQ</string><string name="password_hint">Enter your password</string><string name="label_password">Password:</string></resources>',
    'resources/res/values-fr/strings.xml': '<resources><string name="api_secret">kJ8dh38DJ2kd93JdQ</string></resources>',
    'sources/com/x/app/K.java': 'class K { String clientSecret = "Zq9!x7Lm2Pw4Rt6Y"; String passwordPattern = "[A-Za-z0-9]{8,}"; String tokenType = "bearer"; }',
    'sources/androidx/lib/L.java': 'class L { String secretKey = "Zq9!x7Lm2Pw4Rt6Y"; }'
  };
  const out = await scan(files, { input: openInput(entry(files, zipStored({ 'classes.dex': dex }))) });
  const t = of(out, 'secrets.hardcoded-values').filter((o) => o.state === 'finding').map((o) => o.title.split(' = ')[0]).sort();
  assert.deepEqual(t, ['api_secret', 'clientSecret']);                      // not the hint, the label, the pattern, the type, the translation or the library
  const b = of(out, 'secrets.binary-strings').filter((o) => o.state === 'finding').map((o) => o.title.split(' in ')[0]).sort();
  assert.deepEqual(b, ['Base64 key-sized value', 'Hex key-sized value']);   // not the class descriptor
  assert.match(JSON.stringify(of(out, 'secrets.binary-strings')), /q3Zs9Fh2Lk8Xw1Rt5Yp7Nb4Vc6Mx0A=/);
});

test('rules from the OVAA comparison: real file-URL setting names, provider traversal, deserialization, host checks, result Uris, URL secrets', async () => {
  const app = 'sources/com/x/app/';
  const bad = await scan({
    'resources/AndroidManifest.xml': manifest(),
    [`${app}W.java`]: 'class W { void f(WebView w) { w.getSettings().setAllowFileAccessFromFileURLs(true); w.getSettings().setAllowUniversalAccessFromFileURLs(true); } }',
    [`${app}P.java`]: 'class P extends ContentProvider { ParcelFileDescriptor openFile(Uri uri, String m) { File f = new File(Environment.getExternalStorageDirectory(), uri.getLastPathSegment()); return null; } }',
    [`${app}D.java`]: 'class D implements Serializable { private void readObject(ObjectInputStream in) { File f = new File(in.readUTF()); f.delete(); } }',
    [`${app}Q.java`]: 'class Q implements Parcelable { Q(Parcel p) { Class c = Class.forName(p.readString()); } }',
    [`${app}H.java`]: 'class H { void f(String url) { String host = Uri.parse(url).getHost(); if (host != null && host.endsWith("example.com")) {} } }',
    [`${app}R.java`]: 'class R { void onActivityResult(int a, int b, Intent data) { FileUtils.copyToCache(this, data.getData()); } void g(String t) { String u = "http://e.com/?token=" + t; } }',
    [`${app}S.java`]: 'class S implements Serializable {\n  private long ptr;\n  private native void free(long p);\n  transient long other;\n}'
  });
  const has = (id, re) => of(bad, id).some((o) => o.state === 'finding' && re.test(o.title));
  assert.ok(has('code.webview-settings', /file URLs/));
  assert.ok(has('code.path-traversal', /Uri path/) && has('code.unsafe-deserialization', /readObject/) && has('code.unsafe-deserialization', /Class chosen/));
  assert.ok(has('code.weak-host-check', /Host checked/) && has('code.untrusted-result-uri', /Result Uri/) && has('code.secret-in-url', /query string/) && has('code.serializable-native-pointer', /Native pointer/));
  const ok = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}P.java`]: 'class P extends ContentProvider { ParcelFileDescriptor openFile(Uri uri, String m) { File f = new File(base, uri.getLastPathSegment()); if (!f.getCanonicalPath().startsWith(base.getCanonicalPath())) throw new Exception(); return null; } }' });
  assert.equal(of(ok, 'code.path-traversal').filter((o) => o.state === 'finding').length, 0);
});

test('review fixes: damage means inconclusive whatever the metadata says, validation is per sink, native pointers need a free method, binary fingerprints ignore the value', async () => {
  const app = 'sources/com/x/app/';
  const dmg = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}A.java`]: 'class A { /* JADX WARN: Code restructure failed */ }' }, { partial: false });
  assert.equal(one(dmg, 'code.sensitive-logging').state, 'inconclusive');
  const both = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}P.java`]: `class P extends ContentProvider {\n  File a(Uri u) { File f = new File(base, u.getLastPathSegment()); if (!f.getCanonicalPath().startsWith(base.getCanonicalPath())) throw new X(); return f; }\n${'  // padding\\n'.repeat(60)}  File b(Uri u) { return new File(base, u.getPath()); }\n}` });
  assert.equal(of(both, 'code.path-traversal').filter((o) => o.state === 'finding').length, 1);              // the unvalidated sink, not hidden by the validated one
  const ptr = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}M.java`]: 'class M implements Serializable {\n  private long handle;\n  native void render();\n}' });
  assert.equal(of(ptr, 'code.serializable-native-pointer').filter((o) => o.state === 'finding').length, 0);   // JNI code, but nothing that frees
  const fp = async (key) => {
    const dex = Buffer.from(`\u0000${key}\u0000`);
    const files = { 'resources/AndroidManifest.xml': manifest() };
    return of(await scan(files, { input: openInput(entry(files, zipStored({ 'classes.dex': dex }))) }), 'secrets.binary-strings').filter((o) => o.state === 'finding').map((o) => o.fingerprint);
  };
  const a = await fp('q3Zs9Fh2Lk8Xw1Rt5Yp7Nb4Vc6Mx0A='), b = await fp('Zq8Ls1Ph3Mk9Wx2Rt6Yp4Nb7Vc5Mx0B=');
  assert.ok(a.length === 1 && b.length === 1);
  assert.deepEqual(a, b);
});

test('evidence marks its most important line, also for config files, long elements and signatures', async () => {
  const long = Array.from({ length: 14 }, (_, i) => `android:extra${i}="x"`).join('\n        ');
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ app: `${long}\n        android:debuggable="true"` }) });
  const e = one(out, 'manifest.debuggable').evidence[0];
  assert.match(e.excerpt.split('\n')[e.ref.hitLine - e.ref.startLine], /android:debuggable/);                  // the window moved to show it
  const sig = await scan({ 'resources/AndroidManifest.xml': manifest() }, { sig: { ...OK_SIG, schemes: { v1: { present: true, verified: true } }, signers: [{ subject: 'CN=Release' }] } });
  assert.equal(of(sig, 'signature.verdict')[0].evidence[0].focus, 'v2: absent');
});

test('no app-code rule goes quadratic on a huge single line', async () => {
  const line = `class Big implements Serializable { native void freeIt(); ${'long x = 1; getHost() onActivityResult( readObject( getQueryParameter( new File( '.repeat(4000)} }`;
  const t0 = Date.now();
  await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/Big.java': line });
  assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms`);
});

test('second review fixes: findings do not hide gaps, validation belongs to its own sink, native checks stay inside one class', async () => {
  const app = 'sources/com/x/app/';
  const gap = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}A.java`]: 'class A { void f() { Log.d("t", "password=" + password); } }', [`${app}B.java`]: 'class B { /* JADX WARN: Method dump skipped */ }' });
  assert.deepEqual(of(gap, 'code.sensitive-logging').map((o) => o.state).sort(), ['finding', 'inconclusive']);
  const trav = (body) => scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}P.java`]: `class P extends ContentProvider {\n${body}\n}` });
  const n = async (body) => of(await trav(body), 'code.path-traversal').filter((o) => o.state === 'finding').length;
  assert.equal(await n('  File a(Uri u) { File x = new File(base, other()); x.getCanonicalPath(); File y = new File(base, u.getPath()); return y; }'), 1);          // another file's check before
  assert.equal(await n('  File a(Uri u) { File y = new File(base, u.getPath()); File z = other(); z.getCanonicalPath(); return y; }'), 1);                       // another file's check after
  assert.equal(await n('  File a(Uri u) { File y = new File(base, u.getPath()); if (!y.getCanonicalPath().startsWith(root)) throw new X(); return y; }'), 0);     // its own check
  assert.equal(await n('  File a(Uri u) { return new File(base, u.getPath()).getCanonicalFile(); }'), 0);                                                       // inline
  const ptr = async (src) => of(await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}M.java`]: src }), 'code.serializable-native-pointer').filter((o) => o.state === 'finding').length;
  assert.equal(await ptr('class A implements Serializable {\n  int x;\n}\nclass B {\n  long ptr;\n  native void free();\n}'), 0);                                       // three facts, two classes
  assert.equal(await ptr('class Outer implements Serializable {\n  native void free();\n  static class Inner {\n    long ptr;\n  }\n}'), 0);                              // a nested class
  assert.equal(await ptr('class C implements Serializable {\n  long ptr;\n  native void free();\n}'), 1);
});

test('rules from the Allsafe comparison: payload credentials, text field to WebView, ObjectInputStream, RootBeer, Firebase URL, encoded constants', async () => {
  const app = 'sources/com/x/app/';
  const bad = await scan({
    'resources/AndroidManifest.xml': manifest(),
    [`${app}H.java`]: 'class H { static final String BODY = "<soap:Header><UsernameToken xmlns=\\"http://s.com/w\\">superadmin</UsernameToken><PasswordText xmlns=\\"http://s.com/w\\">supersecurepassword</PasswordText><SessionType>None</SessionType></soap:Header>"; }',
    [`${app}W.java`]: 'class W { void f(WebView w, EditText payload) { w.loadUrl(payload.getText().toString()); } }',
    [`${app}O.java`]: 'class O { void f(File file) throws Exception { FileInputStream fis = new FileInputStream(file); ObjectInputStream ois = new ObjectInputStream(fis); User u = (User) ois.readObject(); } }',
    [`${app}R.java`]: 'class R { boolean f(Context c) { return new RootBeer(c).isRooted(); } byte[] g() { return Base64.decode("NDg2Mw==", 0); } }',
    'resources/res/values/strings.xml': '<resources><string name="db">https://allsafe-8cef0-default-rtdb.firebaseio.com</string></resources>'
  });
  const t = (id) => of(bad, id).filter((o) => o.state === 'finding').map((o) => o.title);
  assert.deepEqual(t('secrets.hardcoded-values').map((x) => x.split(' = ')[0]).sort(), ['PasswordText', 'UsernameToken']);       // not SessionType
  assert.equal(of(bad, 'code.link-parameter-to-url').filter((o) => o.state === 'finding' && /Text field/.test(o.title)).length, 1);
  assert.equal(of(bad, 'code.unsafe-deserialization').filter((o) => o.state === 'finding' && /Object read/.test(o.title)).length, 1);
  assert.equal(t('code.client-root-check').length, 1);
  assert.equal(t('code.encoded-constant').length, 1);
  assert.ok(t('secrets.private-material').some((x) => /Firebase database URL/.test(x)));
});

test('constants that jadx inlines still count: FLAG_SECURE as 8192, mutable PendingIntents as 33554432', async () => {
  const app = 'sources/com/x/app/';
  const out = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}M.java`]: 'class M { void f(Activity a, Context c, Intent i) { a.getWindow().setFlags(8192, 8192); PendingIntent.getActivity(c, 0, i, 33554432); } }' });
  assert.equal(of(out, 'code.no-flag-secure').filter((o) => o.state === 'finding').length, 0);
  assert.ok(of(out, 'code.intent-safety').some((o) => o.state === 'finding' && /Mutable PendingIntent/.test(o.title)));
  assert.ok(!of(out, 'code.intent-safety').some((o) => /without a mutability flag/.test(o.title || '')));
});

test('third review fixes: signer identity, exact permission levels, provider directions, gaps next to findings', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest() };
  const cert = (sha256) => ({ subject: 'CN=Same', sha256 });
  const signed = (splits) => scan(files, { sig: { ...OK_SIG, signers: [cert('a'.repeat(64))], splits } });
  assert.equal(of(await signed([{ file: 'split-1.apk', ...OK_SIG, signers: [cert('b'.repeat(64))] }]), 'signature.verdict').some((o) => /different certificate/.test(o.title)), true);   // same name, different key
  assert.equal(of(await signed([{ file: 'split-1.apk', ...OK_SIG, signers: [cert('a'.repeat(64))] }]), 'signature.verdict').some((o) => /different certificate/.test(o.title)), false);
  const body = '<activity android:name=".S" android:exported="true" android:permission="android.permission.BROADCAST_STICKY"/><activity android:name=".U" android:exported="true" android:permission="android.permission.SOME_NEW_PERMISSION"/>';
  const perms = await scan({ 'resources/AndroidManifest.xml': manifest({ body }) });
  const wp = of(perms, 'manifest.weak-permission');
  assert.ok(wp.some((o) => o.state === 'finding' && /on S/.test(o.title)));                              // BROADCAST_STICKY is a normal permission
  assert.ok(wp.some((o) => o.state === 'inconclusive' && /SOME_NEW_PERMISSION/.test(o.reason)));          // unknown is said, even next to a finding
  const prov = async (attrs) => of(await scan({ 'resources/AndroidManifest.xml': manifest({ top: '<permission android:name="p.SIG" android:protectionLevel="signature"/>', body: `<provider android:name=".P" android:authorities="a.p" android:exported="true" ${attrs}/>` }) }), 'manifest.exported-provider').filter((o) => o.state === 'finding');
  const [w] = await prov('android:readPermission="p.SIG"');
  assert.match(w.title, /writable/);
  assert.deepEqual(w.repro.command, []);                                                                    // no query command for a write-only exposure
  const [r] = await prov('android:writePermission="p.SIG"');
  assert.match(r.title, /readable/);
  assert.deepEqual(r.repro.command.slice(0, 4), ['adb', 'shell', 'content', 'query']);
  assert.equal((await prov('android:permission="p.SIG"')).length, 0);
});

test('checks from the web research: crypto, TLS, WebView, intents, XXE, biometrics, notifications, leftovers', async () => {
  const app = 'sources/com/x/app/';
  const src = {
    C: 'class C { void f(KeyStore ks, InputStream in) throws Exception { ks.load(in, "changeit".toCharArray()); Cipher.getInstance("RSA/ECB/PKCS1Padding"); KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(1024); new SecureRandom("seed".getBytes()); new PBEKeySpec(p, s, 1000, 256); } }',
    X: 'class X { void f() throws Exception { DocumentBuilderFactory.newInstance().newDocumentBuilder(); } }',
    B: 'class B { void f(BiometricPrompt p, BiometricPrompt.PromptInfo i, KeyGenParameterSpec.Builder k) { p.authenticate(i); k.setInvalidatedByBiometricEnrollment(false); } }',
    N: 'class N { void f(NotificationCompat.Builder b, String otpCode, String spinner) { b.setContentText("Your code " + otpCode); b.setContentTitle(spinner); } }',
    L: 'class L { static final String API = "https://staging.example.com/api"; static final String IP = "http://192.168.1.20:8080/"; void f(BluetoothAdapter a, UUID u) throws Exception { a.listenUsingInsecureRfcommWithServiceRecord("x", u); new ServerSocket(8080); } }',
    P: 'class P extends PreferenceActivity { protected boolean isValidFragment(String n) { return true; } }',
    J: 'class J { void f(ObjectMapper m) { m.enableDefaultTyping(); } }',
    I: 'class I { void f(TelephonyManager t) { t.getDeviceId(); } }'
  };
  const files = { 'resources/AndroidManifest.xml': manifest() };
  for (const [k, v] of Object.entries(src)) files[`${app}${k}.java`] = v;
  const out = await scan(files);
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]);
  for (const x of ['Keystore opened with a literal password']) assert.ok(t('code.hardcoded-credential').includes(x), x);
  for (const x of ['RSA without OAEP padding', 'Weak key size', 'SecureRandom with a fixed seed', 'Low PBKDF2 iteration count'].filter((x) => !t('code.weak-crypto').includes(x))) assert.fail(`${x} missing: ${t('code.weak-crypto')}`);
  assert.equal(t('code.xxe').length, 1);
  assert.deepEqual(t('code.biometric-keystore').sort(), ['Biometric prompt without a CryptoObject', 'Key survives new biometric enrollment', 'Keystore key without StrongBox']);
  assert.equal(t('code.sensitive-notification').length, 1);                                // the otp one; spinner is not a PIN
  assert.deepEqual(t('code.debug-leftovers').sort(), ['Private IP address', 'Staging or development host']);
  assert.equal(t('code.insecure-bluetooth').length, 1);
  assert.equal(t('code.local-server').length, 1);
  assert.equal(t('code.fragment-injection').length, 1);
  assert.equal(t('code.device-identifiers').length, 1);
  assert.ok(t('code.unsafe-deserialization').includes('Jackson polymorphic typing turned on'));
  assert.equal(t('code.no-tapjacking-protection').length, 1);
  assert.equal(t('network.no-pinning').length, 1);

  const safe = await scan({ 'resources/AndroidManifest.xml': manifest(),
    [`${app}X.java`]: 'class X { void f() throws Exception { DocumentBuilderFactory d = DocumentBuilderFactory.newInstance(); d.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } }',
    [`${app}K.java`]: 'class K { void f(OkHttpClient.Builder b) { b.certificatePinner(new CertificatePinner.Builder().add("a.com", "sha256/x").build()); new PBEKeySpec(p, s, 310000, 256); } }',
    'resources/res/layout/login.xml': '<LinearLayout android:filterTouchesWhenObscured="true"/>' });
  const n = (id) => of(safe, id).filter((o) => o.state === 'finding').length;
  assert.equal(n('code.xxe'), 0);
  assert.equal(n('network.no-pinning'), 0);
  assert.equal(n('code.no-tapjacking-protection'), 0);
  assert.equal(of(safe, 'code.weak-crypto').filter((o) => o.state === 'finding' && /PBKDF2/.test(o.title)).length, 0);
});

test('checks from the web and skills research: manifest switches, NSC overrides, packaged files, hybrid config, trackers, OAuth, secrets', async () => {
  const app = 'sources/com/x/app/';
  const files = {
    'resources/AndroidManifest.xml': manifest({ app: 'android:testOnly="true" android:requestLegacyExternalStorage="true" android:debuggable="true" android:networkSecurityConfig="@xml/nsc"',
      body: '<receiver android:name=".Code" android:exported="true"><intent-filter><action android:name="android.provider.Telephony.SECRET_CODE"/><data android:scheme="android_secret_code" android:host="1234"/></intent-filter></receiver>' }),
    'resources/res/xml/nsc.xml': '<network-security-config><debug-overrides><trust-anchors><certificates src="user" overridePins="true"/></trust-anchors></debug-overrides></network-security-config>',
    'resources/res/xml/config.xml': '<widget id="x"><access origin="*"/></widget>',
    'sources/com/appsflyer/AppsFlyerLib.java': 'class AppsFlyerLib {}',
    [`${app}O.java`]: 'class O { String u = "https://idp.example.com/authorize?response_type=code&client_id=x"; String t = "123456789:AAH4s9dkdj3kd93jdk3j3kd9kd93kdk3kd9"; }'
  };
  const apk = zipStored({ 'classes.dex': 'x', 'assets/client.p12': 'x', 'assets/www/app.js.map': 'x' });
  const out = await scan(files, { input: openInput(entry(files, apk)) });
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title);
  assert.deepEqual(t('manifest.risky-attributes').sort(), ['Dialer secret code: Code', 'Legacy external storage', 'Test-only build']);
  const ca = of(out, 'network.user-ca').find((o) => o.state === 'finding');
  assert.equal(ca.severity, 'low');                                                        // debug-overrides count when debuggable; trusting user CAs is hardening, so it stays low
  assert.deepEqual(t('package.leftover-files').map((x) => x.split(':')[0]).sort(), ['JavaScript source map', 'Keystore or private key file']);
  assert.equal(t('network.cordova-allowlist').length, 1);
  assert.deepEqual(t('privacy.trackers'), ['Trackers: AppsFlyer']);
  assert.equal(t('code.oauth-pkce').length, 1);
  assert.ok(t('secrets.private-material').some((x) => /Telegram bot token/.test(x)));
  assert.equal(t('code.no-anti-debug').length, 1);

  const quiet = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:networkSecurityConfig="@xml/nsc"' }),
    'resources/res/xml/nsc.xml': '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>',
    [`${app}D.java`]: 'class D { boolean f() { return Debug.isDebuggerConnected(); } String u = "response_type=code&code_challenge=x"; }' });
  for (const id of ['manifest.risky-attributes', 'network.user-ca', 'code.oauth-pkce', 'code.no-anti-debug', 'privacy.trackers']) assert.equal(of(quiet, id).filter((o) => o.state === 'finding').length, 0, id);
  assert.equal(one(quiet, 'network.cordova-allowlist').state, 'not_applicable');
});

test('DragonJAR round, code checks: clipboard reads, deprecated security APIs, passkeys, temp files, timing, stack traces, malware signs, Keystore options', async () => {
  const app = 'sources/com/x/app/';
  const files = { 'resources/AndroidManifest.xml': manifest(),
    [`${app}A.java`]: 'class A { void f(ClipboardManager c) { c.getPrimaryClip(); c.addPrimaryClipChangedListener(l); EncryptedSharedPreferences.create(a); new FingerprintManager(); } }',
    [`${app}B.java`]: 'class B { String s = "{\\"userVerification\\": \\"discouraged\\", \\"challenge\\": \\"abcdEFGH1234\\"}"; void f(Exception e) { e.printStackTrace(); File.createTempFile("a", "b"); } }',
    [`${app}C.java`]: 'class C { boolean f(String password, String x) { return password.equals(x); } String u = "http://abc.onion/x"; void g(DevicePolicyManager d) { d.wipeData(0); } }',
    [`${app}D.java`]: 'class D { void f(KeyGenParameterSpec.Builder b) { b.setUserAuthenticationValidityDurationSeconds(300); b.setUnlockedDeviceRequired(false); } }' };
  const out = await scan(files);
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]);
  assert.deepEqual(t('code.clipboard-read').sort(), ['Clipboard change listener', 'Clipboard read']);
  assert.deepEqual(t('code.deprecated-security-api'), ['EncryptedSharedPreferences from security-crypto']);
  assert.deepEqual(t('code.passkey-weak-config').sort(), ['Hardcoded passkey challenge', 'Passkey does not require user verification']);
  assert.deepEqual(t('code.temp-file-write'), ['Temporary file created']);
  assert.deepEqual(t('code.stack-trace-leak'), ['printStackTrace call']);
  assert.deepEqual(t('code.timing-unsafe-compare'), ['Secret compared with equals']);
  assert.deepEqual(t('code.malware-indicators').sort(), ['Device wipe or lock call', 'Tor onion address']);
  const k = t('code.biometric-keystore');
  for (const x of ['Key stays unlocked for a time window after authentication', 'Key usable on a locked device', 'Keystore key without StrongBox', 'Deprecated fingerprint API']) assert.ok(k.includes(x), x);
  const quiet = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}Q.java`]: 'class Q { boolean f(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); } void g(KeyGenParameterSpec.Builder b) { b.setIsStrongBoxBacked(true); b.setUserAuthenticationValidityDurationSeconds(0); } String s = "{\\"userVerification\\": \\"required\\"}"; }' });
  for (const id of ['code.timing-unsafe-compare', 'code.passkey-weak-config', 'code.biometric-keystore']) assert.equal(of(quiet, id).filter((o) => o.state === 'finding').length, 0, id);
});

test('DragonJAR round, manifest: accessibility, notification listener, device admin, SMS priority, cross profile, Android 14', async () => {
  const body = `<service android:name=".Acc" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" android:exported="true"/>
    <service android:name=".Nl" android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" android:exported="true"/>
    <receiver android:name=".Adm" android:permission="android.permission.BIND_DEVICE_ADMIN"/>
    <receiver android:name=".Boot" android:exported="true"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>
    <receiver android:name=".Sms" android:exported="true"><intent-filter android:priority="999"><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter></receiver>
    <service android:name=".Fg"/>
    <activity android:name=".Noact" android:exported="true"><intent-filter><category android:name="android.intent.category.DEFAULT"/></intent-filter></activity>`;
  const out = await scan({ 'resources/AndroidManifest.xml': manifest({ app: 'android:crossProfile="true"', body, top: '<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>', sdk: '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34"/>' }) });
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]);
  assert.deepEqual(t('manifest.sensitive-services').sort(), ['Accessibility service', 'Cross-profile access', 'Device administrator', 'Notification listener', 'SMS receiver with raised priority']);
  assert.deepEqual(t('manifest.android14-requirements').sort(), ['Intent filter without an action', 'Service without foregroundServiceType']);
  const quiet = await scan({ 'resources/AndroidManifest.xml': manifest({ sdk: '<uses-sdk android:targetSdkVersion="34"/>', body: '<receiver android:name=".Sms" android:exported="true"><intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter></receiver>' }) });
  assert.equal(of(quiet, 'manifest.sensitive-services').filter((o) => o.state === 'finding').length, 0);
});

test('DragonJAR round, package: protectors, Cordova and Capacitor, React Native, Flutter, Unity, .NET, native strings, obfuscation', async () => {
  const apk = zipStored({
    'classes.dex': 'x', 'lib/arm64-v8a/libjiagu.so': 'x',
    'assets/www/index.html': '<html><head></head><body></body></html>', 'assets/www/js/app.js': 'function f(s){ return eval(s); }',
    'assets/capacitor.config.json': '{"server":{"cleartext":true,"allowNavigation":["*"]},"webContentsDebuggingEnabled":true}',
    'assets/index.android.bundle': 'var __DEV__=!0; AsyncStorage.setItem("authToken", t); console.log("password", p);',
    'lib/arm64-v8a/libapp.so': Buffer.from('\0shared_preferences\0'),
    'assets/bin/Data/Managed/Metadata/global-metadata.dat': Buffer.from('PlayerPrefs'),
    'assemblies/My.App.dll': Buffer.from('ServerCertificateValidationCallback'),
    'lib/arm64-v8a/libnat.so': Buffer.concat([elf64(), Buffer.from('\0http://example.com/api\0MD5_Init\0system\0')])
  });
  const files = { 'resources/AndroidManifest.xml': manifest() };
  for (let i = 0; i < 30; i++) files[`sources/com/x/app/Named${i}.java`] = `class Named${i} {}`;
  const out = await scan(files, { input: openInput(entry(files, apk)) });
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title);
  assert.ok(t('package.protector').some((x) => /Qihoo|Jiagu/.test(x)));
  assert.deepEqual(t('package.hybrid-web').map((x) => x.split(' in ')[0]).sort(), ['Capacitor allows cleartext', 'Capacitor allows navigation anywhere', 'Capacitor web debugging enabled', 'No Content Security Policy', 'eval or Function'].sort());
  assert.deepEqual(t('package.react-native').sort(), ['Development mode left on', 'Secret saved in AsyncStorage', 'Secret written with console.log']);
  assert.equal(t('package.flutter').length, 1);
  assert.equal(t('package.unity').length, 1);
  assert.equal(t('package.dotnet').length, 1);
  assert.deepEqual(t('native.strings').map((x) => x.split(' in ')[0]).sort(), ['Cleartext URL', 'Weak crypto name']);
  assert.equal(t('code.no-obfuscation').length, 1);
  assert.ok(t('native.hardening').some((x) => /Unsafe imports|system/.test(x)));
  const plain = await scan({ 'resources/AndroidManifest.xml': manifest() }, { input: openInput(entry({ 'resources/AndroidManifest.xml': manifest() }, zipStored({ 'classes.dex': 'x' }))) });
  for (const id of ['package.hybrid-web', 'package.react-native', 'package.flutter', 'package.unity', 'package.dotnet', 'native.strings']) assert.equal(one(plain, id).state, 'not_applicable', id);
});

test('SDK inventory lists payment, sign-in and monitoring SDKs, and a Facebook client token', async () => {
  const files = { 'resources/AndroidManifest.xml': manifest(), 'sources/com/stripe/Stripe.java': 'class Stripe {}', 'sources/io/sentry/Sentry.java': 'class Sentry {}', 'sources/com/x/app/A.java': 'class A {}',
    'resources/res/values/strings.xml': '<resources><string name="facebook_client_token">abc123def456abc123def456abc123de</string></resources>' };
  const out = await scan(files);
  const t = of(out, 'privacy.sdk-inventory').filter((o) => o.state === 'finding').map((o) => o.title);
  assert.ok(t.includes('SDKs: Stripe, Sentry'));
  assert.ok(t.includes('Facebook client token in resources'));
  const none = await scan({ 'resources/AndroidManifest.xml': manifest(), 'sources/com/x/app/A.java': 'class A {}' });
  assert.equal(of(none, 'privacy.sdk-inventory').filter((o) => o.state === 'finding').length, 0);
});

test('Hrishikesh checklist round: root detection, partial obfuscation, key reuse, copy and paste, keyboard learning', async () => {
  const app = 'sources/com/x/app/';
  const files = { 'resources/AndroidManifest.xml': manifest(),
    'resources/res/layout/pin.xml': '<LinearLayout><EditText android:id="@+id/card_number" android:inputType="number"/><EditText android:id="@+id/pin_field" android:inputType="textNoSuggestions"/></LinearLayout>',
    [`${app}KeyUse.java`]: 'class KeyUse { void f(byte[] KEY) { Cipher.getInstance("AES/CBC/PKCS5Padding"); SecretKeySpec a = new SecretKeySpec(KEY, "AES"); Mac m = Mac.getInstance("HmacSHA256"); SecretKeySpec b = new SecretKeySpec(KEY, "HmacSHA256"); } }' };
  for (let i = 0; i < 30; i++) files[`${app}${String.fromCharCode(97 + (i % 26))}${i > 25 ? 'a' : ''}.java`] = 'class x {}';
  files[`${app}LoginManager.java`] = 'class LoginManager {}';
  const out = await scan(files);
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]);
  assert.equal(t('code.no-root-detection').length, 1);
  assert.equal(t('code.partial-obfuscation').length, 1);
  assert.equal(t('code.key-reuse').length, 1);
  assert.equal(t('code.copy-paste-allowed').length, 1);
  assert.ok(t('code.keyboard-cache').includes('Sensitive field lets the keyboard learn'));
  const quiet = await scan({ 'resources/AndroidManifest.xml': manifest(), 'resources/res/layout/pin.xml': '<EditText android:id="@+id/card_number" android:inputType="number"/>',
    [`${app}Q.java`]: 'class Q { void f(EditText e) { e.setCustomSelectionActionModeCallback(cb); } boolean r() { return new RootBeer(c).isRooted(); } }' });
  for (const id of ['code.copy-paste-allowed', 'code.no-root-detection', 'code.key-reuse', 'code.partial-obfuscation']) assert.equal(of(quiet, id).filter((o) => o.state === 'finding').length, 0, id);
});

test('Ostorlab insecure app round: numeric file modes, lowercase digest names, fixed IV, SQL from a variable, XML injection, Wi-Fi details, BiometricPrompt without a CryptoObject', async () => {
  const app = 'sources/com/x/app/';
  const files = { 'resources/AndroidManifest.xml': manifest(),
    [`${app}F.java`]: 'class F { void f(Context c) throws Exception { c.openFileOutput("a", 1); c.getSharedPreferences("p", 3); new File("x").setReadable(true, false); MessageDigest.getInstance("sha-1"); } }',
    [`${app}I.java`]: 'class I { void f() throws Exception { byte[] iv = "0123456789abcdef".getBytes(); Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(1, k, new IvParameterSpec(iv)); } }',
    [`${app}S.java`]: 'class S { void f(SQLiteDatabase d, String q) { d.execSQL(q, new Object[0]); Xml.parse("<root>" + q + "</root>", null); } }',
    [`${app}W.java`]: 'class W { void f(WifiManager w) { w.getConfiguredNetworks(); } }',
    [`${app}B.java`]: 'class B { void f(BiometricPrompt p) { p.authenticate(new BiometricPrompt.PromptInfo.Builder().setTitle("t").build()); } }' };
  const out = await scan(files);
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]);
  assert.deepEqual(t('code.world-readable-file').sort(), ['File opened to every app', 'World-readable mode as a number']);
  assert.ok(t('code.weak-crypto').includes('MD5 or SHA-1 digest'));
  assert.ok(t('code.weak-crypto').includes('Fixed initialization vector'));
  assert.deepEqual(t('code.sql-from-variable'), ['SQL statement run from a variable']);
  assert.ok(t('code.xxe').includes('XML built from a string with input'));
  assert.ok(t('code.device-identifiers').includes('Wi-Fi network details read'));
  assert.ok(t('code.biometric-keystore').includes('Biometric prompt without a CryptoObject'));
  const quiet = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}Q.java`]: 'class Q { void f(Context c, SQLiteDatabase d, BiometricPrompt p, byte[] r) throws Exception { c.openFileOutput("a", 0); c.getSharedPreferences("p", 0); d.execSQL("DROP TABLE t"); p.authenticate(info, new BiometricPrompt.CryptoObject(ciph)); new IvParameterSpec(r); } }' });
  for (const id of ['code.world-readable-file', 'code.sql-from-variable']) assert.equal(of(quiet, id).filter((o) => o.state === 'finding').length, 0, id);
  assert.equal(of(quiet, 'code.biometric-keystore').filter((o) => o.state === 'finding' && /without a CryptoObject/.test(o.title)).length, 0);
});

test('a damaged class in a library does not make rules inconclusive, but one in the app\'s own code does', async () => {
  const broken = '/* JADX WARN: Code restructure failed: missing block */\nclass B {}';
  const main = '<activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>';
  const lib = await scan({ 'resources/AndroidManifest.xml': manifest({ body: main }), 'sources/com/x/app/Main.java': 'class Main {}', 'sources/template/util/B.java': broken });
  assert.equal(one(lib, 'code.world-readable-file').state, 'checked');
  assert.ok(of(lib, 'code.world-readable-file')[0].coverage.libraryDamaged >= 1);               // reported, not hidden
  const own = await scan({ 'resources/AndroidManifest.xml': manifest({ body: main }), 'sources/com/x/app/Main.java': 'class Main {}', 'sources/com/x/app/B.java': broken });
  assert.equal(one(own, 'code.world-readable-file').state, 'inconclusive');
  const mergedLib = await scan({ 'resources/AndroidManifest.xml': manifest({ body: `${main}<activity android:name="org.lib.Other" android:exported="false"/>` }), 'sources/com/x/app/Main.java': 'class Main {}', 'sources/org/lib/B.java': broken });
  assert.equal(one(mergedLib, 'code.world-readable-file').state, 'checked');                    // a library's manifest entry does not make it app code
});

test('checklist round, manifest and package: single pin, overlay permission, embedded databases, vulnerable libraries, Unity intent', async () => {
  const mf = (body, top = '') => ({ 'resources/AndroidManifest.xml': manifest({ app: 'android:networkSecurityConfig="@xml/nsc"', body, top }) });
  const nsc = (pins) => ({ 'resources/res/xml/nsc.xml': `<network-security-config><domain-config><domain>a.com</domain><pin-set>${pins}</pin-set></domain-config></network-security-config>` });
  const one1 = await scan({ ...mf(''), ...nsc('<pin digest="SHA-256">x</pin>') });
  assert.deepEqual([one(one1, 'network.single-pin').state, one(one1, 'network.single-pin').severity], ['finding', 'low']);
  const two = await scan({ ...mf(''), ...nsc('<pin digest="SHA-256">x</pin><pin digest="SHA-256">y</pin>') });
  assert.equal(one(two, 'network.single-pin').state, 'checked');

  const ov = await scan(mf('', '<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>'));
  assert.ok(of(ov, 'manifest.sensitive-services').some((o) => o.state === 'finding' && /Draws over other apps/.test(o.title) && o.severity === 'low'));

  const files = mf('');
  const dbs = await scan(files, { input: openInput(entry(files, zipStored({ 'assets/seed.db': 'x', 'res/raw/cache.sqlite': 'x', 'assets/readme.txt': 'x' }))) });
  assert.deepEqual(of(dbs, 'package.leftover-files').filter((o) => o.state === 'finding').map((o) => o.title).sort(), ['Database file in the APK: cache.sqlite', 'Database file in the APK: seed.db']);

  const libs = await scan(files, { input: openInput(entry(files, zipStored({
    'META-INF/maven/com.google.code.gson/gson/pom.properties': 'groupId=com.google.code.gson\nartifactId=gson\nversion=2.8.5\n',
    'META-INF/com.google.android.play_core.version': '1.6.0',
    'META-INF/maven/org.apache.commons/commons-text/pom.properties': 'version=1.10.0\n',
    'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties': 'version=2.17.1\n' }))) });
  const log4j = async (v) => one(await scan(files, { input: openInput(entry(files, zipStored({ 'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties': `version=${v}\n` }))) }), 'package.vulnerable-libraries').state;
  assert.deepEqual([await log4j('2.12.4'), await log4j('2.3.2'), await log4j('2.18.0'), await log4j('2.12.3'), await log4j('2.14.1'), await log4j('2.3.1')], ['checked', 'checked', 'checked', 'finding', 'finding', 'finding']);   // fixes for the older branches count
  assert.deepEqual(of(libs, 'package.vulnerable-libraries').filter((o) => o.state === 'finding').map((o) => [o.title, o.severity]).sort(),
    [['Library with a known flaw: core 1.6.0', 'medium'], ['Library with a known flaw: gson 2.8.5', 'low']]);              // commons-text 1.10.0 and log4j 2.17.1 are the fixed versions
  const fine = await scan(files, { input: openInput(entry(files, zipStored({ 'META-INF/maven/com.google.code.gson/gson/pom.properties': 'version=2.10.1\n' }))) });
  assert.equal(one(fine, 'package.vulnerable-libraries').state, 'checked');
  const none = await scan(files, { input: openInput(entry(files, zipStored({ 'classes.dex': 'x' }))) });
  assert.equal(one(none, 'package.vulnerable-libraries').state, 'inconclusive');                                                    // no version files: nothing was read
  const bad = await scan(files, { input: openInput(entry(files, zipStored({ 'META-INF/maven/com.google.code.gson/gson/pom.properties': 'artifactId=gson\n' }))) });
  assert.equal(one(bad, 'package.vulnerable-libraries').state, 'inconclusive');                                                     // a listed library whose version cannot be read

  const unityMf = { 'resources/AndroidManifest.xml': manifest({ body: '<activity android:name="com.unity3d.player.UnityPlayerActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>' }) };
  const unity = await scan(unityMf, { input: openInput(entry(unityMf, zipStored({ 'lib/arm64-v8a/libunity.so': 'x' }))) });
  assert.equal(one(unity, 'package.unity-intent').state, 'inconclusive');                                                     // the Unity version is not readable, so a patched build cannot be told apart
  assert.equal(one(await scan(files, { input: openInput(entry(files, zipStored({ 'classes.dex': 'x' }))) }), 'package.unity-intent').state, 'not_applicable');
});

test('checklist round, code: upload names, binders, results, commands, debug endpoints, SafetyNet, update libraries, JWT, logout, keyboards, TLS, endpoints', async () => {
  const app = 'sources/com/x/app/';
  const files = {
    'resources/AndroidManifest.xml': manifest(),
    [`${app}A.java`]: 'class A { void a(Activity act, URLConnection c, java.io.File dir, String q) { String n = c.getHeaderField("Content-Disposition"); new File(dir, n); act.setResult(-1, new Intent().putExtra("auth_token", q)); Runtime.getRuntime().exec("ls " + q); UUID u = UUID.fromString("0000180d-0000-1000-8000-00805f9b34fb"); BluetoothAdapter b; String s = "https://api.corp-example.io/actuator/env"; String g = "https://api.corp-example.io/graphql"; SafetyNetApi.attest(null, null); CodePush.start(); } }',
    [`${app}S.java`]: 'class S extends Service { public IBinder onBind(Intent i) { return new Binder(); } }',
    [`${app}J.java`]: 'class J { void f(String q) { Jwts.parser().parse(q); JWT.decode(q); Algorithm.HMAC256("supersecretvalue"); Algorithm none = Algorithm.none(); } }',
    [`${app}L.java`]: 'class L { void logout() { token = null; } }',
    [`${app}K.java`]: 'class K { void f(EditText passwordField) { passwordField.setInputType(InputType.TYPE_CLASS_TEXT); } void g() { OutlinedTextField(value = v, onValueChange = {}, label = { Text("Password") }) } }',
    [`${app}T.java`]: 'class T implements X509TrustManager { public void checkServerTrusted(X509Certificate[] c, String a) { try { v(c); } catch (Exception e) { } } void f(HttpsURLConnection h) { h.setHostnameVerifier((x, y) -> true); } }'
  };
  const out = await scan(files);
  const t = (id) => of(out, id).filter((o) => o.state === 'finding').map((o) => o.title.split(':')[0]).sort();
  assert.ok(t('code.path-traversal').includes('Remote file name used as a path'));
  assert.deepEqual(t('code.intent-safety').filter((x) => /binder|result/.test(x)), ['Service returns a binder without a caller check', 'Token returned in an activity result']);
  assert.ok(t('code.dynamic-execution').includes('OS command built from a string') && t('code.dynamic-execution').includes('Over-the-air code update library'));
  assert.ok(!t('code.dynamic-execution').includes('OS command execution'));                              // the concatenated call is reported once, at the higher rating
  assert.deepEqual(t('code.debug-leftovers'), ['Debug or admin endpoint']);
  assert.ok(t('code.deprecated-security-api').includes('SafetyNet Attestation'));
  assert.deepEqual(t('code.jwt-misuse'), ['JWT only decoded', 'JWT parsed without a signing key', 'JWT signature algorithm none', 'JWT signed with a literal secret']);
  assert.deepEqual(t('code.logout-keeps-session'), ['Logout without clearing stored state']);
  assert.equal(t('code.keyboard-cache').filter((x) => /built in code/.test(x)).length, 2);                  // the setInputType call and the Compose field are two sites
  assert.deepEqual(t('code.trust-all-tls').filter((x) => /lambda|swallows/.test(x)), ['Hostname verifier lambda that returns true', 'checkServerTrusted that swallows the exception']);
  const ep = of(out, 'network.endpoint-inventory').find((o) => o.state === 'finding');
  assert.match(ep.summary, /api\.corp-example\.io/);
  assert.doesNotMatch(ep.summary, /schemas\.android\.com/);
  assert.equal(ep.severity, 'low');
  assert.ok(ep.evidence.length > 0 && ep.evidence.every((e) => e.ref.path && e.excerpt));         // every host has a place to look at

  const ok = await scan({
    'resources/AndroidManifest.xml': manifest(),
    [`${app}S.java`]: 'class S extends Service { public IBinder onBind(Intent i) { enforceCallingPermission("x.P", "no"); return new Binder(); } }',
    [`${app}L.java`]: 'class L { void logout() { prefs.edit().clear().apply(); } }',
    [`${app}K.java`]: 'class K { void f(EditText passwordField) { passwordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); } }',
    [`${app}J.java`]: 'class J { void f(String q) { Jwts.parser().setSigningKey(key).parse(q); } }',
    [`${app}Fs.java`]: 'class Fs { void f(Window w) { w.setRecentsScreenshotEnabled(false); } void e() { String x = Build.MODEL; boolean emu = Build.PRODUCT.contains("sdk_gphone"); } }'
  });
  // a generated app with thousands of hosts is capped, and every host that is listed has its own evidence
  const many = Array.from({ length: 520 }, (_, i) => `"https://h${i}.many-example.io/"`).join(';');
  const eo = await scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}M.java`]: `class M { String a = ${many}; }`, [`${app}N.java`]: 'class N { String a = "https://late.busy-example.io/a"; String b = "https://late.busy-example.io/b"; }' });
  const ef = of(eo, 'network.endpoint-inventory').find((o) => o.state === 'finding');
  assert.equal(ef.evidence.length, 40);                                                                         // one place per host named in the summary
  assert.ok(ef.evidence.every((e) => e.excerpt.includes('example.io')));
  assert.match(ef.summary, /late\.busy-example\.io/);                                                            // seen late and often: not shut out by one-off hosts
  assert.ok(ef.evidence[0].excerpt.includes('late.busy-example.io'));                                           // and it leads, with its own evidence
  // any return type and a deeply nested body are read in full; a body that never closes is inconclusive, not checked
  const lg = (src) => scan({ 'resources/AndroidManifest.xml': manifest(), [`${app}L.java`]: src }).then((o) => one(o, 'code.logout-keeps-session'));
  assert.equal((await lg('class L { boolean logout() { return true; } }')).state, 'finding');
  assert.equal((await lg('class L { Task<Void> signOut() throws Exception { if (a) { for (;;) { if (b) { while (c) { x(); } } } } return null; } }')).state, 'finding');
  assert.equal((await lg('class L { Task<Void> signOut() { if (a) { for (;;) { if (b) { while (c) { y(); } } } } String s = "}"; prefs.edit().clear().apply(); return null; } }')).state, 'checked');
  assert.equal((await lg('class L { void logout() { if (a) { x();')).state, 'inconclusive');
  assert.equal((await lg('class L { void logout() { analytics.commit(); nav.clear(); } }')).state, 'finding');         // generic mutations are not clearing a session
  assert.equal((await lg('class L { void logout(@Named("account") String id) { x(); } }')).state, 'finding');          // brackets inside the parameters
  assert.equal((await lg('class L { String s = "void logout() { prefs.edit().clear(); }"; // void signOut() { tokenStore.clear(); }\n }')).state, 'checked');  // text in a string or comment is not a method
  assert.equal((await lg('class L { void logout() { tokenStore.clear(); } }')).state, 'checked');
  assert.equal((await lg('class L { void logout() { // tokenStore.clear();\n x(); } }')).state, 'finding');             // a commented clear does nothing
  assert.equal((await lg('class L { void logout() { CookieManager cm = CookieManager.getInstance(); } }')).state, 'finding');
  assert.equal((await lg('class L { void logout() { prefs.edit().remove("theme").apply(); } }')).state, 'finding');   // not a session key
  for (const n of ['onLogout', 'performLogout', 'handleSignOut', 'doLogout']) assert.equal((await lg(`class L { void ${n}() { x(); } }`)).state, 'finding', n);
  assert.equal((await lg('class L { void logout() { getSharedPreferences("p", 0).edit().remove("auth_token").apply(); } }')).state, 'checked');
  for (const id of ['code.logout-keeps-session', 'code.jwt-misuse', 'code.keyboard-cache']) assert.equal(of(ok, id).filter((o) => o.state === 'finding').length, 0, id);
  assert.equal(of(ok, 'code.intent-safety').filter((o) => o.state === 'finding' && /binder/.test(o.title)).length, 0);
  assert.equal(one(ok, 'code.no-flag-secure').state, 'checked');                                           // setRecentsScreenshotEnabled(false) counts
  assert.equal(one(ok, 'code.no-anti-debug').state, 'checked');                                            // so does a wider emulator check
  const exclude = await scan({ 'resources/AndroidManifest.xml': manifest({ body: '<activity android:name=".Main" android:excludeFromRecents="true"/>' }), [`${app}M.java`]: 'class M {}' });
  assert.equal(one(exclude, 'code.no-flag-secure').state, 'checked');
});

test('keyboard cache: with no layouts and no decompiled sources the rule is inconclusive, not checked', async () => {
  const out = await scan({ 'resources/AndroidManifest.xml': manifest() });
  assert.equal(one(out, 'code.keyboard-cache').state, 'inconclusive');
});
