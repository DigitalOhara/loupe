import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanRecording, analyzeRecording, sessionRecord, DYN_RULES } from './dynamic.js';
import { sensitive } from './redact.js';

const T0 = 1_700_000_000_000;
/** A recording with every capability and every probe group on. Override pieces per test. */
const rec = (o = {}) => cleanRecording({
  pkg: 'com.x.app', uid: 10123, startedAt: T0, endedAt: T0 + 60_000, device: { model: 'SM', release: '14', sdk: 34, clockOffsetMs: 0 }, installed: { sha256: 'a'.repeat(64), match: true },
  caps: { logcat: true, sockets: true, ext: true, root: false, appdata: 'run-as' }, plan: { readonly: true, changing: true, typed: [] },
  pids: [100], logcat: [], sockets: [], steps: [], fs: { before: [], after: [], matches: [] }, ext: [], ...o
});
const log = (msg, extra = {}) => ({ t: T0 + 1000, pid: 100, level: 'D', tag: 'DoLogin', msg, ...extra });
const of = (out, id) => out.filter((o) => o.ruleId === id);
const one = (out, id) => { const r = of(out, id); assert.equal(r.length, 1, id); return r[0]; };

test('cleanRecording whitelists, caps and drops short typed values', () => {
  const r = cleanRecording({ pkg: 'p', evil: 1, caps: { appdata: 'sudo' }, plan: { typed: ['ab', 'secret1', 5] }, logcat: Array.from({ length: 60_000 }, () => ({ msg: 'x'.repeat(5000) })), fs: { after: [{ path: 'a', text: 'y'.repeat(100_000) }, { path: '' }] } });
  assert.equal(r.evil, undefined);
  assert.equal(r.caps.appdata, null);
  assert.deepEqual(r.plan.typed, ['secret1']);
  assert.equal(r.logcat.length, 20_000);
  assert.equal(r.logcat[0].msg.length, 500);
  assert.equal(r.fs.after.length, 1);
  assert.equal(r.fs.after[0].text.length, 65_536);
  assert.deepEqual(cleanRecording(null).logcat, []);
});

test('sensitive finds typed values, Base64 forms, key=value, JWTs, tokens and card numbers', () => {
  const typed = ['Jack@123$'];
  const b64 = Buffer.from('Jack@123$').toString('base64');
  assert.deepEqual(sensitive(`pw=${b64}`, typed).map((h) => h.label), ['A value you typed, Base64 encoded']);
  assert.ok(sensitive('login ok Jack@123$', typed)[0].exact);
  assert.equal(sensitive('password=hunter22', [])[0].value, 'hunter22');
  assert.equal(sensitive('password=null token=*** secret: true', []).length, 0);
  assert.equal(sensitive('t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk', [])[0].label, 'A JWT');
  assert.equal(sensitive('card 4111 1111 1111 1111', [])[0].label, 'A card number');
  assert.equal(sensitive('id 1234 5678 9012 3456', []).length, 0);                      // fails Luhn
  assert.equal(sensitive('xoxb-1234567890-abcdefghij', [])[0].label, 'Slack token');
});

test('logcat secrets: only the app\'s pids, shown as logged, one finding per tag and kind', () => {
  const out = analyzeRecording(rec({
    plan: { readonly: true, changing: true, typed: ['Jack@123$'] },
    logcat: [log('login user=jack password=Secret99x'), log('login user=jack password=Secret99x'), log('password=Other1234', { pid: 999 }), log('typed Jack@123$ ok', { tag: 'Other' })]
  }));
  const f = of(out, 'dyn.logcat-secrets');
  assert.equal(f.length, 2);
  assert.ok(JSON.stringify(f).includes('Secret99x') && JSON.stringify(f).includes('Jack@123$'));
  assert.deepEqual(f.map((x) => x.detection).sort(), ['exact', 'probable']);
  assert.equal(f[0].evidence[0].kind, 'logcat');
});

test('logcat secrets: nothing sensitive is checked clean', () => {
  assert.equal(one(analyzeRecording(rec({ logcat: [log('hello')] })), 'dyn.logcat-secrets').state, 'checked');
});

test('crash: only a crash soon after a step that started a component counts', () => {
  const steps = [{ t: T0 + 5000, kind: 'activity', target: 'com.x.app/com.x.app.Deep', cmd: 'am start -n com.x.app/com.x.app.Deep', output: '' }];
  const fatal = (t) => [{ t, pid: 100, level: 'E', tag: 'AndroidRuntime', msg: 'FATAL EXCEPTION: main' }, { t: t + 1, pid: 100, level: 'E', tag: 'AndroidRuntime', msg: 'java.lang.NullPointerException' }];
  const hit = one(analyzeRecording(rec({ steps, logcat: fatal(T0 + 6000) })), 'dyn.crash');
  assert.deepEqual([hit.state, hit.severity], ['finding', 'medium']);
  assert.match(hit.evidence[0].excerpt, /NullPointerException/);
  assert.equal(one(analyzeRecording(rec({ steps, logcat: fatal(T0 + 30_000) })), 'dyn.crash').state, 'checked');
  assert.equal(one(analyzeRecording(rec({ logcat: fatal(T0 + 6000) })), 'dyn.crash').state, 'not_applicable');
});

test('cleartext: non-TLS ports to non-loopback hosts, once each; plain HTTP ports are probable, others heuristic', () => {
  const sockets = [{ t: T0, remote: '10.0.0.5:80', state: 'ESTABLISHED' }, { t: T0 + 1, remote: '10.0.0.5:80', state: 'TIME_WAIT' }, { t: T0, remote: '127.0.0.1:8080', state: 'ESTABLISHED' }, { t: T0, remote: '1.2.3.4:443', state: 'ESTABLISHED' }, { t: T0, remote: '1.2.3.4:9000', state: 'SYN_SENT' }];
  const f = of(analyzeRecording(rec({ sockets })), 'dyn.cleartext-connection');
  assert.deepEqual(f.map((x) => x.title), ['Connection to 10.0.0.5:80', 'Connection to 1.2.3.4:9000']);
  assert.deepEqual(f.map((x) => x.detection), ['probable', 'heuristic']);
});

test('app storage: typed values (also Base64 and binary matches), status new or changed', () => {
  const b64 = Buffer.from('Jack@123$').toString('base64');
  const before = [{ path: './shared_prefs/a.xml', mode: '660', size: 1, text: '<map/>' }];
  const after = [{ path: './shared_prefs/a.xml', mode: '660', size: 9, text: `<map><string name="pw">${b64}</string></map>` }, { path: './files/n.txt', mode: '660', size: 3, text: 'hi' }];
  const out = analyzeRecording(rec({ plan: { readonly: true, changing: true, typed: ['Jack@123$'] }, fs: { before, after, matches: [{ needle: 0, path: './databases/app.db' }] } }));
  const f = of(out, 'dyn.storage-secrets');
  assert.equal(f.length, 2);
  assert.match(f.find((x) => /a\.xml/.test(x.title)).evidence[0].note, /changed/);
  assert.ok(f.some((x) => /app\.db/.test(x.title)));
  assert.ok(JSON.stringify(f).includes(b64));                              // the stored line is shown as it is on the phone
});

test('world-readable and world-writable files', () => {
  const files = [{ path: './a', mode: '600', size: 1, text: null }, { path: './b', mode: '644', size: 1, text: null }, { path: './c', mode: '666', size: 1, text: null }, { path: './d', mode: '660', size: 1, text: null }];
  const f = of(analyzeRecording(rec({ fs: { before: [], after: files, matches: [] } })), 'dyn.world-readable');
  assert.deepEqual(f.map((x) => [x.evidence[0].ref.path, x.severity]), [['./b', 'medium'], ['./c', 'high']]);
});

test('external storage', () => {
  const f = of(analyzeRecording(rec({ ext: [{ path: '/sdcard/Android/data/com.x.app/n.txt', size: 5, text: 'token=abcd1234' }] })), 'dyn.external-storage');
  assert.equal(f.length, 1);
  assert.ok(JSON.stringify(f).includes('abcd1234'));
});

test('exported activity and provider probes', () => {
  const steps = [
    { t: T0, kind: 'activity', target: 'com.x.app/com.x.app.Open', cmd: 'am start -n com.x.app/com.x.app.Open', output: 'mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Open}' },
    { t: T0, kind: 'activity', target: 'com.x.app/com.x.app.Blocked', cmd: 'am start -n com.x.app/com.x.app.Blocked', output: 'mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Login}' },
    { t: T0, kind: 'provider', target: 'content://com.x.prov', cmd: 'content query --uri content://com.x.prov', output: 'Row: 0 id=1, name=jack' },
    { t: T0, kind: 'provider', target: 'content://com.x.empty', cmd: 'content query --uri content://com.x.empty', output: 'No result found.' }
  ];
  const out = analyzeRecording(rec({ steps }));
  assert.deepEqual(of(out, 'dyn.exported-reachable').map((o) => o.title), ['Opens without login: Open']);
  assert.deepEqual(of(out, 'dyn.provider-query').map((o) => [o.state, o.severity]), [['finding', 'high']]);
  const none = analyzeRecording(rec());
  assert.equal(one(none, 'dyn.exported-reachable').state, 'not_applicable');
  assert.equal(one(none, 'dyn.provider-query').state, 'not_applicable');
});

test('missing capabilities and declined probes are not tested, with the reason', () => {
  const out = analyzeRecording(rec({ caps: { logcat: false, sockets: false, ext: false, root: false, appdata: null }, plan: { readonly: false, changing: false, typed: [] } }));
  const reason = (id) => one(out, id).reason;
  assert.deepEqual([reason('dyn.logcat-secrets'), reason('dyn.cleartext-connection'), reason('dyn.storage-secrets'), reason('dyn.world-readable'), reason('dyn.external-storage'), reason('dyn.crash'), reason('dyn.provider-query')],
    ['logcat-unreadable', 'sockets-unattributable', 'needs-root-or-debuggable', 'needs-root-or-debuggable', 'external-storage-unreadable', 'logcat-unreadable', 'user-declined']);
  assert.equal(reason('dyn.exported-reachable'), 'user-declined');
  assert.ok(DYN_RULES.every((r) => of(out, r.id).length === 1));
});

test('a snapshot that failed makes the storage rules not tested', () => {
  const out = analyzeRecording(rec({ fs: { error: 'run-as: package not debuggable', before: [], after: [], matches: [] } }));
  assert.equal(one(out, 'dyn.storage-secrets').reason, 'needs-root-or-debuggable');
});

test('a throwing rule is an error outcome and the rest still run', () => {
  const r = DYN_RULES.find((x) => x.id === 'dyn.cleartext-connection'), run = r.run;
  r.run = () => { throw new Error('boom'); };
  try { const out = analyzeRecording(rec()); assert.deepEqual([one(out, 'dyn.cleartext-connection').state, one(out, 'dyn.cleartext-connection').reason], ['error', 'boom']); assert.equal(one(out, 'dyn.logcat-secrets').state, 'checked'); }
  finally { r.run = run; }
});

test('sessionRecord has the static scan shape', () => {
  const s = sessionRecord(rec({ logcat: [log('password=Secret99x')] }), { artifactId: 'a'.repeat(64), decompileId: 'b'.repeat(64) });
  assert.deepEqual([s.mode, s.status, s.provenance.counts.logcat], ['dynamic', 'complete', 1]);
  assert.ok(s.outcomes.every((o) => o.ruleId && o.state));
  assert.match(s.outcomes.find((o) => o.state === 'finding').fingerprint, /^[a-f0-9]{16}$/);
});

test('a source that was cut short is inconclusive, never checked, and the session is partial', () => {
  const out = analyzeRecording(rec({ limits: { logcatDropped: 5, socketsDropped: 2, fsTruncated: true, extTruncated: true } }));
  assert.match(one(out, 'dyn.logcat-secrets').reason, /5 log lines were dropped/);
  assert.equal(one(out, 'dyn.cleartext-connection').state, 'inconclusive');
  assert.match(one(out, 'dyn.storage-secrets').reason, /more files than a snapshot lists/);
  assert.equal(one(out, 'dyn.world-readable').state, 'inconclusive');
  assert.equal(one(out, 'dyn.external-storage').state, 'inconclusive');
  assert.equal(one(analyzeRecording(rec({ limits: { logcatEnded: true } })), 'dyn.logcat-secrets').reason, 'the log stream ended before the session did');
  assert.equal(sessionRecord(rec({ limits: { logcatEnded: true } }), { artifactId: 'a'.repeat(64), decompileId: 'b'.repeat(64) }).status, 'partial');
  assert.equal(sessionRecord(rec(), { artifactId: 'a'.repeat(64), decompileId: 'b'.repeat(64) }).status, 'complete');
});

test('a finding still shows when a source was cut short', () => {
  const out = analyzeRecording(rec({ logcat: [log('password=Secret99x')], limits: { logcatDropped: 1 } }));
  assert.equal(of(out, 'dyn.logcat-secrets')[0].state, 'finding');
});

test('log evidence shows the values, provider evidence keeps only row counts, and no fingerprint holds a secret', () => {
  const secrets = ['Secret99x', 'Other1234', 'Jack@123$', 'Zx9y8w7v6u'];
  const steps = [{ t: T0, kind: 'provider', target: 'content://com.x.prov', cmd: 'content query --uri content://com.x.prov', output: `Row: 0 id=1, password=${secrets[0]}, token=${secrets[1]}, note=${secrets[2]}, api_key=${secrets[3]}` }];
  const logs = [log(`login user=jack password=${secrets[0]} token=${secrets[1]} typed ${secrets[2]}`)];
  const s = sessionRecord(rec({ plan: { readonly: true, changing: false, typed: [secrets[2]] }, steps, logcat: logs }), { artifactId: 'a'.repeat(64), decompileId: 'b'.repeat(64) });
  const all = JSON.stringify(s);
  assert.ok(all.includes(secrets[0]) && all.includes(secrets[2]));                                  // the log line is shown as logged
  const prov = JSON.stringify(s.outcomes.filter((o) => o.ruleId === 'dyn.provider-query'));
  for (const x of secrets) assert.ok(!prov.includes(x), `${x} must not be in the provider evidence`);
  for (const x of secrets) assert.ok(s.outcomes.every((o) => !String(o.fingerprint).includes(x)));
  assert.ok(s.outcomes.some((o) => o.state === 'finding' && o.ruleId === 'dyn.provider-query'));
  assert.ok(s.outcomes.some((o) => o.state === 'finding' && o.ruleId === 'dyn.logcat-secrets'));
});

test('the installed APK set is kept, capped and whitelisted', () => {
  const r = cleanRecording({ installed: { sha256s: Array.from({ length: 30 }, () => 'f'.repeat(100)), match: 'yes', evil: 1 } });
  assert.equal(r.installed.sha256s.length, 20);
  assert.equal(r.installed.sha256s[0].length, 64);
  assert.equal(r.installed.match, false);
});

test('probes that were cut short make their rules inconclusive and the session partial', () => {
  const out = analyzeRecording(rec({ limits: { probesCut: true } }));
  assert.match(one(out, 'dyn.provider-query').reason, /still running/);
  assert.equal(one(out, 'dyn.logcat-secrets').state, 'checked');                                    // a passive rule is unaffected
});

test('provider evidence keeps the row count and column names, never the values', () => {
  const steps = [{ t: T0, kind: 'provider', target: 'content://com.x.prov', cmd: 'content query --uri content://com.x.prov', output: 'Row: 0 id=1, refresh_token=abc123def, email=jack@example.com\nRow: 1 id=2, refresh_token=zzz999yyy, email=dev@example.com' }];
  const f = of(analyzeRecording(rec({ steps })), 'dyn.provider-query')[0];
  assert.match(f.evidence[0].excerpt, /2 rows returned\. Columns: id, refresh_token, email\./);
  const all = JSON.stringify(f);
  for (const v of ['abc123def', 'zzz999yyy', 'jack@example.com', 'dev@example.com']) assert.ok(!all.includes(v), v);
});

test('cleartext: no connection observed is inconclusive and tells the user what to do', () => {
  const none = one(analyzeRecording(rec()), 'dyn.cleartext-connection');
  assert.equal(none.state, 'inconclusive');
  assert.match(none.reason, /Use the app's network features/);
});

test('a connection watcher that ended early is inconclusive', () => {
  assert.match(one(analyzeRecording(rec({ sockets: [{ t: T0, remote: '1.2.3.4:443', state: 'ESTABLISHED' }], limits: { socketsEnded: true } })), 'dyn.cleartext-connection').reason, /watcher ended/);
});

test('exported activity: the resumed activity is read in full or relative form, and mCurrentFocus=null does not hide it', () => {
  const step = (target, output) => ({ t: T0, kind: 'activity', target: `com.x.app/${target}`, cmd: `am start -n com.x.app/${target}`, output });
  const titles = (steps) => of(analyzeRecording(rec({ steps })), 'dyn.exported-reachable').filter((o) => o.state === 'finding').map((o) => o.title);
  assert.deepEqual(titles([step('com.x.app.ViewStatement', 'topResumedActivity=ActivityRecord{9f31ff8 u0 com.x.app/.ViewStatement t836}\n  mCurrentFocus=null')]), ['Opens without login: ViewStatement']);
  assert.deepEqual(titles([step('com.x.app.Open', 'mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Open}')]), ['Opens without login: Open']);
  assert.deepEqual(titles([step('com.x.app.Open', 'topResumedActivity=ActivityRecord{1 u0 com.x.app/.Login t5}\n  mCurrentFocus=null')]), []);     // redirected to the login screen
  assert.deepEqual(titles([step('com.x.app.Open', 'topResumedActivity=ActivityRecord{1 u0 com.x.app/.OpenOther t5}')]), []);                    // a different activity with a similar name
});

test('a fully qualified activity name is matched whole, not as the start of a longer one', () => {
  const step = (output) => ({ t: T0, kind: 'activity', target: 'com.x.app/com.x.app.Open', cmd: 'am start -n com.x.app/com.x.app.Open', output });
  const n = (output) => of(analyzeRecording(rec({ steps: [step(output)] })), 'dyn.exported-reachable').filter((o) => o.state === 'finding').length;
  assert.equal(n('mCurrentFocus=Window{1 u0 com.x.app/com.x.app.OpenOther}'), 0);
  assert.equal(n('topResumedActivity=ActivityRecord{1 u0 com.x.app/com.x.app.OpenOther t5}'), 0);
  assert.equal(n('mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Open}'), 1);
  assert.equal(n('topResumedActivity=ActivityRecord{1 u0 com.x.app/com.x.app.Open t5}'), 1);
  assert.equal(n('topResumedActivity=ActivityRecord{1 u0 com.x.app/.OpenOther t5}'), 0);
  assert.equal(n('topResumedActivity=ActivityRecord{1 u0 com.y.app/xcom.x.app.Open t5}'), 0);          // the name sits inside a longer one
});

test('sampled connections: observing some, all on TLS ports, is not clean either', () => {
  const r = one(analyzeRecording(rec({ sockets: [{ t: T0, remote: '1.2.3.4:443', state: 'ESTABLISHED' }] })), 'dyn.cleartext-connection');
  assert.equal(r.state, 'inconclusive');
  assert.match(r.reason, /1 connection observed, all on TLS ports or loopback/);
});

test('warnings from the recorder reach the stored record', () => {
  const s = sessionRecord(rec({ warnings: ['A helper process could not be stopped on the phone.'] }), { artifactId: 'a'.repeat(64), decompileId: 'b'.repeat(64) });
  assert.deepEqual(s.provenance.warnings, ['A helper process could not be stopped on the phone.']);
});

test('an activity that did not show while the screen was off or locked is inconclusive, not "checked"', () => {
  const step = (output) => ({ t: T0, kind: 'activity', target: 'com.x.app/com.x.app.Open', cmd: 'am start -n com.x.app/com.x.app.Open', output });
  const r = (output) => one(analyzeRecording(rec({ steps: [step(output)] })), 'dyn.exported-reachable');
  assert.equal(r('topResumedActivity=x/Keyguard\nmWakefulness=Dozing').state, 'inconclusive');
  assert.equal(r('mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Login}\nisKeyguardShowing=true\nmWakefulness=Awake').state, 'inconclusive');
  assert.equal(r('mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Login}\nisKeyguardShowing=false\nmWakefulness=Awake').state, 'checked');       // awake and unlocked: it really was blocked
  assert.equal(r('mCurrentFocus=Window{1 u0 com.x.app/com.x.app.Open}\nmWakefulness=Dozing').state, 'finding');                                // if it showed, it showed
});

test('a recording at every cap still fits the upload limit', () => {
  const big = { pkg: 'p', logcat: Array.from({ length: 20_000 }, () => ({ t: 1, pid: 1, level: 'D', tag: 'T'.repeat(80), msg: 'é"\\'.repeat(250) })), fs: { before: Array.from({ length: 3000 }, () => ({ path: 'p'.repeat(400), mode: '600', size: 1, mtime: 1, text: 'x'.repeat(2800) })), after: [], matches: [] } };
  const json = JSON.stringify({ id: 'x', recording: cleanRecording(big) });
  assert.ok(json.length < 64 * 1024 ** 2, `${json.length} bytes`);
});

test('a cut source keeps its findings and adds an inconclusive outcome for the same rule', () => {
  const out = analyzeRecording(rec({ plan: { readonly: true, changing: true, typed: ['Jack@123$'] }, logcat: [log('login password=Secret99x')], limits: { logcatDropped: 500 } }));
  const states = of(out, 'dyn.logcat-secrets').map((o) => o.state).sort();
  assert.deepEqual(states, ['finding', 'inconclusive']);
});

test('checks from the research: listening ports, devtools socket, notifications, plain SQLite, provider injection', () => {
  const out = analyzeRecording(rec({
    sockets: [{ t: T0, remote: '0.0.0.0:8080', state: 'LISTEN' }, { t: T0, remote: '127.0.0.1:9000', state: 'LISTEN' }],
    devtools: ['webview_devtools_remote_100', 'webview_devtools_remote_555', 'chrome_devtools_remote'],
    notifications: '  NotificationRecord(0x1: pkg=com.other user=UserHandle{0} id=1)\n        android.text=String (Your code is 999999)\n  NotificationRecord(0x2: pkg=com.x.app user=UserHandle{0} id=2)\n        android.title=String (Bank)\n        android.text=String (Your OTP is 482913)',
    fs: { before: [], after: [], matches: [], sqlite: ['./databases/app.db', './databases/app.db-journal'] },
    steps: [
      { t: T0, kind: 'sqli', target: 'content://com.x.prov/users', cmd: "content query --uri content://com.x.prov/users --where '''", output: 'Error while accessing provider:com.x.prov\nandroid.database.sqlite.SQLiteException: unrecognized token: "\')" (code 1 SQLITE_ERROR)' },
      { t: T0, kind: 'traversal', target: 'content://com.x.files', cmd: 'content read --uri content://com.x.files/..%2Fetc%2Fhosts', output: '127.0.0.1       localhost\n::1             ip6-localhost' },
      { t: T0, kind: 'sqli', target: 'content://com.x.safe', cmd: 'x', output: 'No result found.' }
    ]
  }));
  const t = (id) => of(out, id).filter((o) => o.state === 'finding');
  assert.deepEqual(t('dyn.listening-port').map((f) => f.severity), ['medium', 'low']);
  assert.equal(one(out, 'dyn.cleartext-connection').state, 'inconclusive');                    // listeners are not outgoing connections
  assert.equal(t('dyn.webview-devtools').length, 1);
  assert.deepEqual(t('dyn.notification-secrets').map((f) => f.title), ['A one-time code in a notification']);   // not the other app's
  assert.equal(t('dyn.plaintext-database')[0].title, 'Unencrypted SQLite: 1 file');
  assert.deepEqual(t('dyn.provider-injection').map((f) => f.title.split(':')[0]).sort(), ['Path traversal', 'SQL injection']);
  for (const f of out.filter((o) => o.state === 'finding')) assert.match(String(f.summary.split(/(?<=[.!?])\s+(?=[A-Z])/).length), /^[23]$/, `${f.ruleId}: ${f.summary}`);        // a description is two or three sentences
  const blank = analyzeRecording(rec());
  assert.equal(one(blank, 'dyn.webview-devtools').state, 'not_tested');
  assert.equal(one(blank, 'dyn.notification-secrets').state, 'not_tested');
  assert.equal(one(blank, 'dyn.provider-injection').state, 'not_applicable');
});

test('DragonJAR round, dynamic: service and receiver probes, provider writes, key files, stack traces, App Links, FLAG_SECURE, package flags, work profile', () => {
  const step = (kind, target, cmd, output) => ({ t: T0, kind, target, cmd, output });
  const trace = ['java.lang.IllegalStateException: x', '\tat com.x.app.A.f(A.java:10)', '\tat com.x.app.A.g(A.java:20)', '\tat com.x.app.B.h(B.java:30)'];
  const out = analyzeRecording(rec({
    steps: [
      step('service', 'com.x.app/.Sync', 'am startservice -n com.x.app/.Sync', 'Starting service: Intent { cmp=com.x.app/.Sync }'),
      step('service', 'com.x.app/.Bg', 'am startservice -n com.x.app/.Bg', 'Error: app is in background uid UidRecord{1}'),
      step('receiver', 'com.x.app/.Rcv', 'am broadcast -n com.x.app/.Rcv', 'Broadcast completed: result=0'),
      step('receiver', 'com.x.app/.Locked', 'am broadcast -n com.x.app/.Locked', 'Permission Denial: not exported'),
      step('insert', 'content://com.x.prov', 'content insert --uri content://com.x.prov --bind name:s:loupe-probe', '\nRow: 0 _id=9, name=loupe-probe'),
      step('update', 'content://com.x.prov', 'content update --uri content://com.x.prov --bind name:s:loupe-probe2 --where x', '\nNo result found.'),
      step('window', 'com.x.app', 'dumpsys window windows', 'mAttrs={(0,0)(fillxfill) fl=ALLOW_LOCK_WHILE_SCREEN_ON DIM_BEHIND}')
    ],
    logcat: trace.map((m) => log(m, { tag: 'Net' })),
    fs: { before: [], after: [{ path: './files/client.p12', mode: '600', size: 20, mtime: 0, text: null }, { path: './files/pk.pem', mode: '600', size: 20, mtime: 0, text: '-----BEGIN RSA PRIVATE KEY-----\nabc' }], matches: [], sqlite: [] },
    appLinks: '  Domain verification state:\n    example.com: verified\n    other.example.org: none',
    pkgDump: '    flags=[ DEBUGGABLE HAS_CODE ALLOW_BACKUP ]\n    versionName=1.0',
    workProfile: { profiles: 1, installedIn: ['10'] }
  }));
  const t = (id) => of(out, id).filter((o) => o.state === 'finding');
  assert.deepEqual(t('dyn.exported-service').map((f) => f.title), ['Service starts without a permission: Sync']);
  assert.deepEqual(t('dyn.exported-receiver').map((f) => f.title), ['Receiver accepts a broadcast: Rcv']);
  assert.deepEqual(t('dyn.provider-write').map((f) => f.title.split(':')[0]), ['Provider lets a shell user insert rows']);     // the update returned nothing
  assert.deepEqual(t('dyn.key-files').map((f) => f.severity).sort(), ['high', 'medium']);
  assert.equal(t('dyn.log-stack-trace').length, 1);
  assert.deepEqual(t('dyn.app-links').map((f) => f.title), ['Link not verified: other.example.org']);
  assert.equal(t('dyn.flag-secure').length, 1);
  assert.deepEqual(t('dyn.package-flags').map((f) => f.title).sort(), ['Backups are on for the installed build', 'Installed build is debuggable']);
  assert.equal(t('dyn.work-profile').length, 1);
  for (const f of out.filter((o) => o.state === 'finding' && /^dyn\.(exported-service|exported-receiver|provider-write|key-files|log-stack-trace|app-links|flag-secure|package-flags|work-profile)$/.test(o.ruleId))) assert.match(String(f.summary.split(/(?<=[.!?])\s+(?=[A-Z])/).length), /^[23]$/, f.ruleId);
  const secure = analyzeRecording(rec({ steps: [step('window', 'com.x.app', 'w', 'mAttrs={ fl=ALLOW_LOCK_WHILE_SCREEN_ON SECURE }')] }));
  assert.equal(of(secure, 'dyn.flag-secure').filter((o) => o.state === 'finding').length, 0);
  assert.equal(one(analyzeRecording(rec()), 'dyn.app-links').state, 'not_tested');
  const bg = analyzeRecording(rec({ steps: [step('service', 'com.x.app/.Bg', 'x', 'Error: app is in background uid UidRecord{1}')] }));
  assert.equal(one(bg, 'dyn.exported-service').state, 'inconclusive');
});

test('log secrets also cover session cookies, SSNs and private keys', () => {
  const out = analyzeRecording(rec({ plan: { readonly: true, changing: true, typed: [] }, logcat: [log('Cookie: JSESSIONID=ABCDEF1234567890; path=/'), log('ssn 123-45-6789 ok'), log('-----BEGIN RSA PRIVATE KEY-----')] }));
  assert.deepEqual(of(out, 'dyn.logcat-secrets').filter((o) => o.state === 'finding').map((o) => o.title.split(' in ')[0]).sort(), ['A Social Security number', 'A private key', 'A session cookie']);
});

test('granted dangerous permissions are listed from the package dump', () => {
  const out = analyzeRecording(rec({ pkgDump: '    flags=[ HAS_CODE ]\n      android.permission.CAMERA: granted=true\n      android.permission.INTERNET: granted=true\n      android.permission.READ_CONTACTS: granted=true' }));
  const f = of(out, 'dyn.granted-permissions').filter((o) => o.state === 'finding');
  assert.equal(f.length, 1);
  assert.match(f[0].summary, /CAMERA, READ_CONTACTS/);
  assert.doesNotMatch(f[0].summary, /INTERNET/);
});
