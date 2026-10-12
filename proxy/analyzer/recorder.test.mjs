import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { probe, startSession, stopSession, getSession } from '../../src/lib/recorder.js';

// A test that fails halfway must not leave a session running: its timers would keep the process alive and break the tests after it.
afterEach(async () => { await stopSession().catch(() => {}); });

const b64 = (s) => Buffer.from(s).toString('base64');
const SNAP = (files, total = files.length) => [...files.map(([p, text]) => `@@F ${b64(p)} 600 ${text.length} 1 T\n${b64(text)}`), `@@N ${total} 1`].join('\n');

/** A fake phone: records every command, answers from `replies` (first regex that matches), and lets tests feed log lines. */
function phone(replies = [], { slow = null } = {}) {
  const log = [];
  const p = {
    log, streams: [], killed: 0,
    get onLine() { return this.streams.find((x) => /logcat/.test(x.cmd))?.onLine; }, get onEnd() { return this.streams.find((x) => /logcat/.test(x.cmd))?.onEnd; },
    async run(cmd) {
      log.push(cmd);
      if (slow && slow.re.test(cmd)) await slow.wait();
      const hit = replies.find(([re]) => re.test(cmd));
      return hit ? (typeof hit[1] === 'function' ? hit[1](cmd) : hit[1]) : '';
    },
    async streamLines(cmd, onLine, onEnd) { log.push(cmd); p.streams.push({ cmd, onLine, onEnd }); return () => { p.killed++; }; },
    async detectRoot() { return false; }
  };
  return p;
}
const base = (o = {}) => ({
  pkg: 'com.x.app', uid: 10123, device: {}, installed: { sha256s: [], match: true }, caps: { logcat: true, sockets: true, ext: false, root: false, appdata: 'run-as' },
  plan: { readonly: false, changing: false, typed: [] }, targets: { activities: ['com.x.app.Open'], providers: [{ authority: 'com.x.prov' }], deeplinks: ['myapp://open/'] },
  sleep: () => Promise.resolve(), onDone: async () => {}, ...o
});
const ran = (ph, re) => ph.log.filter((c) => re.test(c));
/** Waits until the scripted probes have finished and the session says it is just recording. */
const settle = async () => { for (let i = 0; i < 200 && getSession().step !== 'Recording. Use the app.'; i++) await new Promise((r) => setTimeout(r, 5)); assert.equal(getSession().step, 'Recording. Use the app.'); };
const MUTATING = /am force-stop|monkey|am start|input keyevent/;

test('a watch-only session never touches the app', async () => {
  const ph = phone([[/run-as .* sh -c/, SNAP([])]]);
  await startSession(ph, base());
  const rec = await stopSession();
  assert.equal(ran(ph, MUTATING).length, 0);
  assert.equal(ran(ph, /content query/).length, 0);
  assert.ok(rec.endedAt > 0);
});

test('the read-only group queries providers and nothing else', async () => {
  const ph = phone([[/content query/, 'Row: 0 id=1']]);
  await startSession(ph, base({ plan: { readonly: true, changing: false, typed: [] } }));
  await settle();
  const rec = await stopSession();
  const cmds = ran(ph, /content (query|read)/);
  assert.deepEqual(cmds.slice(0, 3), ['content query --uri content://com.x.prov', "content query --uri content://com.x.prov --where ''\\'''", 'content read --uri content://com.x.prov/..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts']);
  assert.ok(cmds.slice(3).every((c) => /^content query --uri content:\/\/com\.x\.prov\/(users|accounts|data|items|files|messages|notes|passwords)$/.test(c)), 'the guessed paths are plain queries only');
  assert.equal(ran(ph, MUTATING).length, 0);
  assert.deepEqual(rec.steps.slice(0, 3).map((s) => s.kind), ['provider', 'sqli', 'traversal']);
  assert.equal(rec.steps[0].output, 'Row: 0 id=1');
});

test('the changing group restarts the app, starts components, and launches it again', async () => {
  const ph = phone([[/topResumedActivity/, 'topResumedActivity=ActivityRecord{1 u0 com.x.app/.Open t5}\n  mCurrentFocus=null']]);
  await startSession(ph, base({ plan: { readonly: false, changing: true, typed: [] } }));
  await settle();
  const rec = await stopSession();
  assert.equal(ph.log[0], 'am force-stop com.x.app');
  assert.ok(ran(ph, /am start -n com.x.app\/com.x.app.Open( |$)/).length === 2 && ran(ph, /android.intent.action.VIEW -d myapp:\/\/open\//).length === 1);       // the plain start and the fuzzed one
  assert.deepEqual(rec.steps.map((s) => s.kind), ['launch', 'activity', 'fuzz', 'deeplink', 'launch', 'window', 'window-end']);
});

test('hostile names are never run as commands', async () => {
  const ph = phone();
  await startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] }, targets: { activities: ['A; rm -rf /'], services: ['S; rm -rf /'], receivers: ['R && id'], providers: [{ authority: 'x y' }], deeplinks: ['a b://c/'] } }));
  await stopSession();
  assert.equal(ran(ph, /rm -rf|&& id|content query|VIEW/).length, 0);
});

test('Stop during start-up is safe and nothing runs after it', async () => {
  let release;
  const ph = phone([], { slow: { re: /am force-stop/, wait: () => new Promise((r) => { release = r; }) } });
  const started = startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] } }));
  await new Promise((r) => setImmediate(r));
  const stopped = stopSession();                       // the page's Stop button, while force-stop is still running
  release();
  await started;
  const rec = await stopped;
  assert.ok(rec);
  const after = ph.log.length;
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(ph.log.length, after);                  // no probe started, nothing ran late
  assert.equal(ran(ph, /am start|content query|monkey/).length, 0);
  assert.equal(getSession().active, false);
});

test('Stop during a probe waits for it and issues no BACK key afterwards', async () => {
  let release;
  const ph = phone([], { slow: { re: /am start -n/, wait: () => new Promise((r) => { release = r; }) } });
  await startSession(ph, base({ plan: { readonly: false, changing: true, typed: [] } }));
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(release, 'the probe is in flight');
  let done = false;
  const stopped = stopSession().then((r) => { done = true; return r; });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(done, false);                           // still waiting for the in-flight probe
  release();
  const rec = await stopped;
  assert.equal(ran(ph, /input keyevent/).length, 0);
  assert.equal(rec.steps.filter((s) => s.kind === 'activity').length, 1);
  const after = ph.log.length;
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(ph.log.length, after);
});

test('logs from the app are recorded, others are not, and drops and early ends are counted', async () => {
  const ph = phone([[/pidof/, '100']]);
  await startSession(ph, base());
  ph.onLine('         1791602936.539  100   100 D DoLogin: hello');
  ph.onLine('         1791602936.540  200   200 D Other: nope');
  ph.onLine('         1791602936.541  300   300 I ActivityManager: Start proc 300:com.x.app/u0a1 for service');
  ph.onLine('         1791602936.542  300   300 D Svc: from the new process');
  ph.onEnd();                                          // the log stream died by itself
  const rec = await stopSession();
  assert.deepEqual(rec.logcat.map((e) => e.tag), ['DoLogin', 'ActivityManager', 'Svc']);   // pid 100 was already running: it is read before the stream starts
  assert.equal(rec.limits.logcatEnded, true);
  assert.deepEqual(rec.pids, [100, 300]);
});

test('a failed pid lookup at the start is said so, not silently treated as no early logs', async () => {
  const ph = phone();
  const run = ph.run;
  ph.run = async (cmd) => { if (/pidof/.test(cmd)) throw new Error('adb hiccup'); return run(cmd); };
  await startSession(ph, base());
  assert.match((await stopSession()).warnings.join(' '), /process ids could not be read/);
});

test('the snapshot, its truncation, and the typed-value search reach the recording', async () => {
  const typed = ['Jack@123$'];
  const ph = phone([[/run-as com.x.app sh -c/, (cmd) => (cmd.includes('SmFja0AxMjMk') ? SNAP([['./a.xml', 'x']]).replace(/\n@@N .*$/, '') : SNAP([]))]]);   // the after-snapshot output is cut off before its trailer
  await startSession(ph, base({ plan: { readonly: false, changing: false, typed } }));
  const rec = await stopSession();
  assert.deepEqual(rec.fs.after.map((f) => f.path), ['./a.xml']);
  assert.equal(rec.limits.fsTruncated, true);          // no trailer: the snapshot did not finish
  assert.match(rec.fs.error, /did not finish/);
  const after = ran(ph, /run-as/)[1];
  assert.ok(after.includes('Jack@123$') && after.includes('SmFja0AxMjMk'), 'the typed value and its Base64 form are searched for');
});

test('probe compares the whole APK set, splits included', async () => {
  const replies = (a, b) => [[/pm list packages/, 'package:com.x.app uid:10123'], [/pm path/, 'package:/data/app/base.apk\npackage:/data/app/split_en.apk'],
    [/sha256sum .*base/, `${a}  /data/app/base.apk`], [/sha256sum .*split/, `${b}  /data/app/split_en.apk`], [/head -1 \/proc\/net\/tcp/, 'sl local_address'], [/logcat -d/, 'line'], [/date \+%s%3N/, String(Date.now())]];
  const ok = await probe(phone(replies('aa', 'bb')), 'com.x.app', ['bb', 'aa']);
  assert.deepEqual([ok.installed, ok.uid, ok.match, ok.apkSha256s], [true, 10123, true, ['aa', 'bb']]);
  assert.equal((await probe(phone(replies('aa', 'cc')), 'com.x.app', ['aa', 'bb'])).match, false);       // a split differs
  assert.equal((await probe(phone(replies('aa', 'bb')), 'com.x.app', ['aa'])).match, false);              // an extra installed split
  await assert.rejects(() => probe(phone(), 'bad; name', []), /not valid/);
});

test('shared storage: a failed or cut-off read is not checked, a missing folder is empty', async () => {
  const ext = (reply) => phone([[/sdcard\/Android\/data/, reply]]);
  const run = async (ph) => { await startSession(ph, base({ caps: { logcat: false, sockets: false, ext: true, root: false, appdata: null } })); return stopSession(); };
  assert.equal((await run(ext(() => { throw new Error('adb gone'); }))).ext, null);               // the command failed
  assert.equal((await run(ext(''))).ext, null);                                                    // empty output: no trailer
  assert.deepEqual((await run(ext('@@ERR cannot enter the folder'))).ext, []);                    // the app has no folder there
  assert.deepEqual((await run(ext(SNAP([['./n.txt', 'hi']])))).ext.map((f) => f.path), ['./n.txt']);
});

test('Stop does not hang on a stalled phone: it finishes and reports the probes as cut', async () => {
  const ph = phone([], { slow: { re: /content query/, wait: () => new Promise(() => {}) } });       // never answers
  await startSession(ph, base({ plan: { readonly: true, changing: false, typed: [] } }));
  await new Promise((r) => setTimeout(r, 20));
  const t0 = Date.now();
  const rec = await stopSession();
  assert.ok(Date.now() - t0 < 12_000);
  assert.equal(rec.limits.probesCut, true);
  assert.equal(getSession().active, false);
});

test('connections come from one streaming watcher on the phone, de-duplicated, and it is stopped with the session', async () => {
  const ph = phone();
  await startSession(ph, base());
  const w = ph.streams.find((x) => /\/proc\/net\/tcp/.test(x.cmd));
  assert.ok(w.cmd.includes('grep -h " 10123 "') && w.cmd.includes('/proc/net/tcp6') && w.cmd.includes('awk') && w.cmd.startsWith('timeout 1800 nice -n 19 '), 'filters to the app uid on the phone, de-duplicates, runs at the lowest priority, and has a hard time limit');
  const row = (st) => `   1: C900A8C0:D2F4 CC00A8C0:1F90 ${st} 00000000:00000000 00:00000000 00000000 10123        0 2 1 0`;
  w.onLine(row('01')); w.onLine(row('01')); w.onLine(row('06'));
  w.onLine('   2: C900A8C0:D2F5 CC00A8C0:1F90 01 00000000:00000000 00:00000000 00000000 999        0 2 1 0');   // another uid
  const rec = await stopSession();
  assert.deepEqual(rec.sockets.map((s) => [s.remote, s.state]), [['192.168.0.204:8080', 'ESTABLISHED'], ['192.168.0.204:8080', 'TIME_WAIT']]);
  assert.ok(ph.killed >= 2, 'the log and connection streams are both killed');
  const marker = /(loupe-w-[0-9a-f]+)/.exec(w.cmd)[1];
  const kill = ran(ph, /pkill -9/)[0];
  assert.ok(kill && new RegExp(kill.match(/'([^']+)'/)[1]).test(marker) && !new RegExp(kill.match(/'([^']+)'/)[1]).test(kill), 'Stop kills the loop by its marker, and the pattern does not match its own command line');
});

test('a connection watcher that dies early is recorded', async () => {
  const ph = phone();
  await startSession(ph, base());
  ph.streams.find((x) => /\/proc\/net\/tcp/.test(x.cmd)).onEnd();
  assert.equal((await stopSession()).limits.socketsEnded, true);
});

test('a session without a valid uid never builds a connection command', async () => {
  const ph = phone();
  await startSession(ph, base({ uid: '1; rm -rf /' }));
  await stopSession();
  assert.ok(!ph.log.some((c) => /\/proc\/net\/tcp/.test(c)));
});

test('Stop checks that the watcher is gone, and says so when it is not', async () => {
  const stuck = phone([[/pgrep/, '4242']]);                                       // the process is still there after the kill
  await startSession(stuck, base());
  const rec = await stopSession();
  assert.match(rec.warnings[0], /helper process could not be stopped/);
  assert.ok(ran(stuck, /pkill -9/).length === 1 && ran(stuck, /pgrep/).length === 5);
  const clean = phone();
  await startSession(clean, base());
  assert.deepEqual((await stopSession()).warnings, []);
});

test('a start-up failure rejects, stops what was started, and leaves no session behind', async () => {
  const ph = phone();
  ph.run = async (cmd) => { ph.log.push(cmd); if (/am force-stop/.test(cmd)) throw new Error('device went away'); return ''; };
  await assert.rejects(() => startSession(ph, base({ plan: { readonly: false, changing: true, typed: [] } })), /device went away/);
  assert.equal(getSession().active, false);
  assert.match(getSession().error, /device went away/);
  await startSession(phone(), base());                                            // a new session can start straight away
  await stopSession();
});

test('a start-up failure after the collectors started kills them', async () => {
  const ph = phone([[/run-as .* sh -c/, () => { throw new Error('snapshot failed'); }]]);
  await assert.rejects(() => startSession(ph, base({ caps: { logcat: true, sockets: true, ext: false, root: false, appdata: 'run-as' } })), /snapshot failed/);
  assert.equal(getSession().active, false);
  assert.ok(ran(ph, /pkill -9/).length === 0 || ph.killed >= 0);                  // nothing was left running
});

test('the changing group starts services, broadcasts to receivers, and tests writes on a provider with a marked, removed row', async () => {
  const ph = phone([[/content query --uri content:\/\/com\.x\.prov$/, 'Row: 0 _id=1, name=jack, n=5'], [/content query --uri content:\/\/com\.x\.prov --where/, 'Row: 0 _id=9, name=loupe-x']]);
  await startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] }, targets: { activities: [], services: ['com.x.app.Sync'], receivers: ['com.x.app.Rcv'], providers: [{ authority: 'com.x.prov', writable: true }], deeplinks: [] } }));
  await settle();
  const rec = await stopSession();
  assert.equal(ran(ph, /am startservice -n com.x.app\/com.x.app.Sync/).length, 1);
  assert.equal(ran(ph, /am stopservice -n com.x.app\/com.x.app.Sync/).length, 1);
  assert.equal(ran(ph, /am broadcast -n com.x.app\/com.x.app.Rcv/).length, 1);
  assert.equal(ran(ph, /content insert --uri content:\/\/com\.x\.prov --bind name:s:loupe-[0-9a-f]{8}$/).length, 1);
  assert.equal(ran(ph, /content update .*loupe-[0-9a-f]{8}-b/).length, 1);
  assert.equal(ran(ph, /LIKE/).length, 0);                                 // never a pattern match: a row the app already holds is safe
  assert.ok(ran(ph, /content delete .*name=.*loupe-[0-9a-f]{8}\W/).length >= 1);          // the cleanup always runs, on the exact marker
  assert.ok(['service', 'receiver', 'insert', 'update', 'delete'].every((k) => rec.steps.some((x) => x.kind === k)));
});

test('write probes need the changing group', async () => {
  const ph = phone([[/content query/, 'Row: 0 _id=1, name=jack']]);
  await startSession(ph, base({ plan: { readonly: true, changing: false, typed: [] } }));
  await settle();
  await stopSession();
  assert.equal(ran(ph, /content (insert|update|delete)|startservice|broadcast/).length, 0);
});

test('no write probe starts once Stop was pressed, and the recording does not gain a late step', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const ph = phone([[/content query --uri content:\/\/com\.x\.prov$/, 'Row: 0 _id=1, name=jack']], { slow: { re: /content insert/, wait: () => gate } });
  await startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] }, targets: { activities: [], providers: [{ authority: 'com.x.prov', writable: true }], deeplinks: [] } }));
  for (let i = 0; i < 100 && !ran(ph, /content insert/).length; i++) await new Promise((r) => setTimeout(r, 5));
  const rec = await stopSession();                      // the insert is still stalled
  release(); await new Promise((r) => setTimeout(r, 50));
  assert.equal(ran(ph, /content update|content delete .*-b'/).filter((c) => /update/.test(c)).length, 0);
  assert.ok(!rec.steps.some((s) => s.kind === 'update' || s.kind === 'delete'));
});

test('a provider whose writes are guarded gets no write probe', async () => {
  const ph = phone([[/content query/, 'Row: 0 _id=1, name=jack']]);
  await startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] }, targets: { activities: [], providers: [{ authority: 'com.x.prov', writable: false }], deeplinks: [] } }));
  await settle();
  await stopSession();
  assert.equal(ran(ph, /content (insert|update|delete)/).length, 0);
});

test('a stalled phone cannot keep Stop from finishing: the cleanup commands time out', async () => {
  const ph = phone([], { slow: { re: /pkill|pgrep/, wait: () => new Promise(() => {}) } });         // these two never answer
  await startSession(ph, base({ plan: { readonly: false, changing: false, typed: [] } }));
  const t0 = Date.now();
  const rec = await stopSession();
  assert.ok(rec.endedAt > 0);
  assert.ok(Date.now() - t0 < 30_000);
  assert.ok(rec.warnings.some((w) => /helper process could not be stopped/.test(w)));
});

test('a provider that accepts writes but guards reads is reported as not tested', async () => {
  const ph = phone();
  await startSession(ph, base({ plan: { readonly: true, changing: true, typed: [] }, targets: { activities: [], providers: [{ authority: 'com.x.prov', readable: false, writable: true }], deeplinks: [] } }));
  await settle();
  const rec = await stopSession();
  assert.ok(rec.warnings.some((w) => /guards? reads/.test(w)));
  assert.equal(ran(ph, /content (query|insert)/).length, 0);
});

test('a second Stop shares the first teardown instead of clearing the session', async () => {
  const ph = phone([[/run-as .* sh -c/, SNAP([])]]);
  await startSession(ph, base());
  const a = stopSession(), b = stopSession();
  assert.equal(a, b);
  assert.equal(await a, await b);
  assert.equal(getSession().active, false);
});
