/**
 * Dynamic analysis recorder. It runs in the page because the phone's ADB connection lives there, and takes that connection
 * as `adb` (see session.js) so tests can drive it with a fake phone. A session watches the
 * app's logcat, its network connections and the files in its data folder, optionally runs scripted probes, and returns
 * a recording that the bridge analyzes (proxy/analyzer/dynamic.js). Parsers live in sessionParse.js.
 *
 * Nothing touches the app unless the user ticked the probe group that says so: without it the session only reads.
 * Anything that is dropped, capped or cut short is counted in `limits`, so the analysis can say "inconclusive".
 */
import { PKG, COMPONENT, AUTHORITY, DEEPLINK, quote, parseProcNet, parseLogLine, parseSnapshot, snapshotScript, needlesOf } from './sessionParse.js';

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Rejects when `p` takes longer than `ms`. The underlying command is not cancelled, but nothing waits on it any longer. */
const bounded = (p, ms, what) => { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out`)), ms); })]).finally(() => clearTimeout(t)); };
// Paths a provider often serves although the manifest does not list them (the idea behind drozer's finduris).
const GUESS = ['users', 'accounts', 'data', 'items', 'files', 'messages', 'notes', 'passwords'];
const LIMITS = { logcat: 20_000, sockets: 2000, activities: 12, deeplinks: 8, providers: 6, services: 8, receivers: 8, fuzz: 6 };

let state = { active: false };
let live = null;
const subs = new Set();
const emit = (patch) => { state = { ...state, ...patch }; subs.forEach((f) => f()); };
export const getSession = () => state;
export const subscribe = (f) => { subs.add(f); return () => subs.delete(f); };

/** What this phone and app allow, probed for real. `analyzedShas` are the SHA-256s of the decompiled APK and its splits. */
export async function probe(adb, pkg, analyzedShas) {
  if (!PKG.test(pkg)) throw new Error('The package name is not valid.');
  const run = (c) => adb.run(c).catch((e) => `ERR ${e.message}`);
  const bad = (t) => /^ERR|Permission denied|Operation not permitted|not debuggable|unknown package/i.test(t);

  const uid = Number(/uid:(\d+)/.exec(await run(`pm list packages -U ${pkg}`))?.[1] || 0);
  const paths = [...(await run(`pm path ${pkg}`)).matchAll(/^package:(\S+)/gm)].map((m) => m[1]);
  const shas = [];
  for (const p of paths) shas.push((await run(`sha256sum ${quote(p)}`)).split(/\s+/)[0]);
  const root = await adb.detectRoot();
  const runas = /uid=/.test(await run(`run-as ${pkg} id`));
  const tcp = await run('head -1 /proc/net/tcp');
  const log = await run('logcat -d -t 1');
  const ext = await run(`ls /sdcard/Android/data/${pkg}`);
  const [model, release, sdk] = await Promise.all(['ro.product.model', 'ro.build.version.release', 'ro.build.version.sdk'].map((p) => run(`getprop ${p}`)));
  const t0 = Date.now(), dev = Number(await run('date +%s%3N')), t1 = Date.now();

  return {
    installed: paths.length > 0, uid, apkSha256s: shas, match: shas.length > 0 && [...shas].sort().join() === [...analyzedShas].sort().join(),
    device: { model, release, sdk: Number(sdk) || 0, clockOffsetMs: Number.isFinite(dev) && dev > 0 ? Math.round((t0 + t1) / 2 - dev) : 0 },
    caps: { logcat: !bad(log) && log.length > 0, sockets: /local_address/.test(tcp) && uid > 0, ext: !bad(ext) || /No such file/.test(ext), root, appdata: runas ? 'run-as' : root ? 'root' : null }
  };
}

/** One snapshot of a folder as the app (run-as) or as root. */
async function snapshot(adb, caps, pkg, dir, needles = []) {
  const script = snapshotScript(dir, needles);
  const cmd = caps.appdata === 'root' ? `su -c ${quote(script)}` : `run-as ${pkg} sh -c ${quote(script)}`;
  return parseSnapshot(await bounded(adb.run(cmd), 30_000, 'the snapshot'));
}

/**
 * Starts recording. `o`: { pkg, uid, caps, device, installed: { sha256s, match }, plan: { readonly, changing, typed },
 * targets: { activities, providers: [{ authority }], deeplinks }, onDone(recording) }. Resolves once recording has begun;
 * the scripted probes then run in the background and the user can take over, or stop, at any time.
 */
export async function startSession(adb, o) {
  const sleep = o.sleep || realSleep;
  if (live) throw new Error('A session is already running.');
  if (!PKG.test(o.pkg)) throw new Error('The package name is not valid.');
  const limits = { logcatDropped: 0, socketsDropped: 0, socketsEnded: false, logcatEnded: false, fsTruncated: false, extTruncated: false, probesCut: false };
  const rec = { warnings: [], pkg: o.pkg, uid: o.uid, startedAt: Date.now(), endedAt: 0, device: o.device, installed: o.installed, caps: o.caps, plan: o.plan, pids: [], logcat: [], sockets: [], steps: [], fs: null, ext: null, limits };
  const pids = new Set(), seen = new Set(), timers = [];
  let stopLog = null, stopSocks = null, killWatcher = null, stopping = false, sealed = false, probes = Promise.resolve(), initDone;
  const ready = new Promise((r) => { initDone = r; });
  const counts = () => ({ logcat: rec.logcat.length, sockets: rec.sockets.length, steps: rec.steps.length });
  const say = (step) => { if (!stopping) emit({ step, counts: counts() }); };

  // `stop` exists from the first instant, so Stop can never find it missing. It waits for start-up and for the probes to wind down.
  live = {
    onDone: o.onDone,
    stop: async () => {
      if (stopping) return null;
      stopping = true;
      emit({ stopping: true, step: 'Finishing' });
      // A stalled phone must not trap the user in a session: wait a bounded time for start-up and the probe in flight, then go on and say so.
      await bounded(ready, 8000, 'start-up').catch(() => { limits.probesCut = true; });
      await bounded(probes, 8000, 'the probes').catch(() => { limits.probesCut = true; });
      timers.forEach(clearInterval);
      stopLog?.();
      stopSocks?.();
      await killWatcher?.();
      await sleep(400);
      rec.endedAt = Date.now();
      rec.pids = [...pids];
      // The window again, so "the app stayed open" is something that was seen at the end and not guessed from the launch. Nothing is added when the phone does not answer.
      if (rec.steps.some((s) => s.kind === 'window')) {
        const out = await bounded(adb.run(`dumpsys window windows | grep -F -A30 ${quote(o.pkg + '/')} | grep -E "mAttrs|fl="`), 10_000, 'the window state').catch(() => null);
        if (out !== null) rec.steps.push({ t: Date.now(), kind: 'window-end', target: o.pkg, cmd: 'dumpsys window windows', output: out.slice(0, 2000) });
      }
      // Read once at the end: an open WebView debugging socket, and the text of the notifications the app is showing. null: not readable.
      rec.devtools = await bounded(adb.run('head -1 /proc/net/unix; grep -a devtools_remote /proc/net/unix'), 10_000, 'the socket list').then((t) => (/RefCount/.test(t) ? [...new Set(t.match(/[\w.]*devtools_remote\w*/g) || [])] : null), () => null);
      // Read once at the end: Android's own App Links verdict, the installed package's flags, and whether the app also runs in a work profile.
      rec.appLinks = await bounded(adb.run(`pm get-app-links ${o.pkg}`), 10_000, 'the App Links state').then((t) => (/^ERR|Unknown command|Error/i.test(t) ? null : t), () => null);
      rec.pkgDump = await bounded(adb.run(`dumpsys package ${o.pkg} | grep -E "^ +(flags|pkgFlags|privateFlags|versionName|installerPackageName)=|android\\.permission[.a-z_A-Z]*: granted=true"`), 10_000, 'the package flags').then((t) => (/^ERR/.test(t) || !t.trim() ? null : t), () => null);
      rec.workProfile = await bounded((async () => {
        const users = await adb.run('pm list users');
        const ids = [...users.matchAll(/UserInfo\{(\d+):[^:]*:([0-9a-f]+)\}/gi)].filter((m) => Number(m[1]) > 0 && (parseInt(m[2], 16) & 0x20)).map((m) => m[1]);
        const installedIn = [];
        for (const id of ids.slice(0, 4)) if (/^package:/m.test(await adb.run(`pm path --user ${id} ${o.pkg}`))) installedIn.push(id);
        return { profiles: ids.length, installedIn };
      })(), 15_000, 'the user list').catch(() => null);
      rec.notifications = await bounded(adb.run('dumpsys notification --noredact | grep -E "NotificationRecord|android\\.(title|text|bigText|subText|infoText)=|tickerText="'), 10_000, 'the notification list').then((t) => (/^ERR/.test(t) ? null : t), () => null);
      if (rec.fs) {
        emit({ step: 'Collecting files' });
        const after = await snapshot(adb, o.caps, o.pkg, `/data/data/${o.pkg}`, needlesOf(o.plan.typed).map((n) => n.value)).catch((e) => ({ files: [], matches: [], error: e.message, truncated: true }));
        rec.fs = { error: rec.fs.error || after.error, before: rec.fs.before, after: after.files, matches: after.matches, sqlite: after.sqlite };
        limits.fsTruncated = after.truncated;
      }
      if (o.caps.ext) {
        // A folder that does not exist means the app stored nothing there. Any other failure means shared storage was not checked.
        const e = await bounded(adb.run(snapshotScript(`/sdcard/Android/data/${o.pkg}`)), 30_000, 'the shared storage snapshot').then(parseSnapshot, () => null);
        if (e && (e.complete || e.missing)) { rec.ext = e.files; limits.extTruncated = e.complete && e.truncated; } else rec.ext = null;
      }
      sealed = true;
      return rec;
    }
  };
  emit({ active: true, stopping: false, pkg: o.pkg, startedAt: rec.startedAt, step: 'Preparing', counts: counts(), caps: o.caps, error: '' });

  try {
    // Only the "may change app state" group restarts the app. Otherwise the session just watches.
    if (o.plan.changing) await adb.run(`am force-stop ${o.pkg}`);
    if (!stopping && o.caps.appdata) { const before = await snapshot(adb, o.caps, o.pkg, `/data/data/${o.pkg}`); rec.fs = { error: before.error, before: before.files, after: [], matches: [] }; }

    if (!stopping && o.caps.logcat) {
      // The app may already be running, and its lines are filtered by pid, so learn its pids before the first log line is accepted.
      const readPids = async () => { for (const p of (await adb.run(`pidof ${o.pkg}`)).split(/\s+/)) if (/^\d+$/.test(p)) pids.add(Number(p)); };
      await readPids().catch(() => rec.warnings.push('The app\'s process ids could not be read when the session started, so its first log lines may be missing.'));
      stopLog = await adb.streamLines('logcat -v threadtime -v epoch -T 1', (line) => {
        if (stopping) return;
        const e = parseLogLine(line);
        if (!e) return;
        const m = e.tag === 'ActivityManager' && /Start proc (\d+):([\w.]+)\//.exec(e.msg);
        if (m && m[2] === o.pkg) pids.add(Number(m[1]));
        if (!pids.has(e.pid)) return;
        if (rec.logcat.length < LIMITS.logcat) rec.logcat.push(e); else limits.logcatDropped++;
      }, () => { if (!stopping) limits.logcatEnded = true; });
      timers.push(setInterval(() => { if (!stopping) readPids().catch(() => {}); }, 800));
    }
    if (!stopping && o.caps.sockets && Number.isInteger(o.uid) && o.uid > 0) {
      // A request can open and close in a few milliseconds, so the polling runs on the phone itself, back to back with no pause: one long
      // command that streams only this app's rows, de-duplicated by awk (the uid is an integer, so it is safe in the command). It runs at the
      // lowest priority so the app being tested is not slowed, `timeout` ends it after 30 minutes whatever happens, and Stop kills it by its
      // marker and checks that it is gone (closing the ADB stream alone does not stop a loop on the phone).
      const marker = `loupe-w-${Math.random().toString(16).slice(2, 12)}`, pat = marker.replace(/(.)/, '[$1]');       // [x]yz does not match the command's own line
      // Every phone command here is bounded: a stalled link must not keep Stop from finishing. A step that times out counts as "could not stop".
      const quick = (c) => bounded(adb.run(c), 5000, 'the cleanup command').catch(() => 'ERR');
      killWatcher = async () => {
        await quick(`pkill -9 -f '${pat}'`);
        // pkill returns before the kernel has reaped the processes, so give them a moment before declaring one stuck.
        let left = await quick(`pgrep -f '${pat}'`);
        for (let i = 0; left && left !== 'ERR' && i < 4; i++) { await sleep(250); left = await quick(`pgrep -f '${pat}'`); }       // a timed-out check is not retried
        if (left) rec.warnings.push('A helper process could not be stopped on the phone. It ends by itself within 30 minutes.');
      };
      stopSocks = await adb.streamLines(`timeout 1800 nice -n 19 sh -c 'while :; do grep -h " ${o.uid} " /proc/net/tcp /proc/net/tcp6; done' ${marker} | awk '!s[$2 " " $3 " " $4]++ {print; fflush()}'`, (line) => {
        if (stopping) return;
        for (const r of parseProcNet(line, o.uid)) { const k = `${r.remote}|${r.state}`; if (seen.has(k)) continue; seen.add(k); if (rec.sockets.length < LIMITS.sockets) rec.sockets.push({ t: Date.now(), ...r }); else limits.socketsDropped++; }
      }, () => { if (!stopping) limits.socketsEnded = true; });
    }
    timers.push(setInterval(() => { if (!stopping) emit({ counts: counts() }); }, 500));

    const launch = async () => { const t = Date.now(), cmd = `monkey -p ${o.pkg} -c android.intent.category.LAUNCHER 1`; await adb.run(cmd).catch(() => {}); rec.steps.push({ t, kind: 'launch', target: o.pkg, cmd, output: '' }); };
    const probeStep = async (kind, target, cmd, label) => {
      if (stopping) return;
      say(label);
      const t = Date.now(), out = await adb.run(cmd).catch((e) => `ERR ${e.message}`), ui = kind === 'activity' || kind === 'deeplink' || kind === 'fuzz';
      if (ui) await sleep(1500);
      if (sealed) return;                                  // the recording was finished while this command was in flight
      // Which activity is on screen, and whether the screen was on and unlocked (an activity cannot show otherwise): the resumed activity first (mCurrentFocus is null on some phones even with an app showing), then the focused window.
      const output = !ui ? out.slice(0, 4000) : await adb.run('dumpsys activity activities | grep -m1 -E "topResumedActivity|mResumedActivity"; dumpsys window | grep -m1 mCurrentFocus; dumpsys window | grep -m1 isKeyguardShowing; dumpsys power | grep -m1 mWakefulness').catch(() => '');
      if (!sealed) rec.steps.push({ t, kind, target, cmd, output });
      if (ui && !stopping) { await adb.run('input keyevent KEYCODE_BACK').catch(() => {}); await sleep(600); }
    };

    if (!stopping && o.plan.changing) await launch();
    probes = (async () => {
      if (o.plan.changing) {
        for (const a of o.targets.activities.filter((x) => COMPONENT.test(x)).slice(0, LIMITS.activities)) await probeStep('activity', `${o.pkg}/${a}`, `am start -n ${o.pkg}/${a}`, `Starting ${a.split('.').pop()} from adb`);
        // Fuzzing: the same activities with malformed extras (format strings, huge numbers, a file URI, null). A crash shows missing input checks.
        for (const a of o.targets.activities.filter((x) => COMPONENT.test(x)).slice(0, LIMITS.fuzz)) await probeStep('fuzz', `${o.pkg}/${a}`, `am start -n ${o.pkg}/${a} --es loupe_s ${quote('%s%s%n%x')} --ei loupe_n 2147483647 --el loupe_l -1 --ez loupe_b true --es android.intent.extra.TEXT ${quote('../../../../etc/hosts')} --es uri ${quote('file:///etc/hosts')} --esn loupe_null`, `Fuzzing ${a.split('.').pop()} with odd extras`);
        for (const sv of (o.targets.services || []).filter((x) => COMPONENT.test(x)).slice(0, LIMITS.services)) { await probeStep('service', `${o.pkg}/${sv}`, `am startservice -n ${o.pkg}/${sv}`, `Starting ${sv.split('.').pop()} from adb`); await adb.run(`am stopservice -n ${o.pkg}/${sv}`).catch(() => {}); }
        for (const rc of (o.targets.receivers || []).filter((x) => COMPONENT.test(x)).slice(0, LIMITS.receivers)) await probeStep('receiver', `${o.pkg}/${rc}`, `am broadcast -n ${o.pkg}/${rc}`, `Sending a broadcast to ${rc.split('.').pop()}`);
        for (const d of o.targets.deeplinks.filter((x) => DEEPLINK.test(x)).slice(0, LIMITS.deeplinks)) await probeStep('deeplink', d, `am start -a android.intent.action.VIEW -d ${d} ${o.pkg}`, `Opening ${d}`);
      }
      // Read-only probes: a plain query, a lone quote in the selection (an SQL error means the selection is spliced into the query), and a ../ path to /etc/hosts.
      const notRead = o.targets.providers.filter((x) => x.readable === false && x.writable);
      if (o.plan.changing && notRead.length) rec.warnings.push(`${notRead.map((x) => x.authority).join(', ')} accept${notRead.length === 1 ? 's' : ''} writes without a permission but guard${notRead.length === 1 ? 's' : ''} reads, so Loupe could not pick a column to write and did not test the write surface.`.slice(0, 200));
      if (o.plan.readonly) for (const p of o.targets.providers.filter((x) => AUTHORITY.test(x.authority) && x.readable !== false).slice(0, LIMITS.providers)) for (const path of ['', ...(p.paths || []).filter((x) => /^[\w\-./]+$/.test(x)), ...GUESS.filter((g) => !(p.paths || []).includes(g))]) {
        const guessed = GUESS.includes(path) && !(p.paths || []).includes(path);
        const uri = `content://${p.authority}${path && '/' + path}`;
        await probeStep('provider', uri, `content query --uri ${uri}`, `Querying ${uri}`);
        if (guessed) continue;
        await probeStep('sqli', uri, `content query --uri ${uri} --where ${quote("'")}`, `Testing ${uri} for SQL injection`);
        await probeStep('traversal', uri, `content read --uri ${uri}/..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts`, `Testing ${uri} for path traversal`);
      }
      // Write probes (changing group): add a marked row to a provider that already answered a query, change it, delete it, and always remove it at the end.
      // Only for providers the manifest leaves open for writes as well: a guarded write permission means the shell's success would say nothing about other apps.
      const writeOpen = new Set(o.targets.providers.filter((x) => x.writable).map((x) => x.authority));
      if (o.plan.changing && !stopping) for (const q of rec.steps.filter((x) => x.kind === 'provider' && writeOpen.has(x.target.replace(/^content:\/\//, '').split('/')[0])).slice(0, LIMITS.providers)) {
        const rows = q.output.split('\n').filter((l) => /^Row: /.test(l));
        const col = rows.length && [...rows[0].matchAll(/(?:^Row: \d+ |, )([A-Za-z_]\w*)=([^,]*)/g)].find((m) => m[1] !== '_id' && m[1] !== 'id' && m[2] !== 'NULL' && !/^-?\d+$/.test(m[2].trim()))?.[1];
        if (!col || !/^\w+$/.test(col) || !AUTHORITY.test(q.target.replace(/^content:\/\//, '').split('/')[0])) continue;
        // A random marker per session, matched exactly, so a row the app already holds is never touched. No command starts once Stop was pressed or the recording is sealed;
        // the cleanup below is the one exception, because it removes only this session's own rows.
        let stalled = false;
        const run = (c) => bounded(adb.run(`timeout 5 ${c}`), 6000, 'a write probe').catch((e) => { stalled ||= /timed out/.test(e.message); return `ERR ${e.message}`; }), mark = `loupe-${Math.random().toString(16).slice(2, 10)}`, mark2 = `${mark}-b`, where = (v) => `--where ${quote(`${col}='${v}'`)}`;
        const alive = () => !stopping && !sealed;
        const write = async (kind, cmd, check) => {
          if (!alive()) return false;
          const t = Date.now(), out = await run(cmd), verify = alive() ? (await run(`content query --uri ${q.target} ${check}`)).slice(0, 1500) : '';
          if (!sealed) rec.steps.push({ t, kind, target: q.target, cmd, output: `${out.slice(0, 300)}\n${verify}` });
          return true;
        };
        try {
          await write('insert', `content insert --uri ${q.target} --bind ${col}:s:${mark}`, where(mark));
          await write('update', `content update --uri ${q.target} --bind ${col}:s:${mark2} ${where(mark)}`, where(mark2));
          await write('delete', `content delete --uri ${q.target} ${where(mark2)}`, where(mark2));
        } finally {
          await run(`content delete --uri ${q.target} ${where(mark)}`); await run(`content delete --uri ${q.target} ${where(mark2)}`);
          if (stalled) rec.warnings.push(`A write probe on ${q.target} timed out, so its marked test row (${mark}) may still be in the app.`.slice(0, 200));
        }
      }
      if (!stopping) {
        if (o.plan.changing) {
          await launch(); await sleep(1500);
          if (!stopping) rec.steps.push({ t: Date.now(), kind: 'window', target: o.pkg, cmd: 'dumpsys window windows', output: (await adb.run(`dumpsys window windows | grep -F -A30 ${quote(o.pkg + '/')} | grep -E "mAttrs|fl="`).catch(() => '')).slice(0, 2000) });
        }
        say('Recording. Use the app.');
      }
    })().catch((e) => emit({ error: e.message }));
  } catch (e) {
    // Start-up failed: stop whatever was started and give the session back, so the page can restore its layout and nothing is stored as complete.
    stopping = true; sealed = true;
    timers.forEach(clearInterval); stopLog?.(); stopSocks?.();
    await killWatcher?.();
    live = null;
    emit({ active: false, stopping: false, step: '', error: e.message });
    throw e;
  } finally { initDone(); }
}

/** Stops recording and hands the recording to `onDone`. Resolves with it. */
export function stopSession() {
  if (!live) return Promise.resolve(null);
  const cur = live;
  // One shared teardown: a second Stop waits for it instead of clearing the session while commands are still running.
  return cur.stopped ||= (async () => {
    const rec = await cur.stop();
    if (live === cur) live = null;
    emit({ active: false, stopping: false, step: '' });
    if (rec) await cur.onDone?.(rec);
    return rec;
  })();
}
