/**
 * Dynamic analysis: turns what a session recorded (see src/lib/session.js) into outcomes. The recording comes from
 * the page but its content comes from a phone running an untrusted app, so `cleanRecording` rebuilds it from
 * whitelisted, size-capped fields before any rule sees it. A rule whose prerequisite was missing or whose probe group
 * the user declined is `not_tested` with the reason, never `checked`.
 */
import crypto from 'node:crypto';
import { finding } from './evidence.js';
import { cleanOutcome, str } from './outcome.js';
import { sensitive } from './redact.js';
import { standardsFor, SNAPSHOT } from './standards.js';
import { needlesOf } from '../../src/lib/sessionParse.js';

// Sized so a full recording stays well under the 64 MiB upload limit: 20k log lines of at most 500 characters (10 MB), three snapshots of at most 8 MB of text, a little else.
const CAP = { logcat: 20_000, sockets: 2000, steps: 400, files: 3000, text: 65_536, line: 500 };
const num = (v) => (Number.isFinite(v) ? v : 0);
const arr = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);

export function cleanRecording(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const c = r.caps || {}, p = r.plan || {}, d = r.device || {};
  const files = (f) => arr(f, CAP.files).map((x) => ({ path: str(x?.path, 400), mode: str(x?.mode, 8), size: num(x?.size), mtime: num(x?.mtime), text: typeof x?.text === 'string' ? x.text.slice(0, CAP.text) : null })).filter((x) => x.path);
  return {
    pkg: str(r.pkg, 200), uid: num(r.uid), startedAt: num(r.startedAt), endedAt: num(r.endedAt),
    device: { model: str(d.model, 80), release: str(d.release, 20), sdk: num(d.sdk), clockOffsetMs: num(d.clockOffsetMs) },
    installed: { sha256s: arr(r.installed?.sha256s, 20).map((x) => str(x, 64)), match: r.installed?.match === true },
    warnings: arr(r.warnings, 5).map((w) => str(w, 200)).filter(Boolean),
    limits: { logcatDropped: num(r.limits?.logcatDropped), socketsDropped: num(r.limits?.socketsDropped), socketsEnded: !!r.limits?.socketsEnded, logcatEnded: !!r.limits?.logcatEnded, fsTruncated: !!r.limits?.fsTruncated, extTruncated: !!r.limits?.extTruncated, probesCut: !!r.limits?.probesCut },
    caps: { logcat: !!c.logcat, sockets: !!c.sockets, ext: !!c.ext, root: !!c.root, appdata: c.appdata === 'run-as' || c.appdata === 'root' ? c.appdata : null },
    plan: { readonly: !!p.readonly, changing: !!p.changing, typed: arr(p.typed, 10).map((t) => str(t, 200)).filter((t) => t.length >= 3) },
    pids: arr(r.pids, 50).map(num),
    logcat: arr(r.logcat, CAP.logcat).map((e) => ({ t: num(e?.t), pid: num(e?.pid), level: str(e?.level, 1), tag: str(e?.tag, 80), msg: str(e?.msg, CAP.line) })),
    sockets: arr(r.sockets, CAP.sockets).map((s) => ({ t: num(s?.t), remote: str(s?.remote, 80), state: str(s?.state, 16) })),
    steps: arr(r.steps, CAP.steps).map((s) => ({ t: num(s?.t), kind: ['launch', 'activity', 'deeplink', 'provider', 'sqli', 'traversal', 'fuzz', 'service', 'receiver', 'insert', 'update', 'delete', 'window'].includes(s?.kind) ? s.kind : 'launch', target: str(s?.target, 300), cmd: str(s?.cmd, 400), output: str(s?.output, 4000) })),
    fs: r.fs && typeof r.fs === 'object' ? { error: str(r.fs.error, 200), before: files(r.fs.before), after: files(r.fs.after), matches: arr(r.fs.matches, 200).map((m) => ({ needle: num(m?.needle), path: str(m?.path, 400) })), sqlite: arr(r.fs.sqlite, 200).map((x) => str(x, 400)).filter(Boolean) } : null,
    ext: Array.isArray(r.ext) ? { files: files(r.ext) } : null,
    devtools: Array.isArray(r.devtools) ? arr(r.devtools, 50).map((x) => str(x, 200)) : null,
    notifications: typeof r.notifications === 'string' ? r.notifications.slice(0, 20_000) : null,
    appLinks: typeof r.appLinks === 'string' ? r.appLinks.slice(0, 20_000) : null,
    pkgDump: typeof r.pkgDump === 'string' ? r.pkgDump.slice(0, 16_000) : null,
    workProfile: r.workProfile && typeof r.workProfile === 'object' ? { profiles: num(r.workProfile.profiles), installedIn: arr(r.workProfile.installedIn, 4).map((x) => str(x, 8)) } : null
  };
}

const adbShell = (cmd) => (cmd ? ['adb', 'shell', ...cmd.split(' ')] : []);
const hhmmss = (t) => new Date(t).toISOString().slice(11, 23);
const logLine = (e, off) => `${hhmmss(e.t + off)} ${e.level} ${e.tag}: ${e.msg}`;

// ── rules ──────────────────────────────────────────────────────────────────
const logcatSecrets = {
  id: 'dyn.logcat-secrets', title: 'Sensitive data written to logcat', category: 'STORAGE', needs: ['logcat'],
  run(rec) {
    const pids = new Set(rec.pids), off = rec.device.clockOffsetMs, seen = new Set(), findings = [];
    rec.logcat.forEach((e, i) => {
      if (!pids.has(e.pid)) return;
      for (const h of sensitive(e.msg, rec.plan.typed)) {
        const key = `${e.tag}|${h.label}`;
        if (seen.has(key) || findings.length >= 50) continue;
        seen.add(key);
        findings.push(finding('dyn.logcat-secrets', {
          key, title: `${h.label} in logcat (${e.tag})`, severity: 'high', detection: h.exact ? 'exact' : 'probable', conclusion: 'confirmed',
          summary: `The app wrote ${h.label.toLowerCase()} to the system log. Anyone with adb, and other apps on older Android versions, can read it.`,
          evidence: [{ kind: 'logcat', ref: { path: 'logcat', startLine: i + 1, endLine: i + 1, hitLine: i + 1 }, excerpt: logLine(e, off), note: `pid ${e.pid}` }],
          repro: { steps: ['Start a session and repeat the action that logged this.', 'Run the command and search for the tag.'], command: ['adb', 'logcat', '-d', '-s', e.tag.replace(/[^\w.-]/g, '')] }
        }));
      }
    });
    return { findings };
  }
};

const crash = {
  id: 'dyn.crash', title: 'App crashes when started from adb', category: 'PLATFORM', group: 'changing', needs: ['logcat'],
  run(rec) {
    const pids = new Set(rec.pids), off = rec.device.clockOffsetMs, findings = [];
    const KINDS = ['activity', 'deeplink', 'fuzz', 'service', 'receiver'];
    if (!rec.steps.some((s) => KINDS.includes(s.kind))) return { notApplicable: 'no component was started from adb' };
    for (const st of rec.steps.filter((s) => KINDS.includes(s.kind))) {
      const i = rec.logcat.findIndex((e) => e.tag === 'AndroidRuntime' && pids.has(e.pid) && /FATAL EXCEPTION/.test(e.msg) && e.t + off >= st.t && e.t + off <= st.t + 6000);
      if (i < 0) continue;
      const lines = [];
      for (let j = i; j < rec.logcat.length && lines.length < 8 && rec.logcat[j].tag === 'AndroidRuntime'; j++) lines.push(logLine(rec.logcat[j], off));
      findings.push(finding('dyn.crash', {
        key: st.target, title: `Crash when starting ${st.target.split('/').pop()}`, severity: 'medium', detection: 'exact', conclusion: 'exposure',
        summary: st.kind === 'fuzz' ? `Starting ${st.target} with malformed extras (format strings, a huge number, a file URI, a null) crashed the app. Another app can send the same Intent, which is a denial of service and shows the component does not check its input.` : `Starting ${st.target} crashed the app. Another app can do the same, which is a denial of service and may point to unchecked input.`,
        evidence: [{ kind: 'logcat', ref: { path: 'logcat', startLine: i + 1, endLine: i + lines.length, hitLine: i + 1 }, excerpt: lines.join('\n'), note: st.cmd }],
        repro: { steps: ['Run the command with the app installed.'], command: probeCmd(st) }
      }));
    }
    return { findings };
  }
};

const PLAIN_PORTS = new Set(['80', '8080', '8000', '8008']);
const TLS_PORTS = new Set(['443', '8443', '993', '995', '465', '853', '636', '5228', '5223']);
const cleartext = {
  id: 'dyn.cleartext-connection', title: 'Connection to a non-TLS port', category: 'NETWORK', needs: ['sockets'],
  run(rec) {
    const seen = new Set(), findings = [];
    // Connections are sampled: a short one can be missed, so not seeing a plain HTTP connection never proves there was none.
    // A well-known HTTP port is `probable`; any other port that is not a TLS port is only `heuristic`, since the content is never seen.
    const seenCount = rec.sockets.filter((s) => s.state !== 'LISTEN').length;
    for (const s of rec.sockets) {
      const m = /^(.+):(\d+)$/.exec(s.remote);
      if (!m || s.state === 'LISTEN' || TLS_PORTS.has(m[2]) || /^(127\.|::1$|\[::1\])/.test(m[1]) || seen.has(s.remote)) continue;
      seen.add(s.remote);
      const plain = PLAIN_PORTS.has(m[2]);
      findings.push(finding('dyn.cleartext-connection', {
        key: s.remote, title: `Connection to ${s.remote}`, severity: plain ? 'medium' : 'low', detection: plain ? 'probable' : 'heuristic', conclusion: 'exposure',
        summary: `The app opened a connection to ${s.remote}. ${plain ? `Port ${m[2]} is normally plain HTTP, so a network attacker can likely read and change the traffic.` : `Port ${m[2]} is not a standard TLS port, so a network attacker may be able to read and change the traffic.`} The session saw only the port, so the content itself was never seen.`,
        evidence: [{ kind: 'command', ref: { path: '/proc/net/tcp', startLine: null, endLine: null, hitLine: null }, excerpt: `uid ${rec.uid}  ${s.remote}  ${s.state}`, focus: s.remote, note: `first seen ${hhmmss(s.t)}` }],
        repro: { steps: ['Start a session and repeat the action. Check the Network tab for the connection.', 'Point the phone at your proxy to read the request.'], command: [] }
      }));
    }
    if (findings.length) return { findings };
    return { inconclusive: seenCount ? `${seenCount} connection${seenCount === 1 ? '' : 's'} observed, all on TLS ports or loopback. Connections are sampled and a short one can be missed, so confirm with a proxy` : 'no connection from the app was observed. Use the app\'s network features during the session, and confirm with a proxy' };
  }
};

const status = (before, f) => { const b = before.find((x) => x.path === f.path); return !b ? 'new' : b.text !== f.text ? 'changed' : 'unchanged'; };

const storageSecrets = {
  id: 'dyn.storage-secrets', title: 'Sensitive data stored in app files', category: 'STORAGE', needs: ['appdata'],
  run(rec) {
    const { before, after, matches } = rec.fs, needles = needlesOf(rec.plan.typed), seen = new Set(), findings = [];
    const add = (path, h, text, st) => {
      const key = `${path}|${h.label}`;
      if (seen.has(key) || findings.length >= 50) return;
      seen.add(key);
      const line = text ? (text.split('\n').find((l) => l.includes(h.value)) || '').slice(0, 240) : '(binary file, matched by search)';
      findings.push(finding('dyn.storage-secrets', {
        key, title: `${h.label} in ${path.split('/').pop()}`, severity: 'high', detection: h.exact ? 'exact' : 'probable', conclusion: 'confirmed',
        summary: `${h.label} is stored in ${path} (${st}) without encryption. Anyone who can read the app's data (a debuggable build, a backup, a rooted device) can read it.`,
        evidence: [{ kind: 'file-diff', ref: { path, startLine: null, endLine: null, hitLine: null }, excerpt: `${st === 'unchanged' ? ' ' : '+'} ${line}`, note: st }],
        repro: { steps: ['Use the app so it saves this data, then run the command.'], command: rec.caps.appdata === 'run-as' ? ['adb', 'shell', 'run-as', rec.pkg, 'cat', path.replace(/^\.\//, '')] : [] }
      }));
    };
    for (const f of after) if (f.text) for (const h of sensitive(f.text, rec.plan.typed)) add(f.path, h, f.text, status(before, f));
    for (const m of matches) { const n = needles[m.needle]; if (n) add(m.path, { label: n.label, value: n.value, exact: true }, after.find((f) => f.path === m.path)?.text ?? null, 'found by search'); }
    return { findings };
  }
};

const worldReadable = {
  id: 'dyn.world-readable', title: 'App files readable by other apps', category: 'STORAGE', needs: ['appdata'],
  run(rec) {
    const findings = [];
    for (const f of rec.fs.after) {
      const o = parseInt(f.mode, 8) & 0o007;
      if (!(o & 6) || findings.length >= 50) continue;
      findings.push(finding('dyn.world-readable', {
        key: f.path, title: `${o & 2 ? 'World-writable' : 'World-readable'} file: ${f.path.split('/').pop()}`, severity: o & 2 ? 'high' : 'medium', detection: 'exact', conclusion: 'weakness',
        summary: `${f.path} has mode ${f.mode}, which makes it ${o & 2 ? 'world-writable' : 'world-readable'}. Any other app on the device can ${o & 2 ? 'change its contents, and the app may later use what an attacker wrote' : 'read its contents'}.`,
        evidence: [{ kind: 'file-diff', ref: { path: f.path, startLine: null, endLine: null, hitLine: null }, excerpt: `mode ${f.mode}  ${f.size} bytes  ${f.path}`, note: '' }],
        repro: { steps: ['List the file with its mode.'], command: rec.caps.appdata === 'run-as' ? ['adb', 'shell', 'run-as', rec.pkg, 'ls', '-l', f.path.replace(/^\.\//, '')] : [] }
      }));
    }
    return { findings };
  }
};

const externalStorage = {
  id: 'dyn.external-storage', title: 'Sensitive data on external storage', category: 'STORAGE', needs: ['ext'],
  run(rec) {
    const findings = [], seen = new Set();
    for (const f of rec.ext.files) {
      if (!f.text) continue;
      for (const h of sensitive(f.text, rec.plan.typed)) {
        const key = `${f.path}|${h.label}`;
        if (seen.has(key) || findings.length >= 50) continue;
        seen.add(key);
        findings.push(finding('dyn.external-storage', {
          key, title: `${h.label} in ${f.path.split('/').pop()}`, severity: 'medium', detection: h.exact ? 'exact' : 'probable', conclusion: 'confirmed',
          summary: `${h.label} is stored at ${f.path} on shared storage. Other apps with access to shared storage may read it.`,
          evidence: [{ kind: 'file-diff', ref: { path: f.path, startLine: null, endLine: null, hitLine: null }, excerpt: (f.text.split('\n').find((l) => l.includes(h.value)) || '').slice(0, 240), note: '' }],
          repro: { steps: ['List the folder from adb.'], command: ['adb', 'shell', 'ls', '-l', f.path] }
        }));
      }
    }
    return { findings };
  }
};

const exportedReachable = {
  id: 'dyn.exported-reachable', title: 'Exported activity opens from adb', category: 'PLATFORM', group: 'changing', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => s.kind === 'activity');
    if (!steps.length) return { notApplicable: 'no exported activity was started from adb' };
    const findings = [];
    const asleep = (st) => /mWakefulness=(?!Awake)/.test(st.output) || /isKeyguardShowing=true/.test(st.output);          // an activity cannot appear then, so "did not open" would mean nothing
    for (const st of steps) {
      const cls = st.target.split('/').pop();
      // The phone prints the class in full or relative to the package (com.x/.Open). Anything else on top means it was blocked, redirected or crashed.
      const named = (name, lead) => new RegExp(`${lead}${name.replace(/[.$]/g, '\\$&')}(?![\\w$])`).test(st.output);        // the whole class name, not a prefix of a longer one
      const shown = cls && (named(cls, '(?<![\\w.$])') || (cls.startsWith(`${rec.pkg}.`) && named(cls.slice(rec.pkg.length), '/')));
      if (!shown) continue;
      findings.push(finding('dyn.exported-reachable', {
        key: st.target, title: `Opens without login: ${cls.split('.').pop()}`, severity: 'medium', detection: 'exact', conclusion: 'exposure',
        summary: `Starting ${st.target} from the adb shell put it on screen. The shell is more privileged than an ordinary app, so this shows it is reachable from the shell, which is a strong hint it is reachable from other apps too.`,
        evidence: [{ kind: 'command', ref: { path: 'adb', startLine: null, endLine: null, hitLine: null }, excerpt: `$ ${st.cmd}\n${st.output.split('\n')[0]}`, note: `at ${hhmmss(st.t)}` }],
        repro: { steps: ['Run the command with the app installed and the screen on.'], command: adbShell(st.cmd) }
      }));
    }
    const blind = steps.filter(asleep).length;
    if (!findings.length && blind) return { inconclusive: `the screen was off or locked during ${blind} of ${steps.length} activity start${steps.length === 1 ? '' : 's'}, so whether they open is unknown. Wake and unlock the phone and run a new session` };
    return { findings };
  }
};

const providerQuery = {
  id: 'dyn.provider-query', title: 'Content provider returns data', category: 'PLATFORM', group: 'readonly', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => s.kind === 'provider');
    if (!steps.length) return { notApplicable: 'the app exports no content provider without a permission' };
    const findings = [];
    for (const st of steps) {
      const rows = st.output.split('\n').filter((l) => /^Row: /.test(l));
      if (!rows.length) continue;
      const cols = [...new Set(rows.flatMap((l) => [...l.matchAll(/(?:^Row: \d+ |, )([A-Za-z_]\w*)=/g)].map((m) => m[1])))].slice(0, 20);
      findings.push(finding('dyn.provider-query', {
        key: st.target, title: `Provider returns rows: ${st.target.split('/').pop()}`, severity: 'high', detection: 'exact', conclusion: 'confirmed',
        summary: `A read-only query to ${st.target} returned data. The shell user is more privileged than an ordinary app, but the provider declares no permission, so other apps can very likely read it too.`,
        evidence: [{ kind: 'command', ref: { path: 'adb', startLine: null, endLine: null, hitLine: null }, excerpt: `$ ${st.cmd}\n${rows.length} row${rows.length === 1 ? '' : 's'} returned. Columns: ${cols.join(', ') || 'unknown'}.`, note: 'The returned values are not stored.' }],
        repro: { steps: ['Run the command (read only).'], command: adbShell(st.cmd) }
      }));
    }
    return { findings };
  }
};

const listening = {
  id: 'dyn.listening-port', title: 'App listens on a network port', category: 'NETWORK', needs: ['sockets'],
  run(rec) {
    const findings = [];
    for (const s of rec.sockets.filter((x) => x.state === 'LISTEN')) {
      if (findings.some((f) => f.key === s.remote)) continue;
      const all = /^(0\.0\.0\.0|\[0:0:0:0:0:0:0:0\]):/.test(s.remote);
      findings.push(finding('dyn.listening-port', {
        key: s.remote, title: `Listening on ${s.remote}`, severity: all ? 'medium' : 'low', detection: 'exact', conclusion: 'exposure',
        summary: `The app accepts connections on ${s.remote}. ${all ? 'It listens on every interface, so other devices on the same network can connect to it.' : 'It listens on loopback, so any app on the phone can connect to it.'}`,
        evidence: [{ kind: 'command', ref: { path: '/proc/net/tcp', startLine: null, endLine: null, hitLine: null }, excerpt: `uid ${rec.uid}  ${s.remote}  LISTEN`, focus: s.remote, note: `first seen ${hhmmss(s.t)}` }],
        repro: { steps: ['Forward the port and connect to it.'], command: ['adb', 'forward', `tcp:${s.remote.split(':').pop()}`, `tcp:${s.remote.split(':').pop()}`] }
      }));
    }
    return { findings };
  }
};

const devtools = {
  id: 'dyn.webview-devtools', title: 'WebView debugging socket open', category: 'RESILIENCE', needs: ['devtools'],
  run(rec) {
    const mine = rec.devtools.filter((n) => rec.pids.some((p) => n === `webview_devtools_remote_${p}`) || n === `${rec.pkg}_devtools_remote`);
    if (!mine.length) return { findings: [] };
    return { findings: [finding('dyn.webview-devtools', {
      key: rec.pkg, severity: 'medium', detection: 'exact', conclusion: 'confirmed',
      summary: `The app has a WebView debugging socket open (${mine.join(', ')}). Anyone with adb can attach Chrome DevTools to its WebViews and read or change the pages, cookies and storage.`,
      evidence: [{ kind: 'command', ref: { path: '/proc/net/unix', startLine: null, endLine: null, hitLine: null }, excerpt: mine.map((n) => `@${n}`).join('\n'), focus: mine[0], note: '' }],
      repro: { steps: ['Open chrome://inspect on a computer with the phone plugged in.'], command: ['adb', 'forward', 'tcp:9222', `localabstract:${mine[0]}`] }
    })] };
  }
};

const OTP = /\b(?:otp|code|passcode|password|pin|verification)\b[^\n]{0,40}?\b\d{4,8}\b/i;
const notifications = {
  id: 'dyn.notification-secrets', title: 'Sensitive data shown in a notification', category: 'PRIVACY', needs: ['notifications'],
  run(rec) {
    const findings = [];
    let own = false;
    for (const line of rec.notifications.split('\n')) {
      const p = /pkg=(\S+)/.exec(line);
      if (p) { own = p[1] === rec.pkg; continue; }
      const v = /(?:android\.\w+|tickerText)=(?:String \()?(.*?)\)?\s*$/.exec(line);
      if (!own || !v) continue;
      const hits = sensitive(v[1], rec.plan.typed);
      const label = hits[0]?.label || (OTP.test(v[1]) && 'A one-time code');
      if (!label || findings.some((f) => f.key === label)) continue;
      findings.push(finding('dyn.notification-secrets', {
        key: label, title: `${label} in a notification`, severity: 'medium', detection: hits[0]?.exact ? 'exact' : 'probable', conclusion: 'confirmed',
        summary: `A notification from the app shows ${label.toLowerCase()}. Notifications can appear on the lock screen and are readable by any app with notification access.`,
        evidence: [{ kind: 'command', ref: { path: 'dumpsys notification', startLine: null, endLine: null, hitLine: null }, excerpt: line.trim().slice(0, 240), focus: hits[0]?.value || '', note: 'notifications showing when the session stopped' }],
        repro: { steps: ['Trigger the notification and look at the lock screen.'], command: ['adb', 'shell', 'dumpsys', 'notification', '--noredact'] }
      }));
    }
    return findings.length ? { findings } : { inconclusive: 'only the notifications still showing when the session stopped were read' };
  }
};

const plainDb = {
  id: 'dyn.plaintext-database', title: 'Unencrypted database in app storage', category: 'STORAGE', needs: ['appdata'],
  run(rec) {
    const dbs = (rec.fs.sqlite || []).filter((p) => !/-journal$|-wal$|-shm$/.test(p));
    if (!dbs.length) return { findings: [] };
    return { findings: [finding('dyn.plaintext-database', {
      key: rec.pkg, title: `Unencrypted SQLite: ${dbs.length} file${dbs.length === 1 ? '' : 's'}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
      summary: `${dbs.length} database file${dbs.length === 1 ? ' in the app\'s storage is' : 's in the app\'s storage are'} unencrypted SQLite. Anyone who can read the app's data (a backup, a rooted phone, a debuggable build) can open ${dbs.length === 1 ? 'it' : 'them'} and read every table.`,
      evidence: [{ kind: 'file-diff', ref: { path: dbs[0], startLine: null, endLine: null, hitLine: null }, excerpt: dbs.slice(0, 20).join('\n'), note: 'files that start with "SQLite format 3"' }],
      repro: { steps: ['Copy the file off the phone and open it with sqlite3.'], command: rec.caps.appdata === 'run-as' ? ['adb', 'exec-out', 'run-as', rec.pkg, 'cat', dbs[0].replace(/^\.\//, '')] : [] }
    })] };
  }
};

const providerInjection = {
  id: 'dyn.provider-injection', title: 'Content provider open to SQL injection or path traversal', category: 'PLATFORM', group: 'readonly', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => s.kind === 'sqli' || s.kind === 'traversal');
    if (!steps.length) return { notApplicable: 'the app exports no content provider without a permission' };
    const findings = [];
    for (const st of steps) {
      const sqli = st.kind === 'sqli';
      if (!(sqli ? /unrecognized token|syntax error|SQLiteException|near "'"/i : /^\s*(?:127\.0\.0\.1|::1)\s+\S*localhost/m).test(st.output)) continue;
      findings.push(finding('dyn.provider-injection', {
        key: `${st.kind}|${st.target}`, title: `${sqli ? 'SQL injection' : 'Path traversal'}: ${st.target.replace(/^content:\/\//, '')}`, severity: 'high', detection: 'exact', conclusion: 'confirmed',
        summary: sqli ? `A single quote in the selection made ${st.target} fail with an SQL error, so the selection is pasted into the SQL query. Another app can use it to read any table of the database.` : `Reading ${st.target} with ../ in the path returned the phone's /etc/hosts, so the provider opens files outside its folder. Another app can use it to read the app's private files.`,
        evidence: [{ kind: 'command', ref: { path: 'adb', startLine: null, endLine: null, hitLine: null }, excerpt: `$ ${st.cmd}\n${st.output.split('\n').slice(0, 3).join('\n')}`, focus: sqli ? (/unrecognized token|syntax error|SQLiteException/i.exec(st.output)?.[0] || '') : 'localhost', note: `at ${hhmmss(st.t)}` }],
        repro: { steps: ['Run the command (read only).'], command: probeCmd(st) }
      }));
    }
    return { findings };
  }
};

const probeCmd = (st) => ['adb', 'shell', st.cmd];                  // one argument, so the phone's shell parses the quoting the recorder used
const cmdEv = (st, lines = 3) => ({ kind: 'command', ref: { path: 'adb', startLine: null, endLine: null, hitLine: null }, excerpt: `$ ${st.cmd}\n${st.output.split('\n').slice(0, lines).join('\n')}`, note: `at ${hhmmss(st.t)}` });
const BLOCKED = /Permission Denial|SecurityException|requires |not exported|Error:|Unable to start|app is in background|not found/i;

const exportedService = {
  id: 'dyn.exported-service', title: 'Exported service starts from adb', category: 'PLATFORM', group: 'changing', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => s.kind === 'service');
    if (!steps.length) return { notApplicable: 'no exported service was started from adb' };
    const findings = [], background = steps.filter((s) => /app is in background/i.test(s.output)).length;
    for (const st of steps) {
      if (!/Starting service/i.test(st.output) || BLOCKED.test(st.output)) continue;
      findings.push(finding('dyn.exported-service', { key: st.target, title: `Service starts without a permission: ${st.target.split('/').pop().split('.').pop()}`, severity: 'medium', detection: 'exact', conclusion: 'exposure',
        summary: `Starting ${st.target} from the adb shell worked and the system accepted it. The service declares no permission, so other apps can very likely start it too. Whatever its onStartCommand does with the Intent is reachable by any app.`,
        evidence: [cmdEv(st)], repro: { steps: ['Run the command with the app installed.'], command: probeCmd(st) } }));
    }
    if (!findings.length && background) return { inconclusive: `${background} of ${steps.length} service start${steps.length === 1 ? '' : 's'} were refused because the app was in the background. Open the app first and run a new session` };
    return { findings };
  }
};

const exportedReceiver = {
  id: 'dyn.exported-receiver', title: 'Exported receiver accepts a broadcast from adb', category: 'PLATFORM', group: 'changing', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => s.kind === 'receiver');
    if (!steps.length) return { notApplicable: 'no exported receiver was sent a broadcast from adb' };
    const findings = [];
    for (const st of steps) {
      if (!/Broadcast completed/i.test(st.output) || BLOCKED.test(st.output)) continue;
      findings.push(finding('dyn.exported-receiver', { key: st.target, title: `Receiver accepts a broadcast: ${st.target.split('/').pop().split('.').pop()}`, severity: 'low', detection: 'probable', conclusion: 'exposure',
        summary: `A broadcast sent from the adb shell to ${st.target} was accepted by the system. The receiver declares no permission, so any app can send it Intents with extras of its choice. Whether that is harmful depends on what the receiver does with them.`,
        evidence: [cmdEv(st)], repro: { steps: ['Run the command with the app installed.'], command: probeCmd(st) } }));
    }
    return { findings };
  }
};

const providerWrite = {
  id: 'dyn.provider-write', title: 'Content provider accepts writes', category: 'PLATFORM', group: 'changing', needs: [],
  run(rec) {
    const steps = rec.steps.filter((s) => ['insert', 'update', 'delete'].includes(s.kind));
    if (!steps.length) return { notApplicable: 'no provider with readable rows was open to a write test' };
    const findings = [], done = new Set();
    for (const st of steps) {
      const rows = st.output.split('\n').filter((l) => /^Row: /.test(l)).length;
      const worked = st.kind === 'delete' ? false : rows > 0;
      if (!worked || done.has(`${st.kind}|${st.target}`)) continue;
      done.add(`${st.kind}|${st.target}`);
      const verb = { insert: 'added', update: 'changed' }[st.kind];
      findings.push(finding('dyn.provider-write', { key: `${st.kind}|${st.target}`, title: `Provider lets a shell user ${st.kind} rows: ${st.target.replace(/^content:\/\//, '')}`, severity: 'high', detection: 'exact', conclusion: 'confirmed',
        summary: `A row with a random loupe- marker was ${verb} in ${st.target} from the adb shell, and a follow-up query returned it. The provider declares no write permission, so other apps can very likely change its data. Loupe deleted its test row at the end of the probe.`,
        evidence: [cmdEv(st, 4)], repro: { steps: ['Run the command, then query the provider.'], command: probeCmd(st) } }));
    }
    return { findings };
  }
};

const KEYFILE = /\.(?:jks|bks|keystore|p12|pfx|pem|key|crt|cer)$/i;
const keyFiles = {
  id: 'dyn.key-files', title: 'Key or certificate file in app storage', category: 'STORAGE', needs: ['appdata'],
  run(rec) {
    const findings = [], seen = new Set();
    for (const f of rec.fs.after) {
      if (!KEYFILE.test(f.path) || seen.has(f.path) || findings.length >= 30) continue;
      seen.add(f.path);
      const key = /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(f.text || '');
      findings.push(finding('dyn.key-files', { key: f.path, title: `${key ? 'Private key' : 'Key or certificate'} file: ${f.path.split('/').pop()}`, severity: key ? 'high' : 'medium', detection: key ? 'exact' : 'probable', conclusion: 'confirmed',
        summary: `${f.path} is a ${key ? 'private key' : 'key, keystore or certificate file'} stored in the app's data folder. Anyone who can read the folder, through a backup, a debuggable build or a rooted phone, can copy it. A signing key or client certificate there lets them impersonate the app or its user.`,
        evidence: [{ kind: 'file-diff', ref: { path: f.path, startLine: null, endLine: null, hitLine: null }, excerpt: `mode ${f.mode}  ${f.size} bytes  ${f.path}`, note: '' }],
        repro: { steps: ['List the file from the app data folder.'], command: rec.caps.appdata === 'run-as' ? ['adb', 'shell', 'run-as', rec.pkg, 'ls', '-l', f.path.replace(/^\.\//, '')] : [] } }));
    }
    return { findings };
  }
};

const logStackTrace = {
  id: 'dyn.log-stack-trace', title: 'Stack trace written to logcat', category: 'PRIVACY', needs: ['logcat'],
  run(rec) {
    const pids = new Set(rec.pids), off = rec.device.clockOffsetMs, hits = [];
    rec.logcat.forEach((e, i) => { if (pids.has(e.pid) && e.tag !== 'AndroidRuntime' && /^\s*at [\w.$<>]+\([\w$.]+:\d+\)/.test(e.msg)) hits.push([e, i]); });
    if (hits.length < 3) return { findings: [] };
    const [e, i] = hits[0], tags = [...new Set(hits.map(([x]) => x.tag))].slice(0, 3);
    return { findings: [finding('dyn.log-stack-trace', { key: tags[0], title: `Stack trace in logcat (${tags[0]})`, severity: 'low', detection: 'exact', conclusion: 'confirmed',
      summary: `The app printed ${hits.length} stack trace lines to the system log under ${tags.join(', ')}. A trace names classes, files and line numbers, and often the failing request. Anyone with adb, and other apps on older Android versions, can read it and use it to map the code.`,
      evidence: [{ kind: 'logcat', ref: { path: 'logcat', startLine: i + 1, endLine: i + 1, hitLine: i + 1 }, excerpt: logLine(e, off), note: `pid ${e.pid}` }],
      repro: { steps: ['Start a session and repeat the action that failed.'], command: ['adb', 'logcat', '-d', '-s', e.tag.replace(/[^\w.-]/g, '')] } })] };
  }
};

const appLinks = {
  id: 'dyn.app-links', title: 'App Link is not verified on the phone', category: 'PLATFORM', needs: ['applinks'],
  run(rec) {
    const findings = [];
    // `pm get-app-links` prints one "host: state" line per domain. Anything but verified means other apps can intercept the link.
    for (const m of rec.appLinks.matchAll(/^\s*([\w.*-]+\.[\w.-]+):\s*(\S+)/gm)) {
      const [, host, state] = m;
      if (/^(?:verified|approved)$/i.test(state) || findings.some((f) => f.key === host) || findings.length >= 20) continue;
      findings.push(finding('dyn.app-links', { key: host, title: `Link not verified: ${host}`, severity: 'medium', detection: 'exact', conclusion: 'confirmed',
        summary: `Android reports the domain ${host} as ${state} for this app, not verified. A link to that host opens the app chooser, or goes to another app that claims the host. The link then cannot be trusted to reach this app.`,
        evidence: [{ kind: 'command', ref: { path: 'pm get-app-links', startLine: null, endLine: null, hitLine: null }, excerpt: m[0].trim(), focus: host, note: 'read when the session stopped' }],
        repro: { steps: ['Run the command and read the state of each domain.'], command: ['adb', 'shell', 'pm', 'get-app-links', rec.pkg] } }));
    }
    return findings.length ? { findings } : { findings: [] };
  }
};

const flagSecure = {
  id: 'dyn.flag-secure', title: 'Main screen is not secured against capture', category: 'PRIVACY', group: 'changing', needs: [],
  run(rec) {
    const st = rec.steps.find((s) => s.kind === 'window');
    if (!st) return { notApplicable: 'the app was not launched from adb in this session' };
    if (!/fl=/.test(st.output)) return { inconclusive: 'the phone did not print the window flags for the app, so whether it sets FLAG_SECURE is unknown' };
    if (/\bSECURE\b/.test(st.output)) return { findings: [] };
    return { findings: [finding('dyn.flag-secure', { key: rec.pkg, severity: 'low', detection: 'heuristic', conclusion: 'confirmed',
      summary: 'The app\'s main window does not carry the SECURE flag while it is on screen. Screenshots, screen recordings and the recent-apps thumbnail can then capture whatever it shows. Only the first screen was checked, and later screens may differ.',
      evidence: [{ kind: 'command', ref: { path: 'dumpsys window', startLine: null, endLine: null, hitLine: null }, excerpt: st.output.split('\n').slice(0, 3).join('\n'), focus: 'fl=', note: `at ${hhmmss(st.t)}` }],
      repro: { steps: ['Open the app and take a screenshot, or look at the recent-apps list.'], command: [] } })] };
  }
};

const packageFlags = {
  id: 'dyn.package-flags', title: 'Installed build flags confirm weak settings', category: 'RESILIENCE', needs: ['pkgdump'],
  run(rec) {
    const findings = [];
    for (const [re, label, sev, text] of [
      [/\bDEBUGGABLE\b/, 'Installed build is debuggable', 'high', 'The package manager lists the installed app as DEBUGGABLE. Anyone with adb can attach a debugger and read its private data without root. This confirms the manifest setting on the phone.'],
      [/\bTEST_ONLY\b/, 'Installed build is test-only', 'medium', 'The package manager lists the installed app as TEST_ONLY. It is a test build that was installed with adb install -t and was never meant for users. It may carry debug code and weaker checks.'],
      [/\bALLOW_BACKUP\b/, 'Backups are on for the installed build', 'low', 'The package manager lists ALLOW_BACKUP for the installed app, so its data is included in device backups. Anyone who can pull a backup, through adb on a debuggable build or from the cloud account, can read what the app stored.']
    ]) { const m = re.exec(rec.pkgDump); if (m) findings.push(finding('dyn.package-flags', { key: label, title: label, severity: sev, detection: 'exact', conclusion: 'confirmed', summary: text,
      evidence: [{ kind: 'command', ref: { path: 'dumpsys package', startLine: null, endLine: null, hitLine: null }, excerpt: rec.pkgDump.split('\n').filter((l) => re.test(l)).join('\n').slice(0, 300), focus: m[0], note: 'read when the session stopped' }],
      repro: { steps: ['Run the command and read the flags line.'], command: ['adb', 'shell', 'dumpsys', 'package', rec.pkg] } })); }
    return { findings };
  }
};

const workProfile = {
  id: 'dyn.work-profile', title: 'App also runs in a work profile', category: 'PRIVACY', needs: ['profile'],
  run(rec) {
    if (!rec.workProfile.installedIn.length) return { findings: [] };
    return { findings: [finding('dyn.work-profile', { key: rec.pkg, severity: 'low', detection: 'exact', conclusion: 'confirmed',
      summary: `The phone has a work profile and this app is installed in it, in user ${rec.workProfile.installedIn.join(', ')}. The personal and work copies share a device, so a flaw in cross-profile sharing, backups or file access can move corporate data to the personal side. The app is subject to the work profile's management policy.`,
      evidence: [{ kind: 'command', ref: { path: 'pm path --user', startLine: null, endLine: null, hitLine: null }, excerpt: `${rec.workProfile.profiles} work profile${rec.workProfile.profiles === 1 ? '' : 's'}, app installed in user ${rec.workProfile.installedIn.join(', ')}`, note: 'read when the session stopped' }],
      repro: { steps: ['Run pm list users and pm path with the work profile user id.'], command: ['adb', 'shell', 'pm', 'list', 'users'] } })] };
  }
};

const DANGEROUS = new Set(['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION',
  'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'READ_CALENDAR', 'WRITE_CALENDAR', 'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO']);
const grantedPermissions = {
  id: 'dyn.granted-permissions', title: 'Dangerous permissions granted at runtime', category: 'PRIVACY', needs: ['pkgdump'],
  run(rec) {
    const granted = [...new Set([...rec.pkgDump.matchAll(/android\.permission\.([A-Z_]+): granted=true/g)].map((m) => m[1]).filter((p) => DANGEROUS.has(p)))];
    if (!granted.length) return { findings: [] };
    return { findings: [finding('dyn.granted-permissions', { key: rec.pkg, title: `${granted.length} dangerous permission${granted.length === 1 ? '' : 's'} granted`, severity: 'info', detection: 'exact', conclusion: 'exposure',
      summary: `The phone shows these dangerous permissions as granted to the app: ${granted.join(', ')}. Each gives the app, and any code or flaw inside it, access to sensitive data or sensors. Permissions the app does not need to function widen what a compromise can reach.`,
      evidence: [{ kind: 'command', ref: { path: 'dumpsys package', startLine: null, endLine: null, hitLine: null }, excerpt: granted.map((g) => `android.permission.${g}: granted=true`).join('\n').slice(0, 400), note: 'read when the session stopped' }],
      repro: { steps: ['Run the command and read the granted permissions.'], command: ['adb', 'shell', 'dumpsys', 'package', rec.pkg] } })] };
  }
};

export const DYN_RULES = [logcatSecrets, crash, cleartext, storageSecrets, worldReadable, externalStorage, exportedReachable, providerQuery, listening, devtools, notifications, plainDb, providerInjection, exportedService, exportedReceiver, providerWrite, keyFiles, logStackTrace, appLinks, flagSecure, packageFlags, workProfile, grantedPermissions];

// What a rule could not see even though its capability was there: events dropped at a cap, a stream that ended early, files not listed.
const INCOMPLETE = {
  logcat: (r) => (r.limits.logcatEnded ? 'the log stream ended before the session did' : r.limits.logcatDropped ? `${r.limits.logcatDropped} log lines were dropped because the buffer filled` : ''),
  sockets: (r) => (r.limits.socketsEnded ? 'the connection watcher ended before the session did' : r.limits.socketsDropped ? `${r.limits.socketsDropped} connections were dropped because the list filled` : ''),
  appdata: (r) => (r.limits.fsTruncated ? 'the app has more files than a snapshot lists (over 3000)' : ''),
  ext: (r) => (r.limits.extTruncated ? 'shared storage has more files than a snapshot lists' : '')
};
const incomplete = (rule, rec) => (rule.needs || []).map((n) => INCOMPLETE[n]?.(rec)).find(Boolean) || (rule.group && rec.limits.probesCut ? 'a probe was still running when the session stopped' : '');

const CAPS = {
  logcat: ['logcat-unreadable', (r) => r.caps.logcat],
  sockets: ['sockets-unattributable', (r) => r.caps.sockets],
  appdata: ['needs-root-or-debuggable', (r) => !!r.caps.appdata && !!r.fs && !r.fs.error],
  ext: ['external-storage-unreadable', (r) => r.caps.ext && !!r.ext],
  devtools: ['socket-list-unreadable', (r) => r.devtools !== null],
  notifications: ['notifications-unreadable', (r) => r.notifications !== null],
  applinks: ['app-links-unreadable', (r) => r.appLinks !== null],
  pkgdump: ['package-flags-unreadable', (r) => r.pkgDump !== null],
  profile: ['work-profile-unreadable', (r) => r.workProfile !== null]
};

/** One outcome per rule that did not find anything, one per finding otherwise. Never throws: a rule that fails is an `error` outcome. */
export function analyzeRecording(rec) {
  const out = [];
  for (const rule of DYN_RULES) {
    const head = { ruleId: rule.id, title: rule.title, category: rule.category, standards: standardsFor(rule) };
    const blocked = (rule.needs || []).map((n) => CAPS[n]).find(([, ok]) => !ok(rec)) || (rule.group && !rec.plan[rule.group] ? ['user-declined'] : null);
    if (blocked) { out.push({ ...head, state: 'not_tested', reason: blocked[0] }); continue; }
    let res;
    try { res = rule.run(rec); } catch (e) { out.push({ ...head, state: 'error', reason: String(e?.message || e).slice(0, 200) }); continue; }
    const cut = incomplete(rule, rec);
    if (res.findings?.length) {
      out.push(...res.findings.map((f) => ({ ...head, state: 'finding', ...f })));
      if (cut) out.push({ ...head, state: 'inconclusive', reason: `${cut}. The findings above stand, but this check may have missed others` });       // findings do not make a cut source complete
    } else if (cut || res.inconclusive) out.push({ ...head, state: 'inconclusive', reason: cut || res.inconclusive });   // a probe that may not have run is not "not applicable"
    else if (res.notApplicable) out.push({ ...head, state: 'not_applicable', reason: res.notApplicable });
    else out.push({ ...head, state: 'checked' });
  }
  return out;
}

/** The stored record for a session, shaped like a static scan so the page can show it with the same components. */
export function sessionRecord(rec, { artifactId, decompileId }) {
  const outcomes = analyzeRecording(rec).map((o) => cleanOutcome(o));
  const cut = Object.values(rec.limits).some(Boolean);
  return {
    scanId: crypto.randomBytes(8).toString('hex'), artifactId, decompileId, startedAt: rec.startedAt, finishedAt: Date.now(), status: cut ? 'partial' : 'complete', mode: 'dynamic',
    provenance: {
      analyzer: 1, standards: SNAPSHOT, device: rec.device, installed: rec.installed, caps: rec.caps, limits: rec.limits, plan: { readonly: rec.plan.readonly, changing: rec.plan.changing, typed: rec.plan.typed.length },
      warnings: rec.warnings, counts: { logcat: rec.logcat.length, sockets: rec.sockets.length, files: rec.fs?.after.length ?? 0, steps: rec.steps.length }
    },
    outcomes
  };
}
