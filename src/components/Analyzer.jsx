import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLoupe } from '../store.jsx';
import * as az from '../lib/analyzer.js';
import * as jx from '../lib/jadx.js';
import { probe, startSession, useSession } from '../lib/session.js';
import { Split, useDismiss } from './ui.jsx';
import { AppIcon } from './JxPanels.jsx';
import { toMarkdown } from '../lib/exportScan.js';
import { ago, plural } from '../lib/format.js';
import { Dashboard } from './AnalyzerDashboard.jsx';
import { ResultList, Detail, filterItems, RulesDialog, DeleteDialog, PreRun, TestPlan, bucketize } from './AnalyzerPanels.jsx';

const TARGET_KEY = 'loupe.az.target';
const saved = () => { try { return localStorage.getItem(TARGET_KEY) || ''; } catch { return ''; } };
const INCOMPLETE = { partial: 'Some rules did not finish, so this scan is incomplete.', cancelled: 'The scan was cancelled, so this scan is incomplete.', failed: 'The scan failed, so this scan is incomplete.' };

export default function Analyzer() {
  const { s, set, toast, setLogApp, download } = useLoupe();
  const active = s.view === 'analyzer';
  const [mode, setMode] = useState('static');
  const [recent, setRecent] = useState(null);           // decompiled apps, the scan targets (null while loading)
  const [rules, setRules] = useState([]), [dynRules, setDynRules] = useState([]), [showRules, setShowRules] = useState(false);
  const [target, setTarget] = useState(saved);
  const [res, setRes] = useState(null);                 // { artifactId, scan, dynamic } for the target
  const [job, setJob] = useState(null);
  const [tab, setTab] = useState('findings');
  const [sel, setSel] = useState(null);
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('');
  const [pick, setPick] = useState(false);
  const [err, setErr] = useState('');
  const session = useSession();
  const [plan, setPlan] = useState(null), [pr, setPr] = useState(null), [planErr, setPlanErr] = useState('');
  const [opts, setOpts] = useState({ readonly: true, changing: false, typed: '' });
  const [confirmDel, setConfirmDel] = useState(false);
  const [screen, setScreen] = useState('dashboard');     // 'dashboard' lists the apps that have a result in this mode, 'result' shows one app
  const [sums, setSums] = useState({}), [delRow, setDelRow] = useState(null);
  const [pending, setPending] = useState(null);       // a recording whose upload failed: { id, rec }
  const retryUpload = async () => {
    const p = pending;
    setAnalyzing(true); setErr('');
    try { await az.uploadSession(p.id, p.rec); await load(p.id); setPending(null); setTab('findings'); setSel(null); } catch (e) { setErr(e.message); }
    setAnalyzing(false);
  };
  const [planning, setPlanning] = useState(false), [analyzing, setAnalyzing] = useState(false);
  const pickRef = useDismiss(pick, () => setPick(false));

  // The Decompiler's Analyze button: switch to this app in Static mode and start its scan.
  useEffect(() => {
    const rq = s.azRequest;
    if (!rq) return;
    set({ azRequest: null }); setMode(rq.mode || 'static'); setTarget(rq.id); setErr(''); setScreen('result');
    if (rq.scan !== false) az.startScan(rq.id).then(setJob).catch((e) => setErr(e.message));
    if (rq.newSession) setPlanning(true);
  }, [s.azRequest]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { try { localStorage.setItem(TARGET_KEY, target); } catch { /* private mode */ } }, [target]);
  useEffect(() => { az.status().then((j) => { setRules(j.rules); setDynRules(j.dynamicRules || []); }).catch(() => {}); }, []);
  useEffect(() => {
    if (!active) return;
    jx.recent().then((l) => { setRecent(l); setTarget((t) => (l.some((r) => r.id === t) ? t : l[0]?.id || '')); }).catch((e) => { setRecent([]); setErr(e.message); });
  }, [active]);

  // The dashboard's rows: the stored result of every decompiled app. Only the newest answer counts, and a finished scan or session refreshes it.
  const sumSeq = useRef(0);
  const refreshSums = useCallback(() => {
    if (!recent?.length) { setSums({}); return Promise.resolve(); }
    const n = ++sumSeq.current;
    return az.summary(recent.map((r) => r.id)).then((x) => { if (n === sumSeq.current) setSums(x); }).catch(() => {});
  }, [recent]);
  useEffect(() => { if (active && screen === 'dashboard') refreshSums(); }, [active, screen, refreshSums, job?.status, analyzing]);

  // Only the newest request may set the results: a slow answer for another app must not replace the current one.
  const loadSeq = useRef(0);
  const load = useCallback((id) => {
    const n = ++loadSeq.current;
    return az.results(id).then((r) => { if (n === loadSeq.current) { setRes(r); setErr(''); } }).catch((e) => { if (n === loadSeq.current) { setRes(null); setErr(e.message); } });
  }, []);
  useEffect(() => {
    setRes(null); setJob(null); setSel(null); setQ(''); setCat('');
    if (!target) return undefined;
    let dead = false;
    load(target);
    az.scanState(target).then((j) => { if (!dead && j?.status === 'running') setJob(j); }).catch(() => {});
    return () => { dead = true; };
  }, [target, load]);

  useEffect(() => {
    if (job?.status !== 'running') return undefined;
    let dead = false, n = 0;
    const t = setInterval(() => { const k = ++n; az.scanState(target).then((j) => { if (dead || k !== n) return; setJob(j); if (j && j.status !== 'running') { load(target); if (j.status === 'failed') setErr(`The scan failed${j.error ? `: ${j.error}` : ''}. Any results below are from the previous scan.`); } }).catch(() => {}); }, 400);
    return () => { dead = true; clearInterval(t); };
  }, [job?.status, target, load]);

  // Dynamic: read the manifest's probe targets and ask the phone what it allows, before offering to start.
  useEffect(() => {
    if (mode !== 'dynamic' || !active || !target || !s.connected || session.active) return undefined;
    let dead = false;
    setPlan(null); setPr(null); setPlanErr('');
    (async () => {
      try { const p = await az.plan(target); if (dead) return; setPlan(p); const r = await probe(p.package, p.apkSha256s); if (!dead) setPr(r); }
      catch (e) { if (!dead) setPlanErr(e.message); }
    })();
    return () => { dead = true; };
  }, [mode, active, target, s.connected, session.active]);

  const startDynamic = async () => {
    if (!pr?.installed || !pr.match) return;                 // probes restart the app and write to its providers: never on a build other than the analyzed one
    const typed = opts.typed.split('\n').map((x) => x.trim()).filter((x) => x.length >= 3).slice(0, 10);
    const prev = Object.fromEntries(['topTabs', 'bottomTabs', 'top', 'bottom', 'topOpen', 'bottomOpen', 'split'].map((k) => [k, s[k]]));
    const uniq = (a) => [...new Set(a)];
    // Switch to the Console straight away: starting takes a few seconds (the app is restarted and its files are listed), and the user should
    // be watching the mirror, not a waiting card.
    set({
      view: 'console', top: 'logcat', bottom: 'traffic', topOpen: true, bottomOpen: true, split: 0.55, paused: false,
      topTabs: uniq(['logcat', ...s.topTabs.filter((t) => t !== 'logcat' && t !== 'traffic')]), bottomTabs: uniq(['traffic', ...s.bottomTabs.filter((t) => t !== 'traffic' && t !== 'logcat')])
    });
    setLogApp(plan.package);
    try {
      const sessionTarget = target;                         // fixed now: the picker is locked during a recording, and this is what gets uploaded
      await startSession({
        pkg: plan.package, uid: pr.uid, caps: pr.caps, device: pr.device, installed: { sha256s: pr.apkSha256s, match: pr.match },
        plan: { readonly: opts.readonly, changing: opts.changing, typed }, targets: { activities: plan.activities, services: plan.services, receivers: plan.receivers, providers: plan.providers, deeplinks: plan.deeplinks },
        onDone: async (rec) => {
          set({ ...prev, view: 'analyzer' });
          setMode('dynamic'); setPlanning(false); setAnalyzing(true);
          try { await az.uploadSession(sessionTarget, rec); setTarget(sessionTarget); await load(sessionTarget); setTab('findings'); setSel(null); setPending(null); } catch (e) { setErr(e.message); setPending({ id: sessionTarget, rec }); }          // always the app the session recorded, even if the picker moved          // keep the recording so the upload can be retried
          setAnalyzing(false);
        }
      });
    } catch (e) { set({ ...prev, view: 'analyzer' }); setErr(e.message); }
  };

  const run = async () => { setErr(''); try { setJob(await az.startScan(target)); } catch (e) { setErr(e.message); } };
  const cancel = () => az.cancelScan(target).catch(() => {});

  const scan = mode === 'dynamic' ? res?.dynamic : res?.scan;
  const buckets = useMemo(() => bucketize(scan?.outcomes || []), [scan]);
  const counts = useMemo(() => ({
    high: buckets.findings.filter((o) => o.severity === 'high').length, medium: buckets.findings.filter((o) => o.severity === 'medium').length,
    low: buckets.findings.filter((o) => o.severity === 'low').length, info: buckets.findings.filter((o) => o.severity === 'info').length,
    findings: buckets.findings.length, inconclusive: buckets.inconclusive.length, checked: buckets.checked.length,
    not_tested: buckets.not_tested.length, error: buckets.error.length
  }), [buckets]);
  // A scan with no findings should not open on an empty list: start on the first tab that has results.
  useEffect(() => {
    if (!scan) return;
    setTab(['findings', 'inconclusive', 'checked', 'not_tested', 'error'].find((k) => counts[k]) || 'findings'); setSel(null); setCat('');
  }, [scan?.scanId, mode]); // eslint-disable-line react-hooks/exhaustive-deps
  const items = buckets[tab] || [];
  const shown = filterItems(items, { q, cat });          // the same list the left pane shows
  const cur = shown.includes(sel) ? sel : shown[0] || null;

  const app = recent?.find((r) => r.id === target);
  const busy = job?.status === 'running';
  const copy = (text, what) => navigator.clipboard?.writeText(text).then(() => toast(`${what} copied`), () => toast('Copy failed'));
  // One click saves the Markdown report.
  const exportReport = () => {
    const base = `${(app?.package || 'app').replace(/[^\w.-]/g, '_')}-${scan.mode === 'dynamic' ? 'dynamic' : 'static'}`;
    download(new Blob([toMarkdown(scan, { app: app?.label || app?.name })], { type: 'text/markdown' }), `${base}.md`);
  };
  const deleteResult = async () => {
    try { await az.deleteResults(target, mode); setConfirmDel(false); setSel(null); await load(target); toast('Result deleted'); } catch (e) { setConfirmDel(false); setErr(e.message); }
  };
  const openInConsole = (panel) => set({ view: 'console', [panel === 'logcat' ? 'top' : 'bottom']: panel, topOpen: true, bottomOpen: true });
  const openInDecompiler = (e) => set({ view: 'decompiler', jxRequest: { kind: 'open', id: scan.decompileId, name: app?.name || 'APK', path: e.ref.path, line: e.ref.hitLine || e.ref.startLine } });

  // The page itself carries the primary action before a run, so the toolbar does not repeat it.
  const preRun = !!recent?.length && !err && (mode === 'static' ? !scan && !busy : !session.active && !analyzing && !planErr && s.connected && !(scan && !planning) && !!plan && !!pr);
  const onDash = screen === 'dashboard' && !session.active;
  const Toolbar = (
    <div className="ctxbar az-ctx">
      {!onDash && <button className="btn" disabled={session.active} onClick={() => setScreen('dashboard')} title="Back to the list of analyzed apps"><span aria-hidden="true">‹</span> Dashboard</button>}
      <div className="az-seg" role="tablist" aria-label="Analysis type">
        {[['static', 'Static'], ['dynamic', 'Dynamic']].map(([k, l]) => <button key={k} role="tab" aria-selected={mode === k} className={`${k}${mode === k ? ' on' : ''}`} onClick={() => setMode(k)}>{l}</button>)}
      </div>
      {!onDash && recent?.length > 0 && (
        <span ref={pickRef} className="az-picker">
          <button className="btn az-picker-button" disabled={session.active} onClick={() => setPick((p) => !p)} title="Choose a decompiled app">
            {app && <AppIcon id={app.id} path={app.icon} size={20} />}
            <span className="az-picker-name">{app ? app.label || app.name : 'Choose an App'}</span>
            <span aria-hidden="true">▾</span>
          </button>
          {pick && (
            <div className="menu" style={{ top: 'calc(100% + 4px)', left: 'auto', width: 360, maxHeight: 380, overflow: 'auto' }}>
              {recent.map((r) => (
                <button key={r.id} className={'menu-item' + (r.id === target ? ' on' : '')} onClick={() => { setTarget(r.id); setPick(false); }}>
                  <AppIcon id={r.id} path={r.icon} size={20} />
                  <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0, textAlign: 'left' }}>
                    <span style={{ fontWeight: 500 }}>{r.label || r.name}</span><span className="mono subtle" style={{ fontSize: 10.5 }}>{r.package || r.name}{r.versionName ? ` · ${r.versionName}` : ''}</span>
                  </span>
                </button>))}
            </div>)}
        </span>)}
      {!onDash && app?.package && <span className="mono subtle hide-narrow az-ctx-pkg">{app.package}{app.versionName ? ` · ${app.versionName}` : ''}</span>}
      {!onDash && busy && (
        <span className="mono az-progress">
          <span><i style={{ width: `${Math.max(4, (job.progress.done / job.progress.total) * 100)}%` }} /></span>
          {job.progress.done}/{job.progress.total} rules
        </span>)}
      <div className="spacer" />
      <div className="az-ctx-actions">
      {rules.length > 0 && <button className="btn" onClick={() => setShowRules(true)}>Scan Checks</button>}
      {!onDash && scan && (
        <button className="btn btn-export" title="Download the report as Markdown" onClick={exportReport}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14" /></svg>Export
        </button>)}
      {!onDash && mode === 'static' && target && (busy ? <button className="btn" onClick={cancel}>Cancel</button> : scan && <button className="btn btn-accent" onClick={run}>Rescan</button>)}
      {!onDash && mode === 'dynamic' && !s.connected && scan && !planning && <span className="mono subtle hide-narrow">Connect a phone for a new session</span>}
      {!onDash && mode === 'dynamic' && s.connected && !session.active && scan && !planning && <button className="btn btn-accent" onClick={() => setPlanning(true)}>New Session</button>}
      {!onDash && scan && !busy && !session.active && !analyzing && !pending && <button className="btn btn-danger" title="Delete this stored result" onClick={() => setConfirmDel(true)}>Delete</button>}
      </div>
    </div>
  );

  // The recording bar (SessionBar) owns Stop, so the Analyzer has no second one. Every whole-page state uses this one composition.
  const Hero = ({ title, children, action }) => (
    <div className="az-state-page">
      <div className="az-hero"><h2>{title}</h2><p>{children}</p>{action && <div className="az-hero-action">{action}</div>}</div>
    </div>
  );
  const Say = ({ children }) => <div className="az-empty mono"><span>{children}</span></div>;
  let Body;
  const Results = scan && (
    <>
      {INCOMPLETE[scan.status] && <div className="az-banner">{mode === 'dynamic' && scan.status === 'partial' ? 'Part of this recording was cut short (a probe was still running, or a log or file list filled up). The Inconclusive tab says which checks are affected.' : `${INCOMPLETE[scan.status]} Findings below are real, but missing rules are listed under Errors.`}</div>}
      {mode === 'dynamic' && scan.provenance.warnings?.map((w) => <div className="az-banner" key={w}>{w}</div>)}
      {mode === 'dynamic' && scan.provenance.installed && !scan.provenance.installed.match && <div className="az-banner">The installed build differed from the decompiled APK during this session.</div>}
      {!buckets.findings.length && (
        <div className="az-summary" role="status">
          <div className="az-summary-copy"><strong>No Findings Reported</strong><span>That is not a clean bill of health. Check what was inconclusive or not tested before relying on it.</span></div>
          <div className="az-summary-counts">
            {[['checked', 'checked'], ['inconclusive', 'inconclusive'], ['not_tested', 'not tested'], ['error', 'errors']].map(([k, label]) => (
              <button key={k} disabled={!counts[k]} onClick={() => { setTab(k); setSel(null); setCat(''); }}><b>{counts[k]}</b><span>{label}</span></button>))}
          </div>
        </div>)}
      <Split id="az-split-3" initial={0.33} min={0.2}>
        <ResultList items={items} tab={tab} cur={cur} onSelect={setSel} q={q} setQ={setQ} cat={cat} setCat={setCat} counts={counts} onTab={(t) => { setTab(t); setSel(null); setCat(''); }} />
        <Detail o={cur} scan={scan} onOpen={openInDecompiler} onConsole={openInConsole} onCopy={copy} />
      </Split>
    </>
  );
  if (onDash) {
    Body = recent === null ? <Say>Loading…</Say> : <Dashboard apps={recent} sums={sums} mode={mode} onMore={() => set({ view: 'decompiler' })} onOpen={(a) => set({ azRequest: { id: a.id, mode, scan: false } })}
      onAction={(a) => set({ azRequest: mode === 'static' ? { id: a.id, mode } : { id: a.id, mode, scan: false, newSession: true } })} onDelete={setDelRow} />;
  } else if (mode === 'dynamic') {
    if (session.active) Body = <Hero title={`Recording ${session.pkg}`} action={<button className="btn" onClick={() => set({ view: 'console' })}>Back to the Console</button>}>{String(session.step || '').replace(/\.$/, '')}. {plural(session.counts?.logcat ?? 0, 'log line')}, {plural(session.counts?.sockets ?? 0, 'connection')}, {plural(session.counts?.steps ?? 0, 'probe')} so far.{session.error ? ` ${session.error}` : ''}</Hero>;
    else if (analyzing) Body = <Say>Analyzing the recording…</Say>;
    else if (!recent?.length) Body = <Hero title="Analyze an Android App" action={<button className="btn btn-accent" onClick={() => set({ view: 'decompiler' })}>Open the Decompiler</button>}>A dynamic session needs an app the Decompiler has opened, so decompile its APK first.</Hero>;
    else if (planErr) Body = <Hero title="This Session Cannot Be Planned">{planErr}</Hero>;
    else if (scan && !planning) Body = Results;
    else if (!s.connected) Body = <Hero title="Connect a Phone First" action={<button className="btn btn-accent" onClick={() => set({ view: 'console' })}>Open the Console</button>}>A dynamic session runs the app on a connected phone.</Hero>;
    else Body = plan && pr ? <PreRun title={`Dynamic Session for ${plan.package}`} intro="Loupe switches to the Console and records the app's logs, network connections and files while you use it. When you stop, it turns the recording into findings with the raw evidence." primary={<button className="btn btn-accent" onClick={startDynamic} disabled={!pr.installed || !pr.match} title={!pr.installed ? 'Install the app first.' : !pr.match ? 'The installed build differs from the decompiled APK. Install the decompiled one, or decompile the installed one.' : ''}>Start Session</button>}><TestPlan plan={plan} pr={pr} opts={opts} setOpts={setOpts} /></PreRun> : <Say>Checking the phone and the app…</Say>;
  } else if (recent === null) Body = <Say>Loading…</Say>;
  else if (!recent.length) {
    Body = <Hero title="Analyze an Android App" action={<button className="btn btn-accent" onClick={() => set({ view: 'decompiler' })}>Open the Decompiler</button>}>The Analyzer scans an app that the Decompiler has already opened, so decompile an APK first.</Hero>;
  } else if (!scan && !busy) {
    Body = <PreRun title={`Scan ${app?.label || app?.name || 'this app'}`} intro="Static analysis reads the decoded manifest, the network security config, the signature, the native libraries and the decompiled code, and reports weaknesses with the evidence for each. Nothing leaves this computer." primary={<button className="btn btn-accent" onClick={run}>Run Static Scan</button>} />;
  } else if (busy && !scan) Body = <Say>Scanning… {job.progress.rule}</Say>;
  else Body = Results;

  return (
    <div style={{ display: active ? 'flex' : 'none', flexDirection: 'column', minHeight: 0, minWidth: 0, position: 'relative', background: 'var(--bg)' }}>
      {Toolbar}
      {err && <div className="az-banner err">{err}{pending && <button className="btn" style={{ marginLeft: 12 }} onClick={retryUpload}>Retry Upload</button>}</div>}
      <div style={{ flex: '1 1 auto', minHeight: 0, display: 'flex', flexDirection: 'column' }}>{Body}</div>
      <div className="panel-foot" style={{ gap: 14 }}>
        {!onDash && <span>{scan ? `scanned ${ago(scan.finishedAt || scan.startedAt)}` : 'not scanned yet'}</span>}
        {!onDash && scan && <span>{scan.outcomes.length} results</span>}
        <div className="spacer" />
        <span>local only</span>
      </div>
      {confirmDel && <DeleteDialog app={app?.label || app?.name || 'this app'} mode={mode} count={buckets.findings.length} onClose={() => setConfirmDel(false)} onConfirm={deleteResult} />}
      {delRow && <DeleteDialog app={delRow.label || delRow.name} mode={mode} count={sums[delRow.id]?.[mode]?.findings} onClose={() => setDelRow(null)} onConfirm={async () => { const r = delRow; setDelRow(null); try { await az.deleteResults(r.id, mode); toast('Result deleted'); } catch (e) { setErr(e.message); } refreshSums(); }} />}
      {showRules && <RulesDialog mode={mode} rules={rules} dynamicRules={dynRules} onClose={() => setShowRules(false)} />}
    </div>
  );
}
