import { splitCode } from '../lib/codeSpans.js';
import React, { useEffect, useRef, useState } from 'react';
import { Search, Tab } from './ui.jsx';
import { Shell } from './Dialogs.jsx';
import { cmdLine, findingMarkdown, SEV, ORDER } from '../lib/exportScan.js';
import { titleCase } from '../lib/titleCase.js';


export const TABS = [['findings', 'Findings'], ['inconclusive', 'Inconclusive'], ['checked', 'Checked'], ['not_tested', 'Not Tested'], ['error', 'Errors']];
const REASON = {
  'manifest-unreadable': 'The manifest could not be read or parsed.',
  'tool-unavailable': 'The Java toolchain is not installed, so the signature could not be verified. Set it up from the Decompiler.',
  'apk-missing': 'The original APK is no longer in the decompile cache.',
  'no-sources': 'The decompiler produced no Java sources.',
  'logcat-unreadable': 'The system log could not be read from this phone.',
  'sockets-unattributable': 'Network connections could not be attributed to this app.',
  'needs-root-or-debuggable': 'Reading the app\'s files needs a debuggable app (run-as) or root.',
  'external-storage-unreadable': 'Shared storage could not be read.',
  'socket-list-unreadable': 'The phone\'s socket list (/proc/net/unix) could not be read.',
  'notifications-unreadable': 'The notification list could not be read from this phone.',
  'app-links-unreadable': 'The App Links state could not be read. It needs Android 12 or later.',
  'package-flags-unreadable': 'The installed package flags could not be read from this phone.',
  'work-profile-unreadable': 'The phone\'s user list could not be read.',
  'user-declined': 'You turned this group of checks off before the session.'
};

const DETECTION_TIP = {
  exact: 'This was read directly from parsed app data, such as a manifest attribute. Trust that the reported value is present.',
  probable: 'A code pattern suggests this finding is real. Verify whether the code can run and whether other checks guard it.',
  heuristic: 'This is an educated guess based on code shape or missing protection. Review it manually before acting.'
};
const CONCLUSION_TIP = {
  exposure: 'This app surface is open to attackers. It may be intentional, so check whether access controls or a safer configuration are needed.',
  weakness: 'The app has an insecure design or implementation, such as weak cryptography or a hardcoded credential. Fix or justify it.',
  confirmed: 'A live session observed this behavior on the phone, such as a logged secret or a provider returning rows. Treat it as verified and investigate.'
};

/** Prose with its code-like words (attributes, paths, class names, true/false) shown as inline code. */
const Rich = ({ text }) => splitCode(text).map(([t, code], i) => (code ? <code key={i} className="ic">{t}</code> : t));

/** Groups outcomes into the result tabs. Findings are sorted by severity, then title. */
export function bucketize(outcomes) {
  const b = { findings: [], inconclusive: [], checked: [], not_tested: [], error: [] };
  for (const o of outcomes) {
    if (o.state === 'finding') b.findings.push(o);
    else if (o.state === 'not_applicable') b.not_tested.push(o);
    else b[o.state]?.push(o);
  }
  const bySev = (x, y) => (ORDER[x.severity] ?? 9) - (ORDER[y.severity] ?? 9) || x.title.localeCompare(y.title);
  b.findings.sort(bySev);
  return b;
}

const Sev = ({ s }) => <span className={`az-sev ${s || 'info'}`}>{SEV[s] || 'Info'}</span>;

function Row({ o, on, onClick }) {
  const finding = o.state === 'finding';
  const sub = finding ? o.evidence[0]?.ref.path || o.ruleId
    : o.reason || (o.coverage?.examined ? `${o.coverage.examined} item${o.coverage.examined === 1 ? '' : 's'} examined` : o.ruleId);
  return (
    <button className={`az-row ${finding ? `sev-${o.severity || 'info'}` : `state-${o.state}`}${on ? ' on' : ''}`} onClick={onClick}>
      <span className="az-row-main">
        <span className="az-row-title">{titleCase(o.title)}</span>
        <span className="az-row-meta">
          {finding && o.category && <span className="az-cat">{o.category[0] + o.category.slice(1).toLowerCase()}</span>}
          <span className="az-row-path mono" title={sub}>{sub}</span>
        </span>
      </span>
      {!finding && <span className={`az-state ${o.state}`}>{o.state.replace('_', ' ')}</span>}
    </button>
  );
}

/** The results that pass the text filter and the category chip. Shared by the list and by the detail, so a hidden finding never stays selected. */
export const filterItems = (items, { q, cat }) => items.filter((o) => (!cat || o.category === cat) && (!q || `${o.title} ${o.ruleId} ${o.summary}`.toLowerCase().includes(q.toLowerCase())));

export function ResultList({ items, tab, cur, onSelect, q, setQ, cat, setCat, counts, onTab }) {
  const cats = [...new Set(items.map((o) => o.category).filter(Boolean))];
  const shown = filterItems(items, { q, cat });
  const grouped = tab === 'findings';
  let last = null;
  const listRef = useRef(null);
  // Up and Down move through the findings (not the scroll position); the selected row is kept in view.
  const onKeys = (e) => {
    const step = { ArrowDown: 1, ArrowUp: -1 }[e.key], edge = { Home: 0, End: shown.length - 1 }[e.key];
    if ((step === undefined && edge === undefined) || !shown.length) return;
    e.preventDefault();
    keyed.current = true;
    const i = pos.current >= 0 && shown[pos.current] ? pos.current : shown.indexOf(cur);       // the position survives key repeats that arrive before the next render
    pos.current = edge !== undefined ? edge : Math.min(shown.length - 1, Math.max(0, (i < 0 ? (step > 0 ? -1 : shown.length) : i) + step));
    onSelect(shown[pos.current]);
  };
  const keyed = useRef(false), pos = useRef(-1);
  useEffect(() => {
    pos.current = shown.indexOf(cur);
    const row = listRef.current?.querySelector('.az-row.on');
    row?.scrollIntoView({ block: 'nearest' });
    if (keyed.current && row) row.focus({ preventScroll: true });          // focus follows the arrow keys, so no row keeps a stale ring
    keyed.current = false;
  }, [cur]);
  return (
    <div className="az-left">
      <div className="az-stats">
        <span className="az-stat-total"><b>{counts.findings}</b><span>{counts.findings === 1 ? 'finding' : 'findings'}</span></span>
        {counts.findings > 0
          ? <span className="az-stat-set">{['high', 'medium', 'low', 'info'].filter((x) => counts[x] > 0).map((x) => <span key={x} className="az-stat"><b className={x}>{counts[x]}</b><span>{SEV[x]}</span></span>)}</span>
          : <span className="az-stat-note">{counts.checked} checked · {counts.inconclusive} inconclusive</span>}
      </div>
      <div className="az-tabs" role="tablist" aria-label="Results">
        {TABS.map(([k, l]) => <Tab key={k} role="tab" aria-selected={tab === k} on={tab === k} label={l} badge={counts[k] || ''} onClick={() => onTab(k)} />)}
      </div>
      <div style={{ padding: '8px 8px 0' }}><Search value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter" /></div>
      {grouped && cats.length > 1 && (
        <div className="az-chips">
          <button className={'chip sans' + (cat ? '' : ' on')} onClick={() => setCat('')}>All</button>
          {cats.map((c) => <button key={c} className={'chip sans' + (cat === c ? ' on' : '')} onClick={() => setCat(cat === c ? '' : c)}>{c[0] + c.slice(1).toLowerCase()}</button>)}
        </div>)}
      <div className="az-list" ref={listRef} tabIndex={0} onKeyDown={onKeys} aria-label="Results list. Use the arrow keys to move between results.">
        {shown.map((o) => {
          // Sorted by severity, so the headings are severities (a category heading would repeat out of order). The category is a tag on each row.
          const head = grouped && o.severity !== last ? (last = o.severity, <div className={`az-grp az-sev ${o.severity || 'info'}`} key={`g-${o.severity}`}>{SEV[o.severity] || 'Other'} · {items.filter((x) => x.severity === o.severity).length}</div>) : null;
          return <React.Fragment key={`${o.ruleId}:${o.fingerprint}:${o.title}`}>{head}<Row o={o} on={cur === o} onClick={() => onSelect(o)} /></React.Fragment>;
        })}
        {!shown.length && <div className="az-none mono">{items.length ? 'Nothing matches the filter.' : tab === 'findings' ? 'No findings in this scan.' : 'Nothing here.'}</div>}
      </div>
    </div>
  );
}

const openable = (p) => /^(sources|resources)\//.test(p || '');

function Evidence({ e, onOpen }) {
  const start = e.ref.startLine, hit = e.ref.hitLine;
  const lines = e.excerpt.split('\n');
  return (
    <div className="az-code">
      <div className="az-code-head">
        <span className="az-code-path mono" title={e.ref.path}>{e.ref.path}{start ? `:${hit || start}` : ''}</span>
        {openable(e.ref.path) && <button className="mini" onClick={() => onOpen(e)}>Open in Decompiler</button>}
      </div>
      <div className="az-code-body mono">
        {lines.map((l, i) => (
          <div key={i} className={'az-ln' + ((hit && start && start + i === hit) || (!hit && e.focus && l.includes(e.focus)) ? ' hit' : '')}>
            <span className="n">{start ? start + i : ''}</span><span className="t">{l || ' '}</span>
          </div>))}
      </div>
      {e.note && <div className="az-code-note">{e.note}</div>}
    </div>
  );
}


export function Detail({ o, scan, onOpen, onConsole, onCopy }) {
  if (!o) return <div className="az-empty mono">Select a result.</div>;
  const finding = o.state === 'finding';
  const con = o.evidence.find((e) => e.kind === 'logcat' || e.kind === 'file-diff');
  const std = o.standards;
  return (
    <div className="az-detail">
      <div className="az-detail-content">
        <div className="az-badges">
          {finding ? <Sev s={o.severity} /> : <span className={`az-state ${o.state}`}>{o.state.replace('_', ' ')}</span>}
          {finding && <span className="az-pill tip" data-c={o.detection} data-tip={DETECTION_TIP[o.detection]} tabIndex={0}>{o.detection} detection</span>}
          {finding && <span className="az-pill tip" data-c={o.conclusion} data-tip={CONCLUSION_TIP[o.conclusion]} tabIndex={0}>{o.conclusion}</span>}
          {finding && (
            <button className="az-copy tip" data-tip="Copy this finding as Markdown" aria-label="Copy finding" onClick={() => onCopy(findingMarkdown(o, scan), 'Finding')}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="3" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
            </button>)}
        </div>
        <h2>{titleCase(o.title)}</h2>
        {o.summary && <p className="az-why"><Rich text={o.summary} /></p>}
        {!finding && (
          <section>
            <h4 className="label">{o.state === 'inconclusive' ? 'Why This Is Inconclusive' : 'Outcome'}</h4>
            <p className="az-why"><Rich text={o.state === 'checked' ? 'The rule ran over its whole input and found nothing.' : REASON[o.reason] || o.reason} /></p>
          </section>)}
        {o.coverage?.examined != null && <div className="az-cov mono">examined {o.coverage.examined} of {o.coverage.eligible} · skipped {o.coverage.skipped}{o.coverage.libraryDamaged ? ` · ${o.coverage.libraryDamaged} library files not fully decompiled` : ''}</div>}
        {o.evidence.length > 0 && <section>
          <div className="az-section-head"><h4 className="label">Evidence</h4>
            {finding && con && <button className="btn-quiet" onClick={() => onConsole(con.kind === 'logcat' ? 'logcat' : 'files')}>{con.kind === 'logcat' ? 'Open Logcat' : 'Open Files'}</button>}
          </div>{o.evidence.map((e, i) => <Evidence key={i} e={e} onOpen={onOpen} />)}</section>}
        {finding && o.repro && (o.repro.steps.length > 0 || o.repro.command.length > 0) && (
          <section>
            <h4 className="label">Reproduce</h4>
            <ol className="az-steps">{o.repro.steps.map((x, i) => <li key={i}><Rich text={x} /></li>)}</ol>
            {o.repro.command.length > 0 && (
              <div className="az-cmd mono"><span className="p">$</span><span className="c">{cmdLine(o.repro.command)}</span>
                <button className="mini" onClick={() => onCopy(cmdLine(o.repro.command), 'Command')}>Copy</button></div>)}
          </section>)}
        {finding && o.recommendation && <section><h4 className="label">Recommendation</h4><p className="az-fix"><Rich text={o.recommendation} /></p></section>}
        <section>
          <h4 className="label">Related Standards</h4>
          <div className="az-tags">
            {[...std.masvs, ...std.maswe, ...std.mastg, ...std.cwe].map((t) => <span key={t} className="az-tag mono">{t}</span>)}
          </div>
          <div className="az-fine">Related means the rule touches the same weakness. It does not mean the MASTG test was run or passed. Rule <code className="ic">{o.ruleId}</code>.</div>
        </section>
      </div>
    </div>
  );
}

const Check = ({ ok, children, why }) => (
  <div className="az-plan-row"><span className={ok ? 'ok' : 'no'} aria-hidden="true">{ok ? '✓' : '✕'}</span><span>{children}{!ok && why ? <span className="az-plan-why"> {why}</span> : null}</span></div>
);

/** What a dynamic session will do, before it starts: what this phone allows, and the probe groups the user opts into. */
/** The page before a run, the same for Static and Dynamic: title, intro and one primary action, then what is specific to the mode. */
export function PreRun({ title, intro, primary, children }) {
  return (
    <div className="az-state-page">
      <div className="az-hero"><h2>{title}</h2><p>{intro}</p>
        <div className="az-state-actions">{primary}</div>
      </div>
      {children}
    </div>
  );
}

export function TestPlan({ plan, pr, opts, setOpts }) {
  const c = pr.caps;
  return (
    <div className="az-plan">
        <h4 className="label">What This Phone Allows</h4>
        <Check ok={pr.installed && pr.match} why={!pr.installed ? 'The app is not installed. Install it from the Console first.' : 'The installed build differs from the decompiled APK. A session is blocked, because its probes would run against the wrong build.'}>Installed build matches the decompiled APK</Check>
        <Check ok={c.logcat} why={REASON['logcat-unreadable']}>System Log</Check>
        <Check ok={c.sockets} why={REASON['sockets-unattributable']}>Network Connections for This App</Check>
        <Check ok={!!c.appdata} why={REASON['needs-root-or-debuggable']}>App files{c.appdata ? ` (via ${c.appdata})` : ''}</Check>
        <Check ok={c.ext} why={REASON['external-storage-unreadable']}>Shared Storage</Check>
        <h4 className="label">Probes</h4>
        <label className="az-plan-opt"><input type="checkbox" checked={opts.readonly} onChange={(e) => setOpts({ ...opts, readonly: e.target.checked })} />
          <span>Query exported content providers, read only ({plan.providers.length} found). Also tests each one for SQL injection and path traversal.</span></label>
        <label className="az-plan-opt az-plan-opt-warn"><input type="checkbox" checked={opts.changing} onChange={(e) => setOpts({ ...opts, changing: e.target.checked })} />
          <span>Start exported activities, services and receivers, open deep links, send activities odd extras, and write a marked test row to open providers (it is deleted again). That covers {plan.activities.length} activities, {plan.services?.length || 0} services, {plan.receivers?.length || 0} receivers and {plan.deeplinks.length} links. They run as the shell user and can change app state. The app is force-stopped and launched first. Without this, the session only watches and never touches the app.</span></label>
        <h4 className="label">Values You Will Type (Optional)</h4>
        <textarea className="az-typed" rows={3} value={opts.typed} onChange={(e) => setOpts({ ...opts, typed: e.target.value })} placeholder={'One per line, for example a test username and password.\nLoupe searches the log and the app files for them, and for their Base64 form.'} />
        <div className="az-fine">Test values only. They stay on this computer and are never sent anywhere. Findings show them as typed.</div>
    </div>
  );
}

/** Asks before a stored result is deleted. */
export function DeleteDialog({ app, mode, count, onClose, onConfirm }) {
  const [busy, setBusy] = useState(false);
  return (
    <Shell title={`Delete the ${mode === 'dynamic' ? 'Dynamic' : 'Static'} Scan Result?`} onClose={onClose} actions={<>
      <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
      <button className="btn btn-danger btn-danger-solid" disabled={busy} onClick={() => { setBusy(true); onConfirm(); }}>Delete</button>
    </>}>
      <div>
        This removes the stored {mode} result for <b style={{ color: 'var(--ink)' }}>{app}</b>{count != null ? ` (${count} findings)` : ''} from this computer. It cannot be undone, but you can scan again.
      </div>
    </Shell>
  );
}

const FAMILY = { manifest: 'Manifest', network: 'Network', signature: 'Signature', secrets: 'Secrets', native: 'Native Code', code: 'Code', dyn: 'Dynamic' };
const GROUP = { readonly: 'read only', changing: 'starts the app from adb' };

/** Every rule of one mode, grouped by family, searchable. `rules` come from the status call. */
export function RulesDialog({ mode, rules, dynamicRules, onClose }) {
  const m = mode, [q, setQ] = useState('');
  const list = (m === 'dynamic' ? dynamicRules : rules) || [];
  const shown = list.filter((r) => !q.trim() || `${r.id} ${r.title}`.toLowerCase().includes(q.trim().toLowerCase()));
  const groups = shown.reduce((acc, r) => { const f = r.id.split('.')[0]; (acc[f] = acc[f] || []).push(r); return acc; }, {});
  return (
    <Shell title="Scan Checks" width={680} onClose={onClose} actions={<button className="btn" onClick={onClose}>Close</button>}>
      <div className="az-rules-pop">
        <div className="az-rules-head">
          <input autoFocus placeholder={`Filter ${list.length} checks`} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="az-fine">{m === 'static' ? 'Static rules read the decompiled app. Results say finding, inconclusive, checked or not tested, never just "clean".' : 'Dynamic rules read a recording made on the phone. A rule whose probe was off, or whose source was cut short, is reported as not tested or inconclusive.'}</div>
        <div className="az-rules-list">
          {Object.entries(groups).map(([f, rs]) => (
            <section key={f}>
              <h5>{FAMILY[f] || f} <span className="subtle">{rs.length}</span></h5>
              {rs.map((r) => <div key={r.id} className="az-rule-row"><span>{titleCase(r.title)}</span><span className="mono subtle">{r.id}{r.group ? ` · ${GROUP[r.group] || r.group}` : ''}</span></div>)}
            </section>))}
          {!shown.length && <div className="az-fine">No check matches.</div>}
        </div>
      </div>
    </Shell>
  );
}
