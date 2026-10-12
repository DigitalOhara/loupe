import { useRef, useState } from 'react';
import { AppIcon, TrashButton } from './JxPanels.jsx';
import { ago } from '../lib/format.js';
import { rowsFor } from '../lib/dashboardRows.js';

const STATUS = { complete: 'Complete', partial: 'Partial', cancelled: 'Cancelled', failed: 'Failed' };
const MODES = [['static', 'Static'], ['dynamic', 'Dynamic']];
const NO_PHONE = 'Connect a phone to start a dynamic session';

/** One sub-row of an app: its Static or Dynamic result, or a run button when that mode has not been run. */
function ModeCells({ a, m, label, r, canDynamic, onOpen, onRun, onDelete }) {
  const dyn = m === 'dynamic';
  const run = (
    <button className={`btn jx-analyze az-run ${dyn ? 'az-btn-dynamic' : 'btn-accent'}`} disabled={dyn && !canDynamic} title={dyn && !canDynamic ? NO_PHONE : ''} onClick={() => onRun(a, m)}>
      {r ? (dyn ? 'New Session' : 'Rescan') : dyn ? 'Start Dynamic Session' : 'Run Static Scan'}
    </button>);
  return (
    <>
      <td><span className={`az-ty ${m}`}><i />{label}</span></td>
      {r ? (
        <>
          <td className="mono" style={{ whiteSpace: 'nowrap' }} title={new Date(r.at).toLocaleString()}>{ago(r.at)}</td>
          <td><span className="az-counts">{['high', 'medium', 'low'].map((k) => <span key={k} className={`az-n ${k}${r.severity[k] ? '' : ' zero'}`}>{r.severity[k]}</span>)}</span></td>
          <td className={`az-st ${r.status}`}>{STATUS[r.status] || r.status}</td>
          <td><span className="jx-row-actions">
            <button className="btn jx-analyze jx-results" title={`Open the stored ${m} result`} onClick={() => onOpen(a, m)}>View Results</button>{run}
            <TrashButton title={`Delete the stored ${m} result`} onClick={() => onDelete(a, m)} />
          </span></td>
        </>
      ) : (
        <>
          <td colSpan={3} className="subtle">Not run yet</td>
          <td><span className="jx-row-actions">{run}</span></td>
        </>)}
    </>);
}

/** The Decompiler's upload box, for the Analyzer: whatever APK arrives is decompiled and then scanned. A drop anywhere in the window does the same. */
function Intake({ onFiles }) {
  const pick = useRef(null);
  return (
    <div className="az-intake">
      <div className="jx-hero">
        <h2>Scan an Android App</h2>
        <p>Drop an APK or browse for one.<br />Loupe decompiles it, then starts a static scan.</p>
      </div>
      <div className="jx-zone">
        <input ref={pick} type="file" accept=".apk" multiple hidden onChange={(e) => { onFiles(e.target.files); e.target.value = ''; }} />
        <button className="jx-drop" onClick={() => pick.current?.click()}>
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4M7 9l5-5 5 5M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" /></svg>
          <span>Drag and drop APKs here, or click to browse</span>
        </button>
      </div>
    </div>);
}

export function Dashboard({ apps, sums, canDynamic, onOpen, onRun, onDelete, onFiles }) {
  const [q, setQ] = useState('');
  const all = rowsFor(apps, sums), f = q.trim().toLowerCase();
  const rows = f ? all.filter((a) => [a.label, a.name, a.package].some((x) => x && String(x).toLowerCase().includes(f))) : all;
  if (!all.length) {
    return <div className="az-dash"><Intake onFiles={onFiles} /></div>;
  }
  return (
    <div className="az-dash">
      <Intake onFiles={onFiles} />
      <div className="jx-recent-bar">
        <h3>Analyzed Apps</h3>
        <div className="field" style={{ flex: '0 1 200px' }}>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search apps" aria-label="Search apps" />
        </div>
      </div>
      <table className="jx-scans" style={{ borderCollapse: 'collapse', fontSize: 12 }}>
        <thead><tr><th>App</th><th>Type</th><th>Last Run</th><th>High · Med · Low</th><th>Status</th><th /></tr></thead>
        {rows.map((a) => (
          <tbody key={a.id} className="az-app">
            {MODES.map(([m, label], i) => (
              <tr key={m}>
                {i === 0 && (
                  <td rowSpan={2}>
                    <div className="az-appcell">
                      <AppIcon id={a.id} path={a.icon} />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 500 }}>{a.label || a.name}</div>
                        <div className="mono subtle">{a.package || a.name}</div>
                        <div className="mono subtle">{a.versionName || '-'}{a.versionCode ? ` (${a.versionCode})` : ''}</div>
                      </div>
                    </div>
                  </td>)}
                <ModeCells a={a} m={m} label={label} r={sums[a.id][m]} canDynamic={canDynamic} onOpen={onOpen} onRun={onRun} onDelete={onDelete} />
              </tr>))}
          </tbody>))}
      </table>
      {!rows.length && <div className="az-fine" style={{ textAlign: 'center', padding: 16 }}>No app matches.</div>}
    </div>);
}
