import { AppIcon, TrashButton } from './JxPanels.jsx';
import { ago } from '../lib/format.js';
import { rowsFor } from '../lib/dashboardRows.js';

const STATUS = { complete: 'Complete', partial: 'Partial', cancelled: 'Cancelled', failed: 'Failed' };

export function Dashboard({ apps, sums, mode, onOpen, onAction, onDelete, onMore }) {
  const rows = rowsFor(apps, sums, mode);
  const high = rows.filter((a) => sums[a.id][mode].severity.high > 0).length;
  if (!rows.length) {
    return (
      <div className="az-state-page">
        <div className="az-hero">
          <h2>{mode === 'static' ? 'No Static Results Yet' : 'No Dynamic Sessions Yet'}</h2>
          <p>{mode === 'static' ? 'Scan a decompiled app and its result appears here.' : 'Record a session on a connected phone and its result appears here.'}</p>
          <div className="az-hero-action"><button className="btn btn-accent" onClick={onMore}>{apps.length ? 'Choose an App in the Decompiler' : 'Open the Decompiler'}</button></div>
        </div>
      </div>);
  }
  return (
    <div className="az-dash">
      <div className="az-dash-head">
        <span className="subtle">{rows.length} {rows.length === 1 ? 'app' : 'apps'} · {high} with High findings</span>
        <button className="btn" onClick={onMore}>Analyze Another App</button>
      </div>
      <table className="jx-scans" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead><tr><th /><th>App</th><th>Version</th><th>{mode === 'static' ? 'Last Scanned' : 'Last Session'}</th><th>High</th><th>Medium</th><th>Low</th><th>Status</th><th /></tr></thead>
        <tbody>
          {rows.map((a) => {
            const r = sums[a.id][mode];
            return (
              <tr key={a.id} className="jx-scan" onClick={() => onOpen(a)}>
                <td style={{ width: 32 }}><AppIcon id={a.id} path={a.icon} /></td>
                <td><div style={{ fontWeight: 500 }}>{a.label || a.name}</div><div className="mono subtle">{a.package || a.name}</div></td>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>{a.versionName || '-'}{a.versionCode ? ` (${a.versionCode})` : ''}</td>
                <td className="mono" style={{ whiteSpace: 'nowrap' }} title={new Date(r.at).toLocaleString()}>{ago(r.at)}</td>
                {['high', 'medium', 'low'].map((k) => <td key={k}><span className={`az-n ${k}${r.severity[k] ? '' : ' zero'}`}>{r.severity[k]}</span></td>)}
                <td className={`az-st ${r.status}`}>{STATUS[r.status] || r.status}</td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <span className="jx-row-actions">
                    <button className={`btn jx-analyze ${mode === 'static' ? 'btn-accent' : 'az-btn-dynamic'}`} onClick={(e) => { e.stopPropagation(); onAction(a); }}>{mode === 'static' ? 'Rescan' : 'New Session'}</button>
                    <TrashButton title="Delete this stored result" onClick={() => onDelete(a)} />
                  </span>
                </td>
              </tr>);
          })}
        </tbody>
      </table>
    </div>);
}
