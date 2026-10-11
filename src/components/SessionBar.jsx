import { useEffect, useState } from 'react';
import { useLoupe } from '../store.jsx';
import { plural } from '../lib/format.js';
import { useSession, stopSession } from '../lib/session.js';

const clock = (ms) => { const t = Math.max(0, Math.floor(ms / 1000)); return `${String(Math.floor(t / 60)).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`; };

/** Pinned under the header on every view while a dynamic session records. It owns Stop, so no other screen needs a second one. */
export function SessionBar() {
  const ses = useSession();
  const { s, set, loadNet } = useLoupe();
  const [now, setNow] = useState(Date.now());
  const onConsole = s.view === 'console', onAnalyzer = s.view === 'analyzer';
  useEffect(() => {
    if (!ses.active) return undefined;
    let n = 0;
    const t = setInterval(() => { setNow(Date.now()); if (onConsole && ++n % 3 === 0) loadNet(); }, 1000);
    return () => clearInterval(t);
  }, [ses.active, onConsole, loadNet]);
  if (!ses.active) return null;
  const c = ses.counts || {};
  return (
    <div className="az-session" role="status">
      <span className="az-rec"><i aria-hidden="true" />REC {clock(now - ses.startedAt)}</span>
      <span className="az-session-pkg mono" title={ses.pkg}>{ses.pkg}</span>
      <span className="az-session-step">{ses.error || ses.step}</span>
      <div className="spacer" />
      <span className="mono subtle hide-narrow">{plural(c.logcat || 0, 'log line')} · {plural(c.sockets || 0, 'connection')} · {plural(c.steps || 0, 'probe')}</span>
      {onAnalyzer
        ? <button className="btn-quiet" onClick={() => set({ view: 'console' })}>Console</button>
        : <button className="btn-quiet" onClick={() => set({ view: 'analyzer' })}>Analyzer</button>}
      <button className="btn btn-accent" disabled={ses.stopping} onClick={() => stopSession()}>{ses.stopping ? 'Stopping…' : 'Stop and Analyze'}</button>
    </div>
  );
}
