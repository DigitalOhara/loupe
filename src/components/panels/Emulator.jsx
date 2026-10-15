import { useEffect, useRef, useState } from 'react';
import { useLoupe } from '../../store.jsx';
import { EmptyState, Mini, Split } from '../ui.jsx';

const head = {
  display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
  padding: '0 0 6px', fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase',
  color: 'var(--ink3)', borderBottom: '1px solid var(--line)', marginBottom: 8
};
const hint = { fontSize: 10.5, color: 'var(--ink3)', lineHeight: 1.6, margin: '8px 0 0' };
const input = {
  fontSize: 12, padding: '5px 8px', background: 'var(--bg2)',
  border: '1px solid var(--line)', borderRadius: 6, color: 'var(--ink)'
};
const badge = (ok) => ({
  display: 'inline-flex', alignItems: 'center', gap: 5,
  padding: '3px 8px', borderRadius: 7, fontSize: 10,
  border: '1px solid ' + (ok ? 'var(--ok)' : 'var(--line)'),
  color: ok ? 'var(--ok)' : 'var(--ink3)',
  textTransform: 'none', letterSpacing: 0
});
const dot = (ok) => ({
  width: 5, height: 5, borderRadius: '50%',
  background: ok ? 'var(--ok)' : 'var(--ink3)',
  animation: ok ? 'lpPulse 1.6s ease-in-out infinite' : 'none'
});
const logBox = {
  fontSize: 11, fontFamily: 'var(--mono)', lineHeight: 1.5,
  background: 'var(--bg2)', border: '1px solid var(--line)', borderRadius: 6,
  padding: 8, maxHeight: 200, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all'
};

export function Emulator() {
  const { s, toast, emuStatus, emuSetup, emuRefresh, emuStart, emuStop, emuConnect, emuCreateAvd, emuDeleteAvd } = useLoupe();
  const [avdName, setAvdName] = useState('');
  const logRef = useRef(null);

  useEffect(() => { emuRefresh(); }, []);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [s.emuLog]);

  // Poll status while setup is running
  useEffect(() => {
    if (!s.emuSetupBusy) return;
    const iv = setInterval(emuRefresh, 3000);
    return () => clearInterval(iv);
  }, [s.emuSetupBusy]);

  const running = s.emuRunning || [];
  const avds = s.emuAvds || [];
  const isRunning = (name) => running.some((r) => r.name === name);

  return (
    <Split id="emulator">
      <div className="scroll" style={{ minWidth: 0, padding: 12, display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* SDK status */}
        <section>
          <div style={head}>
            <span>Android Emulator</span>
            <span className="mono" style={badge(s.emuInstalled)}>
              <span style={dot(s.emuInstalled)} />
              {s.emuInstalled ? 'SDK ready' : 'not installed'}
            </span>
          </div>

          {!s.emuInstalled && (
            <div>
              <p style={hint}>
                Loupe can download the Android SDK emulator, a rooted system image (API 34, google_apis),
                and set up a virtual device automatically. No Genymotion or Android Studio needed.
              </p>
              <div style={{ marginTop: 10 }}>
                <Mini tone="accent" disabled={s.emuSetupBusy}
                  label={s.emuSetupBusy ? 'Setting up…' : 'Install Android Emulator'}
                  onClick={emuSetup} />
              </div>
            </div>
          )}

          {s.emuSetupBusy && s.emuProgress && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--ink2)', marginBottom: 4 }}>
                {s.emuProgress.phase}
                {s.emuProgress.detail ? ` — ${s.emuProgress.detail}` : ''}
              </div>
              <div style={{ height: 4, background: 'var(--bg2)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', background: 'var(--accent)', borderRadius: 2,
                  width: `${s.emuProgress.pct || 0}%`, transition: 'width 0.3s ease'
                }} />
              </div>
            </div>
          )}

          {s.emuInstalled && (
            <p className="mono" style={{ ...hint, fontSize: 10 }}>
              SDK: {s.emuSdkRoot || '~/.loupe/android-sdk'}
            </p>
          )}
        </section>

        {/* AVDs */}
        {s.emuInstalled && (
          <section>
            <div style={head}>
              <span>Virtual Devices</span>
              <Mini label="Refresh" onClick={emuRefresh} />
            </div>

            {avds.length === 0 && (
              <p style={hint}>No AVDs found. Create one below.</p>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {avds.map((name) => {
                const r = running.find((x) => x.name === name);
                return (
                  <div key={name} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 10px', background: 'var(--bg2)',
                    border: '1px solid var(--line)', borderRadius: 6
                  }}>
                    <span style={dot(!!r)} />
                    <span className="mono" style={{ flex: 1, fontSize: 12 }}>{name}</span>
                    {r && <span className="mono" style={{ fontSize: 10, color: 'var(--ink3)' }}>{r.serial}</span>}
                    {r ? (
                      <>
                        <Mini tone="accent" label="Connect" onClick={() => emuConnect(name)} />
                        <Mini tone="danger" label="Stop" onClick={() => emuStop(name)} />
                      </>
                    ) : (
                      <>
                        <Mini tone="accent" label="Start" onClick={() => emuStart(name)} />
                        {name !== 'loupe_device' && (
                          <Mini tone="danger" label="Delete" onClick={() => emuDeleteAvd(name)} />
                        )}
                      </>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Create new AVD */}
            <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
              <input className="mono" value={avdName} onChange={(e) => setAvdName(e.target.value)}
                placeholder="new AVD name" style={{ ...input, flex: 1 }} />
              <Mini tone="accent" label="Create AVD"
                disabled={!avdName.trim()}
                onClick={() => { emuCreateAvd(avdName.trim()); setAvdName(''); }} />
            </div>
            <p style={hint}>
              Emulators use rooted google_apis images (API 34) — <code>adb root</code> and
              SELinux permissive are enabled automatically on boot. Full root for Frida, CA install, etc.
            </p>
          </section>
        )}

      </div>

      {/* Log pane (required: Split needs two children) */}
      <div style={{ minWidth: 0, padding: 12, display: 'flex', flexDirection: 'column' }}>
        <div style={head}><span>Log</span></div>
        <div ref={logRef} className="scroll mono" style={{ flex: '1 1 auto', minHeight: 0, fontSize: 11, lineHeight: 1.7, color: 'var(--ink2)' }}>
          {(!s.emuLog || s.emuLog.length === 0)
            ? <span style={{ color: 'var(--ink3)' }}>Emulator setup and runtime events show here.</span>
            : s.emuLog.map((l, i) => <div key={i}>{l}</div>)}
        </div>
      </div>
    </Split>
  );
}
