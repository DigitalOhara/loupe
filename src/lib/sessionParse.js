/**
 * Pure helpers for dynamic sessions (no browser or device APIs, so node tests can import them): parsers for what the
 * phone prints, and the shell script that snapshots an app's files. See session.js for the recorder that uses them.
 */

/** Files listed per snapshot. A listing that reaches it may be cut short. */
export const FILE_CAP = 3000;
export const CONTENT_BUDGET = 8 * 1024 * 1024;     // bytes of file text per snapshot, so a snapshot stays far below the upload limit (64 MiB for all of a session)
export const PKG = /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)*$/;
export const COMPONENT = /^[\w.$]+$/;
export const AUTHORITY = /^[\w.-]+$/;
export const DEEPLINK = /^[\w+.-]+:\/\/[\w.-]+\/$/;

/** The values searched for: each typed value and its Base64 form (an encoding is not protection). The order is the index in `@@M n`. */
export const needlesOf = (typed) => typed.flatMap((t) => [{ value: t, label: 'A value you typed' }, { value: btoa(String.fromCharCode(...new TextEncoder().encode(t))), label: 'A value you typed, Base64 encoded' }]);

/** Single-quotes a string for a Unix shell. */
export const quote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

const STATES = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING' };
const le4 = (h) => [h.slice(6, 8), h.slice(4, 6), h.slice(2, 4), h.slice(0, 2)].map((x) => parseInt(x, 16));

function addr(hex) {
  const [ip, port] = hex.split(':');
  const p = parseInt(port, 16);
  if (ip.length === 8) return `${le4(ip).join('.')}:${p}`;
  if (ip.length !== 32) return '';
  const words = [0, 8, 16, 24].map((i) => ip.slice(i, i + 8));
  if (words[0] === '00000000' && words[1] === '00000000' && words[2].toUpperCase() === 'FFFF0000') return `${le4(words[3]).join('.')}:${p}`;     // IPv4-mapped (::ffff:a.b.c.d is stored as 0000000000000000FFFF0000 + the address)
  const groups = words.flatMap((w) => { const b = le4(w); return [(b[0] << 8 | b[1]).toString(16), (b[2] << 8 | b[3]).toString(16)]; });
  return `[${groups.join(':')}]:${p}`;
}

/** Connections of one uid from the text of /proc/net/tcp and /proc/net/tcp6: [{ remote: 'ip:port', state }]. A listening socket has no peer, so its `remote` is its own local address. */
export function parseProcNet(text, uid) {
  const out = [];
  for (const line of String(text).split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8 || !/^\d+:$/.test(f[0]) || Number(f[7]) !== uid) continue;
    const state = STATES[f[3]];
    const remote = addr(f[state === 'LISTEN' ? 1 : 2]);
    if (!state || !remote || /^(0\.0\.0\.0|\[0:0:0:0:0:0:0:0\]):0$/.test(remote)) continue;
    out.push({ remote, state });
  }
  return out;
}

/** `logcat -v threadtime -v epoch` → { t (device ms), pid, level, tag, msg }, or null for banners and junk. */
export function parseLogLine(line) {
  const m = /^\s*(\d+)\.(\d+)\s+(\d+)\s+\d+\s+([VDIWEFA])\s+(.+?)\s*:\s?(.*)$/.exec(line);
  return m ? { t: Number(m[1]) * 1000 + Math.round(Number(`0.${m[2]}`) * 1000), pid: Number(m[3]), level: m[4], tag: m[5], msg: m[6] } : null;
}

/**
 * Shell script that lists every file under `dir` (up to FILE_CAP) as the app, with the text of the small text ones. App-controlled bytes (file names and contents)
 * never appear raw: they are Base64, whose alphabet has no `@`, so a hostile app cannot forge a record. Records:
 * `@@F <path> <mode> <size> <mtime> T|B` (small text file, or anything else) followed by one Base64 line of content for T,
 * `@@D <mode> <path>` per folder, `@@M <n> <path>` per file containing needle n, `@@Q <path>` per unencrypted SQLite file, `@@X <n>` for files whose names contain a newline (they cannot be listed line by line), and one final `@@N <files> <folders>`. Output without exactly one `@@N` is incomplete.
 * Needles are quoted, never spliced in raw.
 */
export function snapshotScript(dir, needles = []) {
  return [
    `b() { printf %s "$1" | base64 -w 0; }`,
    `cd ${quote(dir)} 2>/dev/null || { echo "@@ERR cannot enter the folder"; exit 0; }`,
    `t=0; cap=0; find . -type f 2>/dev/null | head -${FILE_CAP} | while IFS= read -r f; do m=$(stat -c '%a %s %Y' "$f" 2>/dev/null); s=\${m#* }; s=\${s%% *}; if [ "\${s:-0}" -lt 65536 ] && [ $t -lt ${CONTENT_BUDGET} ] && grep -Iq . "$f" 2>/dev/null; then echo "@@F $(b "$f") $m T"; head -c 65536 "$f" | base64 -w 0; echo; t=$((t+\${s:-0})); else echo "@@F $(b "$f") $m B"; if [ $t -ge ${CONTENT_BUDGET} ] && [ $cap = 0 ]; then echo "@@B"; cap=1; fi; fi; done`,
    `find . -type d 2>/dev/null | head -1000 | while IFS= read -r d; do echo "@@D $(stat -c %a "$d" 2>/dev/null) $(b "$d")"; done`,
    ...needles.map((n, i) => `grep -rlaF -e ${quote(n)} . 2>/dev/null | head -20 | while IFS= read -r p; do echo "@@M ${i} $(b "$p")"; done`),
    `find . -type f -size +0 2>/dev/null | head -${FILE_CAP} | while IFS= read -r f; do [ "$(head -c 15 "$f" 2>/dev/null)" = "SQLite format 3" ] && echo "@@Q $(b "$f")"; done`,
    `nl=$(printf '\\n.'); nl=\${nl%.}; echo "@@X $(find . -type f -name "*$nl*" -exec echo x \\; 2>/dev/null | wc -l | tr -d ' ')"`,
    `echo "@@N $(find . -type f 2>/dev/null | wc -l | tr -d ' ') $(find . -type d 2>/dev/null | wc -l | tr -d ' ')"`
  ].join('\n');
}

const unb64 = (t) => { try { return new TextDecoder().decode(Uint8Array.from(atob(t), (c) => c.charCodeAt(0))); } catch { return ''; } };

/** Parses the script's output into { files, dirs, matches, error, total, truncated }. `truncated` means the output was cut off, the listing hit the cap, or the content byte budget ran out. */
export function parseSnapshot(text, cap = FILE_CAP) {
  const out = { files: [], dirs: [], matches: [], sqlite: [], error: '', total: 0, unlisted: 0, capped: false, truncated: false, complete: false, missing: false };
  let cur = null, trailers = 0;
  const flush = () => { if (cur) { out.files.push(cur); cur = null; } };
  for (const line of String(text).split('\n')) {
    let m;
    if ((m = /^@@F (\S+) (\d+) (\d+) (\d+) ([TB])$/.exec(line))) { flush(); cur = { path: unb64(m[1]), mode: m[2], size: Number(m[3]), mtime: Number(m[4]), text: m[5] === 'T' ? '' : null }; }
    else if ((m = /^@@D (\d+) (\S+)$/.exec(line))) { flush(); out.dirs.push({ path: unb64(m[2]), mode: m[1] }); }
    else if ((m = /^@@M (\d+) (\S+)$/.exec(line))) { flush(); out.matches.push({ needle: Number(m[1]), path: unb64(m[2]) }); }
    else if ((m = /^@@Q (\S+)$/.exec(line))) { flush(); out.sqlite.push(unb64(m[1])); }                        // a plain (unencrypted) SQLite file
    else if ((m = /^@@X (\d+)$/.exec(line))) { flush(); out.unlisted = Number(m[1]); }
    else if ((m = /^@@N (\d+) (\d+)$/.exec(line))) { flush(); out.total = Number(m[1]); trailers++; }
    else if ((m = /^@@ERR (.*)$/.exec(line))) { flush(); out.error = m[1]; }
    else if (line === '@@B') { flush(); out.capped = true; }                                                    // the byte budget ran out: later files were listed but not read
    else if (cur && cur.text === '' && /^[A-Za-z0-9+/=]*$/.test(line)) cur.text = unb64(line);       // the one content line of a text file
  }
  flush();
  if (!out.error && trailers !== 1) out.error = trailers ? 'the snapshot ended more than once' : 'the snapshot did not finish';       // cut off, empty or garbled: never read as "no files"
  out.complete = !out.error;
  out.missing = out.error === 'cannot enter the folder';
  out.truncated = !out.complete || out.files.length >= cap || out.unlisted > 0 || out.capped;                // the file count is a hint only: files appear and vanish while the app runs
  return out;
}
