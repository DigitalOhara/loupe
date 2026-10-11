/**
 * Finds the code-like words in a finding's prose (attributes, paths, file names, class and method names, constants, true/false) so the page
 * and the Markdown report can show them as inline code. Text between backticks is code as written. Everything else is matched by shape,
 * so a plain word is never touched.
 */
const NOT_CODE = new Set(['JavaScript', 'StrandHogg', 'GitHub', 'TypeScript']);
const RE = new RegExp([
  '`[^`\\n]+`',                                                        // already marked
  '\\b[a-z][a-z0-9+.-]*:\\/\\/(?:[^\\s,;)"\'`]*[\\w/])?',                       // http://, content://example/path
  '(?:[\\w.$-]+\\/){2,}[\\w.$-]*\\w|[\\w$-]+(?:\\.[\\w$-]+)*\\.\\w+\\/[\\w./$-]*\\w|[\\w-]*_[\\w-]*\\/[\\w./$-]*\\w|\\b[\\w-]+\\/(?=\\s|$)',   // paths: two or more slashes, dir/file.ext, shared_prefs/x
  '\\b(?:android|tools|app):[\\w.-]+',                                   // android:debuggable
  '\\b[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+(?:\\(\\))?',               // com.x.Main, Cipher.getInstance, app.ab, strings.xml
  '\\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\\b',                                // FLAG_SECURE
  '\\b[a-z]+[A-Z][A-Za-z0-9]*\\b|\\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\\b', // allowBackup, WebView
  '\\b[a-z0-9]+(?:_[a-z0-9]+)+\\b',                                     // shared_prefs, android_secret_code
  '\\b\\w+\\(\\)',                                                      // getInstance()
  '\\b(?:true|false|null)\\b'
].join('|'), 'g');

/** [[text, isCode], ...] covering the whole string. */
export function splitCode(text) {
  const s = String(text ?? ''), out = [];
  let last = 0;
  for (const m of s.matchAll(RE)) {
    if (NOT_CODE.has(m[0]) || /^\d+(?:\.\d+)+$/.test(m[0])) continue;
    if (m.index > last) out.push([s.slice(last, m.index), false]);
    out.push([m[0].startsWith('`') ? m[0].slice(1, -1) : m[0], true]);
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push([s.slice(last), false]);
  return out;
}
