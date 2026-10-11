/**
 * Title Case for finding and check names: the major words are capitalized, the minor ones (short articles, conjunctions and prepositions) stay lowercase
 * unless they start the title, follow a colon, or end it. Anything that looks like code is left exactly as it is: names with inner capitals or digits
 * (WebView, readObject, MD5), all-caps words (URLs, TLS), and anything with a dot, slash, underscore or at-sign (strings.xml, libtool-checker.so).
 */
const MINOR = new Set('a an and as at but by for from in into nor of off on onto or per so the to up via vs with yet'.split(' '));
const KEEP = new Set(['adb', 'su', 'jadx']);
const plain = (w) => /^[A-Za-z]+$/.test(w);
const cap = (w) => w[0].toUpperCase() + w.slice(1).toLowerCase();

export function titleCase(text) {
  const words = String(text ?? '').split(' ');
  const last = words.length - 1;
  let start = true;                                              // the first word, and the first after a colon
  return words.map((w, i) => {
    const [, pre, core, post] = /^([("'\[]*)([\s\S]*?)([,;:)"'\]]*)$/.exec(w);
    const lead = start;
    start = post.includes(':');
    if (!core || KEEP.has(core)) return w;
    const parts = core.split('-');
    if (!parts.every((p) => plain(p))) return w;                  // a path, a file name, a version or a code name: not a word
    const fix = (p, k) => (p !== p.toLowerCase() && p !== cap(p) ? p : MINOR.has(p.toLowerCase()) && !(lead && k === 0) && !(i === last && k === parts.length - 1) ? p.toLowerCase() : cap(p));
    return pre + parts.map(fix).join('-') + post;
  }).join(' ');
}
