/**
 * Minimal strict XML reader for decoded Android XML (manifest, network security config). The input is hostile:
 * DTDs and entities are refused, and size, depth and node count are capped. Elements carry the 1-based line range of their start tag.
 */
export class XmlError extends Error {}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const decode = (s) => s.replace(/&(#x[0-9a-fA-F]+|#\d+|[A-Za-z]+);/g, (_, e) => {
  if (e[0] !== '#') return ENT[e] ?? '';
  const n = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
  return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
});

const TOKEN = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[A-Za-z_][\w:.-]*\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/y;
const ATTR = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

/** @returns {{ name: string, attrs: Record<string,string>, children: object[], text: string, line: number, endLine: number }} the root element */
export function parseXml(text, { maxBytes = 4 * 1024 * 1024, maxDepth = 64, maxNodes = 200_000 } = {}) {
  if (text.length > maxBytes) throw new XmlError('xml is too large');
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw new XmlError('DTDs are not supported');
  let root = null, nodes = 0, line = 1, at = 0;
  const stack = [];
  while (at < text.length) {
    TOKEN.lastIndex = at;
    const m = TOKEN.exec(text);
    if (!m) throw new XmlError(`bad xml at line ${line}`);
    at = TOKEN.lastIndex;
    const [tok, cdata, close, name, rawAttrs, selfClose, chars] = m;
    const startLine = line;
    for (let i = tok.indexOf('\n'); i >= 0; i = tok.indexOf('\n', i + 1)) line++;
    if (chars !== undefined || cdata !== undefined) { if (stack.length) stack.at(-1).text += decode(chars ?? cdata); continue; }
    if (!name) continue;                                    // comment or processing instruction
    if (close) {
      if (!stack.length || stack.pop().name !== name) throw new XmlError(`unbalanced </${name}> at line ${startLine}`);
      continue;
    }
    if (++nodes > maxNodes) throw new XmlError('too many elements');
    const el = { name, attrs: {}, children: [], text: '', line: startLine, endLine: line };
    for (const a of rawAttrs.matchAll(ATTR)) el.attrs[a[1]] = decode(a[2] ?? a[3]);
    if (stack.length) stack.at(-1).children.push(el); else if (root) throw new XmlError('more than one root element'); else root = el;
    if (!selfClose) { if (stack.length >= maxDepth) throw new XmlError('xml is nested too deeply'); stack.push(el); }
  }
  if (stack.length || !root) throw new XmlError('xml ended early');
  return root;
}

/** Depth-first walk over an element and its descendants. */
export function* walk(el) { yield el; for (const c of el.children) yield* walk(c); }
