import { titleCase } from './titleCase.js';
import { splitCode } from './codeSpans.js';

/** Turns a stored scan (static or dynamic) into a Markdown report. Pure functions, no browser APIs. */

export const SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const shq = (a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`);
export const cmdLine = (argv) => argv.map(shq).join(' ');
/** Inline text: one line, with Markdown structure characters escaped, so hostile text cannot make headings, links, images or table cells. */
const inline = (t) => String(t ?? '').replace(/[\r\n]+/g, ' ').replace(/([\\`*_{}[\]<>()#!|~])/g, '\\$1').replace(/^(\s*)([-+]|\d+\.)(?=\s)/, '$1\\$2');
/** A code block whose fence is longer than any run of backticks inside it, so its content cannot close it. */
/** Prose for the report: code-like words in backticks, everything else escaped. */
const rich = (t) => splitCode(t).map(([x, code]) => (code ? `\`${x.replace(/`/g, '')}\`` : inline(x))).join('');
const block = (t) => { const f = '`'.repeat(Math.max(2, ...[...String(t).matchAll(/`+/g)].map((m) => m[0].length)) + 1); return `${f}\n${t}\n${f}`; };
const std = (o) => [...o.standards.masvs, ...o.standards.maswe, ...o.standards.mastg, ...o.standards.cwe].join(', ');

/** One finding as Markdown: summary, evidence, how to reproduce it. */
/**
 * A four-letter code for an app name, used in finding IDs (ISNH-01). One word: its first four letters. Two words: two letters each. Three or more: the
 * first letters of the first four words (three words: plus the word's second letter). CamelCase splits into words, digits are ignored, and a short
 * name is padded with X, so every name gives a stable code.
 */
export function reportCode(name) {
  const words = String(name || '').replace(/\.apk$/i, '').replace(/([a-z])([A-Z])/g, '$1 $2').split(/[^A-Za-z]+/).filter(Boolean).map((w) => w.toUpperCase());
  if (!words.length) return 'APPX';
  const code = words.length === 1 ? words[0] : words.length === 2 ? words[0].slice(0, 2) + words[1].slice(0, 2) : words.slice(0, 4).map((w) => w[0]).join('') + (words.length === 3 ? words[0][1] || '' : '');
  return code.slice(0, 4).padEnd(4, 'X');
}

export const ORDER = { high: 0, medium: 1, low: 2, info: 3 };
/** IDs like ISNH-01 for the findings in report order: by severity. */
export function findingIds(outcomes, code) {
  const sorted = outcomes.filter((o) => o.state === 'finding').map((o, i) => [o, i]).sort(([a, i], [b, j]) => ((ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4)) || i - j).map(([o]) => o);
  const pad = String(sorted.length).length > 2 ? 3 : 2;
  return new Map(sorted.map((o, i) => [o, `${code}-${String(i + 1).padStart(pad, '0')}`]));
}

export function findingMarkdown(o, scan, id = '') {
  const ev = o.evidence.map((e) => `Evidence (${inline(e.ref.path)}${e.ref.startLine ? `:${e.ref.startLine}` : ''}):\n${block(e.excerpt)}`).join('\n\n');
  const steps = o.repro?.steps?.length ? `\nReproduce:\n${o.repro.steps.map((x, i) => `${i + 1}. ${rich(x)}`).join('\n')}` : '';
  const cmd = o.repro?.command?.length ? `\n${block(cmdLine(o.repro.command))}` : '';
  return `### ${id ? `${id}: ` : ''}${inline(titleCase(o.title))}\nSeverity: ${SEV[o.severity] || '-'} · Detection: ${o.detection} · Conclusion: ${o.conclusion}\nRule: ${inline(o.ruleId)}\n\n${rich(o.summary)}\n\n${ev}${steps}${cmd}${o.recommendation ? `\n\nRecommendation:\n${rich(o.recommendation)}` : ''}\n\nRelated standards: ${inline(std(o))}\n`;
}

const group = (outcomes) => ({
  findings: outcomes.filter((o) => o.state === 'finding'),
  other: outcomes.filter((o) => o.state !== 'finding')
});

export function toMarkdown(scan, { app = '' } = {}) {
  const g = group(scan.outcomes), p = scan.provenance;
  const ids = findingIds(scan.outcomes, reportCode(app));
  const byId = (list) => [...list].sort((a, b) => ids.get(a).localeCompare(ids.get(b)));
  const when = new Date(scan.finishedAt || scan.startedAt).toISOString().replace('T', ' ').slice(0, 16);
  const head = [`# ${app ? `${inline(app)}: ` : ''}${scan.mode === 'dynamic' ? 'Dynamic' : 'Static'} analysis`, '',
    `Scanned ${when} UTC · status ${scan.status}${p.device ? ` · ${p.device.model} (Android ${p.device.release})` : ''}`, '',
    `${g.findings.length} findings, ${g.other.filter((o) => o.state === 'checked').length} rules checked clean, ${g.other.filter((o) => o.state === 'inconclusive').length} inconclusive, ${g.other.filter((o) => o.state === 'not_tested' || o.state === 'not_applicable').length} not tested, ${g.other.filter((o) => o.state === 'error').length} errors.`, '',
    'This is an automated report. No findings does not mean the app is secure. Related standards are pointers, not a statement that a test ran or passed.', ''];
  const sections = [
    ...(g.findings.length ? ['## Summary', '', '| ID | Severity | Finding |', '|---|---|---|', ...byId(g.findings).map((o) => `| ${ids.get(o)} | ${SEV[o.severity] || '-'} | ${inline(titleCase(o.title))} |`), '', '## Findings', '', ...byId(g.findings).map((o) => findingMarkdown(o, scan, ids.get(o)))] : []),
    ...(g.other.length ? ['## Other results', '', '| Rule | Result | Reason |', '|---|---|---|', ...g.other.map((o) => `| ${inline(o.ruleId)} | ${o.state.replace('_', ' ')} | ${inline(o.reason)} |`), ''] : [])
  ];
  return [...head, ...sections].join('\n');
}
