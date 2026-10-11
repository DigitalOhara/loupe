/**
 * What the analyzer produces. Every rule yields one or more outcomes: `finding` (with evidence), or exactly one of
 * `inconclusive`, `checked`, `not_tested`, `not_applicable`, `error`. The rule worker's output derives from hostile
 * APK text, so `cleanOutcome` rebuilds each outcome from whitelisted, size-capped fields before anything is stored or served.
 */
import crypto from 'node:crypto';

export const STATES = ['finding', 'inconclusive', 'checked', 'not_tested', 'not_applicable', 'error'];
export const SEVERITIES = ['high', 'medium', 'low', 'info'];
export const DETECTIONS = ['exact', 'probable', 'heuristic'];
export const CONCLUSIONS = ['exposure', 'weakness', 'confirmed'];
export const EVIDENCE_KINDS = ['manifest', 'resource', 'source', 'signature', 'native', 'logcat', 'file-diff', 'command'];
export const CATEGORIES = ['STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY'];

const CAP = { id: 160, text: 600, excerpt: 4096, path: 400, step: 300, argv: 40, evidence: 20, steps: 12, std: 12 };
export const str = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
const oneOf = (v, list) => (list.includes(v) ? v : null);
const int = (v) => (Number.isInteger(v) && v >= 0 && v < 1e7 ? v : null);
const strs = (v, n, m) => (Array.isArray(v) ? v.slice(0, m).map((x) => str(x, n)).filter(Boolean) : []);

/** Stable identity for a finding: the rule plus what it is about (a component name, a file and token), never a line number. */
export function fingerprint(ruleId, key) {
  return crypto.createHash('sha256').update(`${ruleId}\0${key}`).digest('hex').slice(0, 16);
}

/** A 20 character key id such as `AKIA` plus 16 letters becomes `AK************OP`: enough to recognise, not enough to use. */
export function mask(s) {
  const n = String(s).length;
  return n <= 8 ? '*'.repeat(n) : s.slice(0, 2) + '*'.repeat(Math.min(n - 4, 12)) + s.slice(-2);
}

function cleanEvidence(e) {
  if (!e || typeof e !== 'object') return null;
  const kind = oneOf(e.kind, EVIDENCE_KINDS);
  if (!kind) return null;
  const r = e.ref && typeof e.ref === 'object' ? e.ref : {};
  return {
    kind, excerpt: str(e.excerpt, CAP.excerpt), note: str(e.note, CAP.text), focus: str(e.focus, 160),
    ref: { path: str(r.path, CAP.path), startLine: int(r.startLine), endLine: int(r.endLine), hitLine: int(r.hitLine) }
  };
}

/** @returns a sanitized outcome, or throws TypeError when the shape is unusable. */
export function cleanOutcome(o) {
  if (!o || typeof o !== 'object') throw new TypeError('outcome must be an object');
  const state = oneOf(o.state, STATES);
  if (!state || typeof o.ruleId !== 'string' || !o.ruleId) throw new TypeError('outcome needs a ruleId and a known state');
  const cov = o.coverage && typeof o.coverage === 'object' ? o.coverage : {};
  const std = o.standards && typeof o.standards === 'object' ? o.standards : {};
  const repro = o.repro && typeof o.repro === 'object' ? o.repro : null;
  return {
    ruleId: str(o.ruleId, CAP.id), state, reason: str(o.reason, CAP.text),
    title: str(o.title, CAP.text), summary: str(o.summary, CAP.text * 2), category: oneOf(o.category, CATEGORIES),
    severity: oneOf(o.severity, SEVERITIES), detection: oneOf(o.detection, DETECTIONS), conclusion: oneOf(o.conclusion, CONCLUSIONS),
    fingerprint: str(o.fingerprint, 32),
    coverage: { eligible: int(cov.eligible), examined: int(cov.examined), skipped: int(cov.skipped), errors: int(cov.errors), libraryDamaged: int(cov.libraryDamaged) },
    standards: { maswe: strs(std.maswe, 16, CAP.std), mastg: strs(std.mastg, 24, CAP.std), masvs: strs(std.masvs, 32, CAP.std), cwe: strs(std.cwe, 16, CAP.std) },
    evidence: (Array.isArray(o.evidence) ? o.evidence.slice(0, CAP.evidence) : []).map(cleanEvidence).filter(Boolean),
    repro: repro ? { steps: strs(repro.steps, CAP.step, CAP.steps), command: strs(repro.command, CAP.step, CAP.argv) } : null
  };
}
