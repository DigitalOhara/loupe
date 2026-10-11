import fs from 'node:fs';

const data = JSON.parse(fs.readFileSync(new URL('./standards.json', import.meta.url), 'utf8'));
export const SNAPSHOT = data.snapshot;

/** The related standards for a rule, with the MASVS category derived from the rule's own category. */
export function standardsFor(rule) {
  const s = data.rules[rule.id] || {};
  return { maswe: s.maswe || [], mastg: s.mastg || [], cwe: s.cwe || [], masvs: [`MASVS-${rule.category}`] };
}
