/** Secrets found by name and shape: assigned literals in code and resources, and key-shaped constants in the dex and native strings. */
import path from 'node:path';
import { openZip, readEntry } from '../../zipfile.js';
import { finding, sourceEv, SECRETS } from '../evidence.js';
import { scrub } from '../redact.js';
import { KV, XML_STRING, PROP, EMBEDDED, embeddedValue, plausible, keyShaped, entropy } from '../secretscan.js';
import { isLibrary } from './appcode.js';

const MAX = 50;
const TEXT = /\.(java|kt|xml|json|properties|txt|yml|yaml|cfg|conf|env|ini|gradle)$/i;
const TRANSLATION = /\/res\/values-[a-z]{2}(?:-r[A-Z]{2})?\//;       // the same strings again in another language

const hardcoded = {
  id: 'secrets.hardcoded-values', title: 'Password, key or secret assigned a literal value', category: 'STORAGE', needs: ['manifest'], code: true,
  async run({ input }) {
    const findings = [], seen = new Set();
    const hit = (rel, text, m, name, value) => {
      const key = `${scrub(rel)}|${name.toLowerCase()}`;
      if (seen.has(key) || !plausible(name, value) || findings.length >= MAX) return;
      seen.add(key);
      const strong = value.length >= 16 && entropy(value) >= 3.5;
      findings.push(finding('secrets.hardcoded-values', {
        key, title: `${name} = a literal value in ${rel.split('/').pop()}`, severity: strong ? 'high' : 'medium', detection: strong ? 'probable' : 'heuristic', conclusion: 'weakness',
        summary: `${name} is set to a fixed value in ${rel}. A secret that ships in the app can be read by anyone who unpacks it.${strong ? '' : ' The value was matched by name and shape only, so it may be a public identifier or a test value.'}`,
        evidence: [sourceEv(rel, text, m.index, name)], repro: { steps: ['Open the evidence location in the Decompiler and check what the value protects.'], command: [] }
      }));
    };
    for (const dir of ['sources', 'resources']) {
      for await (const { rel, text } of input.walk(dir, TEXT, { skipDir: (r) => (dir === 'sources' && isLibrary(r)) || TRANSLATION.test(`${r}/`) })) {
        for (const re of /\.(?:properties|env|ya?ml|cfg|conf|ini|txt)$/i.test(rel) ? [KV, PROP] : /\.xml$/i.test(rel) ? [XML_STRING] : [KV]) for (const m of text.matchAll(re)) hit(rel, text, m, m[1], m[2]);
        if (/\.(?:java|kt)$/.test(rel)) for (const m of text.matchAll(EMBEDDED)) {           // a credential inside an XML or SOAP payload kept in a string
          const key = `${scrub(rel)}|embedded|${m[1].toLowerCase()}`;
          if (seen.has(key) || !embeddedValue(m[2]) || findings.length >= MAX) continue;
          seen.add(key);
          findings.push(finding('secrets.hardcoded-values', {
            key, title: `${m[1]} = embedded in a string payload in ${rel.split('/').pop()}`, severity: /pass|secret|key/i.test(m[1]) ? 'high' : 'medium', detection: 'probable', conclusion: 'weakness',
            summary: `${m[1]} is set to a fixed value inside a string in ${rel}. A credential that ships in the app can be read by anyone who unpacks it.`,
            evidence: [sourceEv(rel, text, m.index, m[1])], repro: { steps: ['Open the evidence location in the Decompiler and check what the value protects.'], command: [] }
          }));
        }
      }
    }
    return { findings };
  }
};

const BIN = /^(?:classes\d*\.dex|lib\/[^/]+\/[^/]+\.so|assets\/.+\.(?:so|bin|dat|db|cfg|properties|keys?|bundle))$/i;
const MAX_ENTRY = 48 * 1024 ** 2, MAX_ENTRIES = 80;

/** Printable runs of a binary, like `strings`. Dex strings are length-prefixed, native ones null-terminated: both are runs of printable bytes. */
const runs = (buf) => buf.toString('latin1').match(/[\x20-\x7e]{8,}/g) || [];

const binary = {
  id: 'secrets.binary-strings', title: 'Key or secret in compiled code strings', category: 'STORAGE', needs: ['apk'], code: true,
  async run({ input }) {
    const findings = [], seen = new Set(), index = new Map();
    const add = (entry, label, value, why) => {
      if (seen.has(`${entry}|${label}|${value}`) || findings.length >= MAX) return;
      seen.add(`${entry}|${label}|${value}`);
      const slot = `${entry}|${label}`, n = index.get(slot) || 0;
      index.set(slot, n + 1);
      const key = `${slot}|${n}`;                                    // the occurrence number, never the value: a rotated key keeps its identity
      findings.push(finding('secrets.binary-strings', {
        key, title: `${label} in ${entry.split('!').pop()}`, severity: why === 'format' ? 'high' : 'low', detection: why === 'format' ? 'probable' : 'heuristic', conclusion: 'weakness',
        summary: `${label} appears in the compiled code of ${entry}. ${why === 'format' ? 'Its format belongs to a provider, so it is probably a real credential that anyone who unpacks the APK can read.' : 'Only its shape was checked, so it could be a hash or an identifier; if it is a real key, anyone who unpacks the APK can read it.'}`,
        evidence: [{ kind: 'native', ref: { path: entry, startLine: null, endLine: null }, excerpt: value.slice(0, 240), note: label }],
        repro: { steps: ['Extract the file from the APK and run strings on it, or search the value in the Decompiler.'], command: [] }
      }));
    };
    let looked = 0;
    for (const file of input.apkPaths()) {
      const part = path.basename(file), zip = await openZip(file).catch(() => null);
      if (!zip) { input.stats.skipped++; continue; }
      for (const e of zip.entries.filter((x) => BIN.test(x.name))) {
        if (looked++ >= MAX_ENTRIES || e.unc > MAX_ENTRY) { input.stats.skipped++; continue; }
        const name = part === 'base.apk' ? e.name : `${part}!${e.name}`;
        const buf = await readEntry(zip, e, MAX_ENTRY).catch(() => null);
        if (!buf) { input.stats.skipped++; continue; }
        input.stats.examined++;
        for (const s of runs(buf)) {
          for (const [label, re] of SECRETS) { re.lastIndex = 0; const m = re.exec(s); if (m) add(name, label, m[0], 'format'); }
          const kind = keyShaped(s);
          if (kind) add(name, kind[0].toUpperCase() + kind.slice(1), s, 'shape');
        }
      }
    }
    return { findings };
  }
};

export default [hardcoded, binary];
