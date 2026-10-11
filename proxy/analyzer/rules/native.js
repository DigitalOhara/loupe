/** Hardening facts for the native libraries inside the APK, read straight from its zip (bounded). */
import path from 'node:path';
import { openZip, readEntry } from '../../zipfile.js';
import { parseElf } from '../elf.js';
import { finding } from '../evidence.js';

const LIB = /^lib\/([^/]+)\/([^/]+\.so)$/;
const MAX_LIBS = 256;

const native = {
  id: 'native.hardening', title: 'Native library hardening is incomplete', category: 'CODE', needs: ['apk'],
  async run({ input }) {
    // Every APK part counts: an App Bundle usually keeps its native libraries in ABI splits, not in the base.
    const libs = [];
    let unreadable = 0;
    for (const file of input.apkPaths()) {
      const part = path.basename(file), zip = await openZip(file).catch(() => null);
      if (!zip) { input.stats.skipped++; unreadable++; continue; }                                  // an unreadable part cannot be called clean
      for (const e of zip.entries) if (LIB.test(e.name)) libs.push({ zip, e, name: part === 'base.apk' ? e.name : `${part}!${e.name}` });
    }
    if (!libs.length && !unreadable) return { notApplicable: 'the APK has no native libraries' };
    const findings = [];
    if (libs.length > MAX_LIBS) input.stats.skipped += libs.length - MAX_LIBS;        // not inspected, so the rule cannot say "checked"
    for (const { zip, e, name } of libs.slice(0, MAX_LIBS)) {
      if (e.unc > 16 * 1024 ** 2) { input.stats.skipped++; continue; }
      const f = parseElf(await readEntry(zip, e, 16 * 1024 ** 2));
      if (f.error) { input.stats.skipped++; continue; }
      input.stats.examined++;
      const missing = [f.nx === false && 'non-executable stack (NX)', f.relro !== 'full' && (f.relro === 'none' ? 'RELRO' : 'full RELRO (BIND_NOW)'), !f.canary && 'stack canary', !f.pie && 'PIE', !f.fortify && 'FORTIFY_SOURCE', f.rpath && 'an empty RPATH/RUNPATH', !f.stripped && 'stripped symbols', f.dangerous.length && `unsafe imports (${f.dangerous.join(', ')})`].filter(Boolean);
      if (!missing.length) continue;
      findings.push(finding('native.hardening', {
        key: name, title: `${f.dangerous.length && missing.length === 1 ? 'Unsafe imports' : `Missing ${missing.join(', ')}`}: ${name.split('/').pop()}`, severity: 'low', detection: f.canary ? 'exact' : 'probable', conclusion: 'weakness',
        summary: `The native library ${name} has these gaps: ${missing.join(', ')}. They make memory corruption bugs in the library easier to exploit, and the library easier to analyze. Unsafe imports such as gets, system and popen allow buffer overflows and command injection if their input is not fully controlled.`,
        evidence: [{ kind: 'native', ref: { path: name, startLine: null, endLine: null }, note: '', focus: !f.canary ? 'stack canary import: no' : f.nx === false ? 'NX: no' : f.relro !== 'full' ? `RELRO: ${f.relro}` : !f.pie ? 'PIE: no' : !f.fortify ? 'FORTIFY: no' : f.rpath ? 'RPATH/RUNPATH: set' : f.dangerous.length ? 'unsafe imports: ' + f.dangerous.join(', ') : 'symbol table: present', excerpt: `NX: ${f.nx === null ? 'unknown' : f.nx ? 'yes' : 'no'}\nRELRO: ${f.relro}\nstack canary import: ${f.canary ? 'yes' : 'no'}\nPIE: ${f.pie ? 'yes' : 'no'}\nFORTIFY: ${f.fortify ? 'yes' : 'no'}\nRPATH/RUNPATH: ${f.rpath ? 'set' : 'none'}\nsymbol table: ${f.stripped ? 'stripped' : 'present'}\nunsafe imports: ${f.dangerous.join(', ') || 'none'}` }],
        repro: { steps: ['Extract the library and run readelf -lW and readelf -s on it.'], command: [] }
      }));
    }
    return { findings };
  }
};

const WEAK = /\b(?:MD5_Init|MD5Init|MD4_Init|SHA1_Init|DES_ecb_encrypt|DES_set_key|DES_crypt|RC4_set_key|RC4\b|EVP_des_\w+|EVP_rc4|EVP_md5|EVP_sha1|BF_set_key|ECB)\b/;
const nativeStrings = {
  id: 'native.strings', title: 'Native code carries cleartext URLs or weak crypto', category: 'CRYPTO', needs: ['apk'],
  async run({ input }) {
    const libs = [];
    for (const file of input.apkPaths()) {
      const zip = await openZip(file).catch(() => null);
      if (!zip) { input.stats.skipped++; continue; }
      for (const e of zip.entries) if (LIB.test(e.name)) libs.push({ zip, e });
    }
    if (!libs.length) return { notApplicable: 'the APK has no native libraries' };
    if (libs.length > MAX_LIBS) input.stats.skipped += libs.length - MAX_LIBS;        // not inspected, so the rule cannot say "checked"
    const findings = [], seen = new Set();
    for (const { zip, e } of libs.slice(0, MAX_LIBS)) {
      if (e.unc > 16 * 1024 ** 2) { input.stats.skipped++; continue; }
      const buf = await readEntry(zip, e, 16 * 1024 ** 2).catch(() => null);
      if (!buf) { input.stats.skipped++; continue; }
      input.stats.examined++;
      const t = buf.toString('latin1'), lib = e.name.split('/').pop();
      const url = /http:\/\/(?!schemas\.|www\.w3\.org|localhost|127\.0\.0\.1|10\.0\.2\.2)[\w.-]+\.[a-z]{2,}[\w\/.?=&%-]*/i.exec(t);
      if (url && !seen.has(`u|${lib}`)) { seen.add(`u|${lib}`); findings.push(finding('native.strings', { key: `url|${lib}`, title: `Cleartext URL in ${lib}`, severity: 'low', detection: 'probable', conclusion: 'weakness',
        summary: `${lib} contains an http:// address, so the native code can send requests without TLS. A network attacker can read or change that traffic. Native code also bypasses the network security config, so the app's TLS settings do not protect it.`,
        evidence: [{ kind: 'native', ref: { path: e.name, startLine: null, endLine: null }, excerpt: url[0].slice(0, 200), note: 'string in the library' }], repro: { steps: ['Run strings on the library and search for http://.'], command: [] } })); }
      const w = WEAK.exec(t);
      if (w && !seen.has(`w|${lib}`)) { seen.add(`w|${lib}`); findings.push(finding('native.strings', { key: `weak|${lib}`, title: `Weak crypto name in ${lib}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
        summary: `${lib} references ${w[0]}, a weak or broken algorithm or mode. If the library uses it to protect data or check integrity, an attacker can break or forge that protection. The name may also come from a bundled crypto library that never calls it.`,
        evidence: [{ kind: 'native', ref: { path: e.name, startLine: null, endLine: null }, excerpt: w[0], note: 'symbol or string in the library' }], repro: { steps: ['Run strings or readelf -s on the library and search for the name.'], command: [] } })); }
    }
    return { findings };
  }
};

// Files that should not ship: signing keystores and private keys, and the maps that undo obfuscation.
const LEFTOVER = [
  [/\.(?:jks|bks|keystore|p12|pfx)$|(?:^|\/)[^/]*private[^/]*\.(?:pem|key)$/i, 'Keystore or private key file', 'medium', 'A keystore or private key file is packaged in the APK. Anyone can extract it, and if it holds a signing or client key, an attacker can use it to impersonate the app or its server.'],
  [/(?:^|\/)(?:mapping|R\.mapping|obfuscate\.map|seeds|usage)\.txt$|(?:^|\/)obfuscate\.map$/i, 'Obfuscation mapping file', 'low', 'An obfuscation mapping file is packaged in the APK. It maps the renamed classes back to their real names, which undoes the obfuscation.'],
  [/\.js\.map$/i, 'JavaScript source map', 'low', 'A JavaScript source map is packaged in the APK. Anyone can use it to rebuild the original, readable source of the bundled JavaScript.']
];
const leftovers = {
  id: 'package.leftover-files', title: 'Key or mapping file left in the APK', category: 'STORAGE', needs: ['apk'],
  async run({ input }) {
    const findings = [];
    for (const file of input.apkPaths()) {
      const part = path.basename(file), zip = await openZip(file).catch(() => null);
      if (!zip) { input.stats.skipped++; continue; }
      input.stats.examined++;
      for (const e of zip.entries) {
        const hit = LEFTOVER.find(([re]) => re.test(e.name));
        if (!hit || findings.length >= 50) continue;
        const name = part === 'base.apk' ? e.name : `${part}!${e.name}`;
        findings.push(finding('package.leftover-files', {
          key: name, title: `${hit[1]}: ${name.split('/').pop()}`, severity: hit[2], detection: 'exact', conclusion: 'weakness', summary: hit[3],
          evidence: [{ kind: 'native', ref: { path: name, startLine: null, endLine: null }, excerpt: `${name} (${e.unc} bytes)`, note: hit[1] }],
          repro: { steps: ['Run unzip -l on the APK and extract the file.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

export default [native, leftovers, nativeStrings];
