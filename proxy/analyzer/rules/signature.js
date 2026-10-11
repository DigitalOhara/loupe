/** Signature facts from apksig (see jadx.js `signature`). The verdict is cached per decompile entry. */
import fsp from 'node:fs/promises';
import path from 'node:path';
import { finding } from '../evidence.js';
import { openZip, readEntry } from '../../zipfile.js';
import { certificates } from '../apksig.js';

const sigEv = (sig, note, focus = '') => ({
  kind: 'signature', ref: { path: 'sig.json', startLine: null, endLine: null }, note, focus,
  excerpt: [`verified: ${sig.verified}`, ...Object.entries(sig.schemes || {}).map(([k, v]) => `${k}: ${v.present ? (v.verified ? 'valid' : 'INVALID') : 'absent'}`), ...(sig.signers || []).map((s) => `signer: ${s.subject}`), ...(sig.errors || []).map((e) => `error: ${e}`)].join('\n')
});

const MAX_APK = 200 * 1024 ** 2;
const algorithm = {
  id: 'signature.algorithm', title: 'APK signed with a weak algorithm or key', category: 'CRYPTO', needs: ['apk'],
  async run({ input }) {
    const findings = [], seen = new Set();
    let unread = 0;
    for (const file of input.apkPaths()) {
      const part = path.basename(file), st = await fsp.stat(file).catch(() => null);
      if (!st || st.size > MAX_APK) { input.stats.skipped++; unread++; continue; }
      const apk = await fsp.readFile(file).catch(() => null);
      if (!apk) { input.stats.skipped++; unread++; continue; }
      const v1 = [], zip = await openZip(file).catch(() => null);
      for (const e of zip?.entries || []) if (/^META-INF\/[^/]+\.(?:RSA|DSA|EC)$/i.test(e.name) && e.unc < 64 * 1024) { const b = await readEntry(zip, e, 64 * 1024).catch(() => null); if (b) v1.push(b); }
      input.stats.examined++;
      for (const c of certificates(apk, v1)) {
        const why = [];
        let sev = 'medium';
        if (/^MD[245]/.test(c.sigAlg)) { why.push(`the certificate is signed with ${c.sigAlg}, a broken hash`); sev = 'high'; }
        else if (/^SHA1with/.test(c.sigAlg)) why.push(`the certificate is signed with ${c.sigAlg}, and SHA-1 is broken for signatures`);
        if (c.keyAlg === 'RSA' && c.keyBits && c.keyBits < 2048) { why.push(`the RSA key is only ${c.keyBits} bits`); sev = c.keyBits < 1024 ? 'high' : sev; }
        if (c.keyAlg === 'DSA') why.push('the key is DSA, which Android no longer recommends for app signing');
        const key = `${part}|${c.sigAlg}|${c.keyAlg}${c.keyBits}`;
        if (!why.length || seen.has(key)) continue;
        seen.add(key);
        findings.push(finding('signature.algorithm', { key, title: `Weak signing: ${c.sigAlg} ${c.keyAlg}${c.keyBits ? ` ${c.keyBits}` : ''}`, severity: sev, detection: 'exact', conclusion: 'weakness',
          summary: `The APK signing certificate is weak: ${why.join(', and ')}. An attacker who can forge or collide a signature can pass a modified app off as the original, or push a malicious update. Android compares signing certificates when it installs updates, so the certificate is the app's identity.`,
          evidence: [{ kind: 'signature', ref: { path: part, startLine: null, endLine: null }, note: 'signing certificate', focus: c.sigAlg, excerpt: `signature algorithm: ${c.sigAlg}\nkey: ${c.keyAlg}${c.keyBits ? ` ${c.keyBits} bits` : ''}` }],
          repro: { steps: ['Run apksigner verify --print-certs -v on the APK and read the certificate details.'], command: [] } }));
      }
    }
    if (!findings.length && unread) return { inconclusive: `${unread} APK part${unread === 1 ? ' was' : 's were'} too large or unreadable, so its signing certificate was not read` };
    return { findings };
  }
};

export default [{
  id: 'signature.verdict', title: 'APK signature problems', category: 'RESILIENCE', needs: ['manifest', 'signature'],
  run({ model, sig }) {
    const findings = [], s = sig.schemes || {}, min = model.manifest.minSdk ?? 1;
    const steps = ['Run apksigner verify --print-certs on the APK, or open the Info tab in the Decompiler.'];
    if (!sig.verified) findings.push(finding('signature.verdict', { key: 'invalid', title: 'APK signature does not verify', severity: 'high', detection: 'exact', conclusion: 'weakness', summary: 'apksig could not verify the APK signature. The APK may have been modified after signing, or it may be corrupt.', evidence: [sigEv(sig, 'verification failed', 'verified: false')], repro: { steps, command: [] } }));
    if ((sig.signers || []).some((x) => /CN=Android Debug/i.test(x.subject))) findings.push(finding('signature.verdict', { key: 'debug-cert', title: 'Signed with a debug certificate', severity: 'low', detection: 'exact', conclusion: 'weakness', summary: 'The APK is signed with a debug certificate (CN=Android Debug). The Android build tools generate the debug key with a well-known password, so the signature does not identify a trusted publisher.', evidence: [sigEv(sig, 'debug certificate', 'CN=Android Debug')], repro: { steps, command: [] } }));
    if (s.v1?.present && !s.v2?.present && !s.v3?.present && min <= 26) findings.push(finding('signature.verdict', { key: 'v1-only', title: 'Only a v1 signature, with minSdk 26 or lower', severity: 'medium', detection: 'exact', conclusion: 'exposure', summary: `The APK has only a v1 (JAR) signature and installs on Android versions from API ${min} up to 8.0. On those versions an attacker can modify a v1-only APK without breaking its signature (Janus, CVE-2017-13156).`, evidence: [sigEv(sig, 'no v2 or v3 signature', 'v2: absent')], repro: { steps, command: [] } }));
    // Every split must verify and share the base's signer; a split that cannot be read leaves the verdict incomplete.
    const who = (x) => (x.signers || []).map((g) => g.sha256 || `subject:${g.subject}`).sort().join('|');           // the certificate itself, not its name: two keys can share a subject
    let unread = 0;
    for (const sp of sig.splits || []) {
      if (sp.error) { unread++; continue; }
      if (!sp.verified) findings.push(finding('signature.verdict', { key: `split-invalid:${sp.file}`, title: `Split APK signature does not verify: ${sp.file}`, severity: 'high', detection: 'exact', conclusion: 'weakness', summary: `The split APK ${sp.file} failed signature verification. That part of the app may have been modified, or it may be corrupt.`, evidence: [sigEv(sp, sp.file, sp.verified ? 'signer:' : 'verified: false')], repro: { steps, command: [] } }));
      else if (who(sp) !== who(sig)) findings.push(finding('signature.verdict', { key: `split-signer:${sp.file}`, title: `Split APK signed by a different certificate: ${sp.file}`, severity: 'high', detection: 'exact', conclusion: 'weakness', summary: `The split APK ${sp.file} is signed by a different certificate than the base APK. Android refuses to install such a set, so the splits do not come from the same build.`, evidence: [sigEv(sp, sp.file, sp.verified ? 'signer:' : 'verified: false')], repro: { steps, command: [] } }));
    }
    if (!findings.length && unread) return { inconclusive: `${unread} split APK${unread === 1 ? '' : 's'} could not be verified, so only the base APK's signature was checked` };
    return { findings };
  }
}, algorithm];
