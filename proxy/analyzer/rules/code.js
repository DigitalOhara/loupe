/**
 * Rules over the decompiled Java. They match a few specific, well-known idioms, not general data flow: jadx output is
 * reconstructed source, so these report `probable` detections, and say whether the match is in the app's own package.
 */
import { finding, sourceEv, SECRETS } from '../evidence.js';
import { scrub } from '../redact.js';

const JAVA = /\.java$/;
const MAX = 50;
const inApp = (rel, pkg) => !!pkg && rel.startsWith(`sources/${pkg.replace(/\./g, '/')}/`);

const TLS = [
  ['Empty checkServerTrusted', /void\s+checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*(?:\/\/[^\n]*\s*)*\}/g],
  ['HostnameVerifier that always returns true', /boolean\s+verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;\s*\}/g],
  ['WebView proceeds after an SSL error', /onReceivedSslError\s*\([^)]*\)\s*\{[\s\S]{0,240}?\.proceed\s*\(\s*\)/g],
  ['Allow-all hostname verifier', /SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER|new\s+AllowAllHostnameVerifier\s*\(/g]
];

const trustAllTls = {
  id: 'code.trust-all-tls', title: 'TLS certificate or hostname checks disabled', category: 'NETWORK', needs: ['sources'], code: true,
  async run({ input, model }) {
    const findings = [], pkg = model.manifest?.package;
    for await (const { rel, text } of input.walk('sources', JAVA)) {
      for (const [label, re] of TLS) {
        for (const m of text.matchAll(re)) {
          if (findings.length >= MAX) return { findings };
          const mine = inApp(rel, pkg);
          findings.push(finding('code.trust-all-tls', {
            key: `${label}|${scrub(rel)}`, title: `${label}: ${rel.split('/').pop()}`, severity: mine ? 'high' : 'medium', detection: 'probable', conclusion: 'weakness',
            summary: `${label} in ${rel}, ${mine ? 'in the app\'s own package' : 'in a bundled library'}. If this code is used for real connections, any certificate is accepted and TLS gives no protection against a network attacker.`,
            evidence: [sourceEv(rel, text, label.includes('proceeds') ? m.index + m[0].lastIndexOf('.proceed') : m.index, label)], repro: { steps: ['Open the evidence location in the Decompiler and check where the class is used.'], command: [] }
          }));
        }
      }
    }
    return { findings };
  }
};

const webviewDebugging = {
  id: 'code.webview-debugging', title: 'WebView debugging enabled', category: 'RESILIENCE', needs: ['sources'], code: true,
  async run({ input }) {
    const findings = [], re = /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)/g;
    for await (const { rel, text } of input.walk('sources', JAVA)) {
      for (const m of text.matchAll(re)) {
        if (findings.length >= MAX) return { findings };
        // ponytail: any non-negated debug check in the 300 characters before counts as a guard, with no control-flow analysis.
        const guard = [...text.slice(Math.max(0, m.index - 300), m.index).matchAll(/(!?)\s*(?:BuildConfig\.DEBUG|FLAG_DEBUGGABLE|isDebuggable)/g)].at(-1);
        if (guard && !guard[1]) continue;
        findings.push(finding('code.webview-debugging', {
          key: scrub(rel), severity: 'low', detection: 'probable', conclusion: 'exposure',
          summary: 'WebView debugging is turned on with no debug-build check nearby. With it on, anyone with adb can inspect and drive the app\'s WebViews from Chrome DevTools.',
          evidence: [sourceEv(rel, text, m.index)], repro: { steps: ['Open the evidence location and check whether the call is limited to debug builds.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

const SECRET_FILES = /\.(java|kt|xml|json|properties|txt|js|yml|yaml|cfg|conf|pem|key|env)$/i;

const secrets = {
  id: 'secrets.private-material', title: 'Private key or provider credential in the APK', category: 'STORAGE', needs: ['manifest'], code: true,
  async run({ input }) {
    const findings = [];
    for (const dir of ['resources', 'sources']) {
      for await (const { rel, text } of input.walk(dir, SECRET_FILES)) {
        for (const [label, re, hide, sev] of SECRETS) {
          let n = 0;                                                       // the key uses the occurrence number, never the secret, so a fingerprint cannot be used to test guesses
          for (const m of text.matchAll(re)) {
            if (findings.length >= MAX) return { findings };
            const ev = sourceEv(rel, text, m.index, label);
            if (!hide) ev.excerpt = m[0];                                  // a private key: show the header line only, never the key body
            findings.push(finding('secrets.private-material', {
              key: `${label}|${scrub(rel)}|${n++}`, title: `${label} in ${rel.split('/').pop()}`, severity: sev || 'high', detection: 'probable', conclusion: 'weakness',
              summary: `${label} is stored in the app package at ${rel}. Anyone can extract it from the APK.`,
              evidence: [ev], repro: { steps: ['Open the evidence location in the Decompiler.'], command: [] }
            }));
          }
        }
      }
    }
    return { findings };
  }
};

export default [trustAllTls, webviewDebugging, secrets];
