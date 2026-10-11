/**
 * Hybrid and cross-platform apps keep their logic outside the Java sources: web files (Cordova, Capacitor), a JavaScript bundle (React Native),
 * a compiled Dart snapshot (Flutter), Unity metadata and .NET assemblies. These rules read those files straight from the APK zip, plus the
 * names of packers and protectors that wrap the code.
 */
import path from 'node:path';
import { openZip, readEntry } from '../../zipfile.js';
import { finding } from '../evidence.js';

const MAX_READ = 32 * 1024 ** 2;

/** Every entry of every APK part: [{ name (shown), entry, zip }]. A part that cannot be opened counts as skipped. */
async function entriesOf(input) {
  const out = [];
  for (const file of input.apkPaths()) {
    const part = path.basename(file), zip = await openZip(file).catch(() => null);
    if (!zip) { input.stats.skipped++; continue; }
    for (const e of zip.entries) out.push({ name: part === 'base.apk' ? e.name : `${part}!${e.name}`, path: e.name, e, zip });
  }
  return out;
}
const read = async (input, x) => {
  if (x.e.unc > MAX_READ) { input.stats.skipped++; return null; }
  const b = await readEntry(x.zip, x.e, MAX_READ).catch(() => null);
  if (!b) input.stats.skipped++; else input.stats.examined++;
  return b;
};
const ev = (name, excerpt, note) => ({ kind: 'native', ref: { path: name, startLine: null, endLine: null }, excerpt: String(excerpt).slice(0, 240), note });
const out = (id, key, title, severity, detection, summary, evidence, steps) => finding(id, { key, title, severity, detection, conclusion: 'weakness', summary, evidence, repro: { steps: [steps], command: [] } });

const PACKERS = [
  [/(?:^|\/)lib(?:jiagu|jgdtc|secexe|secmain|DexHelper|protectClass|mobisec|baiduprotect|nqshield|egis|ijiami|dexjni|apkprotect|kwscmm|protect)\w*\.so$/i, 'Qihoo 360 Jiagu, Bangcle, Ijiami or a similar packer'],
  [/(?:^|\/)libexec(?:pp)?\.so$|(?:^|\/)libexecmain\.so$/i, 'Bangcle packer'],
  [/(?:^|\/)libAppSuit\w*\.so$|(?:^|\/)libappsuit\w*\.so$/i, 'AppSuit'],
  [/(?:^|\/)libdexguard\w*\.so$|guardsquare|dexguard/i, 'Guardsquare DexGuard'],
  [/(?:^|\/)libtalsec\w*\.so$|talsec|freerasp/i, 'Talsec freeRASP'],
  [/(?:^|\/)lib(?:arxan|whitecryption|promon|shield)\w*\.so$|promon|arxan/i, 'Arxan, Promon or Whitecryption protection']
];
const protector = {
  id: 'package.protector', title: 'Packer or app protector found', category: 'RESILIENCE', needs: ['apk'],
  async run({ input }) {
    const found = new Map();
    for (const x of await entriesOf(input)) for (const [re, label] of PACKERS) if (re.test(x.path) && !found.has(label)) found.set(label, x.name);
    input.stats.examined++;
    if (!found.size) return { findings: [] };
    return { findings: [...found].map(([label, name]) => out('package.protector', label, `Protector: ${label}`, 'info', 'probable',
      `The APK contains files that belong to ${label}. Packers and protectors encrypt or hide the real code, so a static scan of the decompiled sources sees only a stub. Findings about this app are therefore a lower bound, and a dynamic session shows more.`,
      [ev(name, name, 'file that identifies the protector')], 'List the APK with unzip -l and look for the named file.')) };
  }
};

const cordova = {
  id: 'package.hybrid-web', title: 'Hybrid web app configuration is weak', category: 'PLATFORM', needs: ['apk'],
  async run({ input }) {
    const all = await entriesOf(input);
    const html = all.filter((x) => /^assets\/www\/.+\.html$/i.test(x.path)), cap = all.find((x) => x.path === 'assets/capacitor.config.json');
    if (!html.length && !cap) return { notApplicable: 'the APK has no Cordova or Capacitor web files' };
    const findings = [];
    const idx = html.find((x) => /(?:^|\/)index\.html$/i.test(x.path));
    if (idx) {
      const t = (await read(input, idx))?.toString('utf8') || '';
      if (t && !/<meta[^>]+http-equiv=["']?Content-Security-Policy/i.test(t)) findings.push(out('package.hybrid-web', 'no-csp', 'No Content Security Policy in index.html', 'medium', 'exact',
        'The app\'s main web page has no Content-Security-Policy. Without one, any script that gets injected into the page runs with the app\'s plugin access. In a hybrid app that can mean reading files, contacts or the camera.',
        [ev(idx.name, t.split('\n').slice(0, 6).join('\n'), 'start of the page: no CSP meta tag')], 'Open assets/www/index.html and look for a Content-Security-Policy meta tag.'));
    }
    for (const x of html.concat(all.filter((y) => /^assets\/www\/.+\.js$/i.test(y.path))).slice(0, 200)) {
      if (!/\.js$/i.test(x.path)) continue;
      const t = (await read(input, x))?.toString('utf8') || '';
      const m = /\beval\s*\(|new\s+Function\s*\(/.exec(t);
      if (m && !/\.min\.js$|vendor|polyfill|runtime/.test(x.path)) findings.push(out('package.hybrid-web', `eval|${x.name}`, `eval or Function in ${x.path.split('/').pop()}`, 'low', 'heuristic',
        'The web code of the app builds and runs code from strings with eval or the Function constructor. If any part of that string comes from a server, a link or a stored value, an attacker can run script in the app\'s WebView. A strict Content Security Policy would normally block this call.',
        [ev(x.name, t.slice(Math.max(0, m.index - 60), m.index + 100), 'the call')], 'Open the file and look at what is passed to eval.'));
    }
    if (cap) {
      const t = (await read(input, cap))?.toString('utf8') || '';
      for (const [re, label, text] of [
        [/"cleartext"\s*:\s*true/, 'Capacitor allows cleartext', 'capacitor.config.json sets server.cleartext to true, so the web view may load pages over plain HTTP. A network attacker can change those pages. The scripts they inject then reach the app\'s native plugins.'],
        [/"allowNavigation"\s*:\s*\[[^\]]*"\*"/, 'Capacitor allows navigation anywhere', 'capacitor.config.json lets the web view navigate to any host. A link or redirect can then load attacker pages inside the app. Those pages run with the same bridge to native code as the app\'s own.'],
        [/"webContentsDebuggingEnabled"\s*:\s*true/, 'Capacitor web debugging enabled', 'capacitor.config.json turns on WebView debugging. Anyone with adb can attach Chrome DevTools and read or change the app\'s pages, storage and tokens. This setting belongs only in debug builds.']
      ]) { const m = re.exec(t); if (m) findings.push(out('package.hybrid-web', label, label, 'medium', 'exact', text, [ev(cap.name, t.slice(Math.max(0, m.index - 40), m.index + 120), 'setting')], 'Open assets/capacitor.config.json.')); }
    }
    return { findings };
  }
};

const HERMES = Buffer.from([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]);
const reactNative = {
  id: 'package.react-native', title: 'React Native bundle weakness', category: 'STORAGE', needs: ['apk'],
  async run({ input }) {
    const b = (await entriesOf(input)).find((x) => x.path === 'assets/index.android.bundle');
    if (!b) return { notApplicable: 'the APK has no React Native bundle' };
    const buf = await read(input, b);
    if (!buf) return { inconclusive: 'the React Native bundle could not be read or is larger than the read limit' };
    const findings = [];
    if (buf.subarray(0, 8).equals(HERMES)) {
      findings.push(out('package.react-native', 'hermes', 'Hermes bytecode: JavaScript not readable', 'info', 'exact',
        'The app\'s JavaScript is compiled to Hermes bytecode, which Loupe does not decompile. Logic and secrets in the JavaScript are not covered by the source rules, and only plain strings in the bundle are scanned. Hermes bytecode can be disassembled with public tools, so it is not protection.',
        [ev(b.name, 'Hermes bytecode header', 'file type')], 'Run hbc-disassembler on assets/index.android.bundle.'));
      return { findings };
    }
    const t = buf.toString('utf8');
    for (const [re, label, sev, text] of [
      [/AsyncStorage\.setItem\(\s*["'`][^"'`]*(?:token|password|passwd|secret|jwt|session|pin)[^"'`]*["'`]/i, 'Secret saved in AsyncStorage', 'medium', 'The JavaScript saves a token, password or session value with AsyncStorage. AsyncStorage keeps plain text in an unencrypted file in the app\'s data folder. Anyone who can read that folder, such as through a backup or a rooted phone, reads the secret.'],
      [/__DEV__\s*=\s*!0|__DEV__:\s*!0|__DEV__\s*=\s*true/, 'Development mode left on', 'medium', 'The bundle was built with __DEV__ set to true. Development mode adds the debug menu, verbose error screens and extra logging, and it runs slower code paths. A build like this should never reach users.'],
      [/console\.(?:log|debug|info)\([^)]*(?:token|password|secret|jwt|authorization)/i, 'Secret written with console.log', 'low', 'The JavaScript logs a token, password or authorization value with console.log. React Native forwards these calls to logcat, which other apps and adb can read on older or debuggable builds. A logged secret is exposed.'],
      [/(?:localhost|10\.0\.2\.2|127\.0\.0\.1):8081/, 'Metro dev server address in the bundle', 'low', 'The bundle holds the Metro development server address on port 8081. A release build should load only its packaged bundle. The address suggests development settings shipped in the build.']
    ]) { const m = re.exec(t); if (m) findings.push(out('package.react-native', label, label, sev, 'probable', text, [ev(b.name, t.slice(Math.max(0, m.index - 40), m.index + 140), 'match in the bundle')], 'Search assets/index.android.bundle for the shown text.')); }
    return { findings };
  }
};

const flutter = {
  id: 'package.flutter', title: 'Flutter app storage weakness', category: 'STORAGE', needs: ['apk'],
  async run({ input }) {
    const app = (await entriesOf(input)).filter((x) => /^lib\/[^/]+\/libapp\.so$/.test(x.path));
    if (!app.length) return { notApplicable: 'the APK has no Flutter app library' };
    const findings = [];
    for (const x of app.slice(0, 1)) {
      const buf = await read(input, x);
      if (!buf) return { inconclusive: 'the Flutter library could not be read' };
      const t = buf.toString('latin1');
      if (/shared_preferences/.test(t) && !/flutter_secure_storage/.test(t)) findings.push(out('package.flutter', 'prefs', 'Flutter app uses shared_preferences without secure storage', 'low', 'heuristic',
        'The Dart code uses the shared_preferences plugin and does not include flutter_secure_storage. shared_preferences writes plain XML to the app\'s data folder, so anything saved there is readable by someone with access to that folder. Tokens and passwords should live in the Android Keystore.',
        [ev(x.name, 'shared_preferences: present\nflutter_secure_storage: absent', 'plugin names found in the compiled Dart')], 'Run strings on libapp.so and search for the plugin names.'));
    }
    return { findings };
  }
};

const unity = {
  id: 'package.unity', title: 'Unity app stores data in PlayerPrefs', category: 'STORAGE', needs: ['apk'],
  async run({ input }) {
    const all = await entriesOf(input);
    const files = all.filter((x) => /(?:^|\/)global-metadata\.dat$|(?:^|\/)Assembly-CSharp\.dll$/.test(x.path));
    if (!files.length && !all.some((x) => /libil2cpp\.so$|libunity\.so$/.test(x.path))) return { notApplicable: 'the APK has no Unity runtime' };
    const findings = [];
    for (const x of files) {
      const buf = await read(input, x);
      if (!buf) continue;
      if (/PlayerPrefs/.test(buf.toString('latin1'))) findings.push(out('package.unity', 'playerprefs', 'Unity code uses PlayerPrefs', 'low', 'heuristic',
        'The game code calls PlayerPrefs. Unity stores these values in an XML file in the app\'s shared_prefs folder with no encryption. Saved scores, tokens and purchase flags can be read and edited by anyone who can open that file.',
        [ev(x.name, 'PlayerPrefs referenced in the compiled code', 'name found in the metadata')], 'Search the file for PlayerPrefs, then read shared_prefs/<package>.v2.playerprefs on a rooted phone.'));
    }
    return { findings: findings.slice(0, 1) };
  }
};

const dotnet = {
  id: 'package.dotnet', title: '.NET app weakness', category: 'NETWORK', needs: ['apk'],
  async run({ input }) {
    const dlls = (await entriesOf(input)).filter((x) => /^assemblies\/[^/]+\.dll$/.test(x.path));
    if (!dlls.length) return { notApplicable: 'the APK has no .NET assemblies' };
    const findings = [];
    let compressed = 0;
    for (const x of dlls.slice(0, 120)) {
      const buf = await read(input, x);
      if (!buf) continue;
      if (buf.subarray(0, 4).toString('latin1') === 'XALZ') { compressed++; continue; }
      if (/^(?:System|Microsoft|Mono|netstandard|mscorlib|Xamarin|Java\.|Newtonsoft|SkiaSharp|Plugin|Square|Google|AndroidX)/.test(path.basename(x.path))) continue;                 // the app's own assemblies, not the framework
      const t = buf.toString('latin1');
      if (/ServerCertificateValidationCallback/.test(t)) findings.push(out('package.dotnet', `cb|${x.name}`, `Custom certificate validation in ${path.basename(x.path)}`, 'medium', 'heuristic',
        'The assembly sets a ServerCertificateValidationCallback. Such a callback often returns true to get past a certificate error in testing, which turns off TLS checks for the whole app. A network attacker can then read and change its traffic.',
        [ev(x.name, 'ServerCertificateValidationCallback referenced', 'name found in the assembly metadata')], 'Decompile the assembly with ILSpy and read the callback body.'));
      if (/Preferences/.test(t) && /Microsoft\.Maui\.Storage|Xamarin\.Essentials/.test(t) && !/SecureStorage/.test(t)) findings.push(out('package.dotnet', `prefs|${x.name}`, `Preferences without SecureStorage in ${path.basename(x.path)}`, 'low', 'heuristic',
        'The assembly saves data with Preferences and never uses SecureStorage. Preferences writes plain XML to the app\'s data folder. Tokens and credentials stored there can be read by anyone with access to that folder.',
        [ev(x.name, 'Preferences: used\nSecureStorage: absent', 'names found in the assembly')], 'Decompile the assembly and search for Preferences.Set.'));
    }
    if (compressed && !findings.length) return { inconclusive: `${compressed} assemblies are compressed (XALZ), so their contents were not read` };
    return { findings };
  }
};

export default [protector, cordova, reactNative, flutter, unity, dotnet];
