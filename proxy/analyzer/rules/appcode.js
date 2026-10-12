/**
 * Rules over the app's decompiled classes, minus well-known library packages, one finding per pattern and file. Each one matches a few well-known
 * idioms on reconstructed source, so detections are `probable` or `heuristic`. One factory builds them all: they differ
 * only in their patterns and wording.
 */
import { finding, sourceEv, manifestEv, isLocalHost } from '../evidence.js';
import { scrub } from '../redact.js';

const JAVA = /\.java$/;
const MAX = 50;
/** How many arguments the first call in `src` has (commas inside nested brackets and strings do not count). */
function topLevelArgs(src) {
  let depth = 0, n = 0, str = null, started = false;
  for (const ch of src) {
    if (str) { if (ch === str) str = null; continue; }
    if (ch === '"' || ch === "'") str = ch;
    else if (ch === '(' || ch === '[' || ch === '{') { if (!started) { started = true; n = 1; } else depth++; }
    else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth--; }
    else if (ch === ',' && depth === 0 && started) n++;
  }
  return n;
}
const hostOk = (u) => isLocalHost(String(u).split(/[/:?#]/)[0]);

/**
 * Well-known library packages, which are pruned from the walk. Everything else under sources/ counts as the app's code, so first-party code is never
 * skipped because it sits under an unexpected package name. An unrecognised third-party library is scanned too, which can add noise but never hides code.
 */
const LIBRARY = /^sources\/(?:androidx|android\/support|kotlin|kotlinx|java|javax|dagger|org\/(?:apache|jetbrains|intellij|slf4j|bouncycastle|json)|okhttp3|okio|retrofit2|io\/(?:flutter|reactivex|realm|branch)|com\/(?:google|jakewharton|github|airbnb|caverock|squareup|facebook|crashlytics|adjust|appsflyer|mixpanel|amplitude|segment|bumptech|android\/(?:volley|billingclient|installreferrer)))(?:\/|$)/;
export const isLibrary = (rel) => LIBRARY.test(rel);
const appCode = (input) => input.walk('sources', JAVA, { skipDir: isLibrary });
const ABSENCE = 'part of the code was not decompiled or not read, so the absence of this cannot be claimed';
const NO_CLASSES = 'no decompiled classes were found outside the well-known library packages, so the app\'s own code was not checked';


/** pattern: [label, regex, { sev?, gate?, detection?, skip?(match, text) }]. */
function appRule(id, title, category, summary, patterns, repro = 'Open the evidence location in the Decompiler and check that the code is reachable.') {
  return {
    id, title, category, needs: ['sources', 'manifest'], code: true,
    async run({ input, model }) {
      const findings = [];
      let scanned = 0;
      for await (const { rel, text } of appCode(input)) {
        scanned++;
        for (const [label, re, o = {}] of patterns) {
          if (o.gate && !o.gate.test(text)) continue;
          for (const m of text.matchAll(re)) {
            if (findings.length >= MAX) return { findings };
            if (o.skip?.(m, text)) continue;
            const ev = sourceEv(rel, text, m.index, label);
            findings.push(finding(id, {
              key: `${label}|${scrub(rel)}`, title: `${label}: ${rel.split('/').pop()}`, severity: o.sev || 'medium',
              detection: o.detection || 'probable', conclusion: 'weakness', summary: o.d || summary(o),
              evidence: [ev], repro: { steps: [repro], command: [] }
            }));
            break;                                                          // one finding per pattern and file; the Decompiler shows the rest
          }
        }
      }
      return findings.length || scanned || input.stats.truncated ? { findings } : { inconclusive: NO_CLASSES };
    }
  };
}

const credentials = appRule('code.hardcoded-credential', 'Hardcoded credential or backdoor', 'STORAGE',
  () => 'A login decision or secret is fixed in the app\'s code. Anyone who decompiles the APK can read it. It may grant access that the normal login path does not.',
  [
    ['Credential compared with a hardcoded value', /\b(\w*(?:user(?:name)?|passw(?:or)?d|pwd|passcode|admin(?:name|user)?))\s*\.equals(?:IgnoreCase)?\(\s*"([^"]{3,})"\s*\)/gi, { d: 'The app compares a username, password or passcode variable against a string literal to decide whether to grant access. The literal is stored in the APK, so anyone who decompiles it can read the accepted value. That value can be used to log in or to reach functionality the normal authentication path would not allow.', sev: 'high' }],
    ['Keystore opened with a literal password', /\.load\s*\([^;]*"([^"]{2,})"\s*\.toCharArray\s*\(\)/g, { d: 'A KeyStore is loaded with a password written as a string literal in the code. The password sits in the APK in readable form, so anyone holding the app package and the keystore file can open the keystore. That exposes the private keys and certificates stored in it.', sev: 'high' }],
    ['Database opened with a literal key', /(?:getWritableDatabase|getReadableDatabase|openOrCreateDatabase|openDatabase)\s*\([^;]*"([^"]{4,})"\s*\)|\.encryptionKey\s*\(\s*"([^"]{4,})"/g, { d: 'An encrypted database (SQLCipher or Realm) is opened with a key written as a string literal. The key can be recovered from the APK, so it gives no protection to someone who obtains the database file. An attacker with a backup, a rooted device or a copy of the file can decrypt all of the stored data.', sev: 'high', gate: /sqlcipher|SQLCipher|io\.realm|SupportFactory|net\.zetetic/ }],
    ['Hardcoded value compared with a credential', /"([^"]{3,})"\s*\.equals(?:IgnoreCase)?\(\s*[\w.]*(?:user(?:name)?|passw(?:or)?d|pwd|passcode)\s*\)/gi, { d: 'The app compares a hardcoded string with a username or password variable. The literal is readable by decompiling the APK. It may be a backdoor or default credential that works for every installation of the app.', sev: 'high' }]
  ]);

const CRYPTO = /Cipher|MessageDigest|SecretKeySpec/;
const crypto = appRule('code.weak-crypto', 'Weak or misused cryptography', 'CRYPTO',
  () => 'The app encrypts or hashes with a weak mode, a fixed IV, a short key or a key stored in the code. Anyone who decompiles the APK can read the key material or reproduce the weakness. Data the app protects this way can be decrypted or forged.',
  [
    ['Weak cipher or ECB mode', /Cipher\.getInstance\(\s*"(?:AES|DES\w*|RC[24]|ARCFOUR|Blowfish|(?!RSA\/)[\w]+\/ECB\/\w+)"/g, { d: 'Cipher.getInstance requests DES, RC2, RC4, Blowfish, an ECB mode, or a bare AES name that defaults to AES/ECB on Android. ECB encrypts identical plaintext blocks to identical ciphertext blocks, and DES and RC4 are broken or have short keys. Ciphertext can reveal plaintext patterns and may be brute-forced or modified.', sev: 'medium' }],
    ['Constant IV', /byte\[\]\s+\w*(?:iv|nonce)\w*\s*=\s*\{\s*(?:-?\w+\s*,\s*)*-?\w+\s*\}/gi, { d: 'A byte array literal named like an IV or nonce supplies the initialization data for a cipher. A fixed IV makes identical plaintexts encrypt to identical ciphertexts, and reusing a nonce with the same key in CTR or GCM mode breaks both confidentiality and integrity. An attacker who collects several ciphertexts can learn about the plaintexts or forge messages.', sev: 'low', gate: CRYPTO }],
    ['Fixed initialization vector', /new\s+(?:IvParameterSpec|GCMParameterSpec)\s*\([^;]*?"[^"]{8,}"\s*\.getBytes\s*\(|byte\[\]\s+(\w+)\s*=\s*"[^"]{8,}"\s*\.getBytes\s*\([^)]*\)\s*;[\s\S]{0,600}?new\s+(?:IvParameterSpec|GCMParameterSpec)\s*\([^;]*?\b\1\b/g, { sev: 'high', d: 'The initialization vector for a cipher is a fixed string in the code. A repeated IV with the same key lets an attacker spot equal plaintext blocks, and in CTR or GCM mode it can expose the key stream. The IV must be random and new for every encryption.' }],
    ['Key built from a string literal', /SecretKeySpec\s*\(\s*"([^"]{4,})"/g, { d: 'A SecretKeySpec is created directly from a string literal. The key bytes are stored in the APK, so every installation shares the same key and anyone can read it. All data encrypted with this key can be decrypted offline.', sev: 'high' }],
    ['RSA without OAEP padding', /Cipher\.getInstance\(\s*"RSA(?:\/[A-Z]+\/(?:PKCS1Padding|NoPadding))?"/g, { d: 'Cipher.getInstance requests RSA with the default, PKCS1 or no padding instead of OAEP. PKCS#1 v1.5 padding is open to padding oracle attacks such as Bleichenbacher\'s, and unpadded RSA is deterministic and malleable. An attacker who can submit ciphertexts to the decrypting side can recover plaintext or forge messages.', sev: 'low' }],
    ['Weak key size', /(?:KeyPairGenerator[\s\S]{0,200}?\.initialize\s*\(\s*(?:512|768|1024)\b|KeyGenerator[\s\S]{0,200}?\.init\s*\(\s*(?:40|56|64)\b|setKeySize\s*\(\s*(?:512|768|1024)\s*\))/g, { d: 'A key is generated with a size that is too small for current use, such as RSA of 1024 bits or less or a symmetric key of 64 bits or less. Keys of this size are within reach of factoring or brute-force attacks. An attacker who captures the protected data can recover the key and then decrypt or forge it.', sev: 'low', detection: 'heuristic' }],
    ['SecureRandom with a fixed seed', /new\s+SecureRandom\s*\(\s*[^)\s][^)]*\)|SecureRandom[\s\S]{0,300}?\.setSeed\s*\(/g, { d: 'A SecureRandom is constructed with a seed or has setSeed called on it. With some algorithms, such as SHA1PRNG, seeding before first use makes the output fully deterministic. Keys, tokens or IVs drawn from it can then be regenerated by anyone who knows or guesses the seed.', sev: 'medium', detection: 'heuristic' }],
    ['Low PBKDF2 iteration count', /new\s+PBEKeySpec\s*\([^;]*?,\s*(\d{1,4})\s*,\s*\d+\s*\)/g, { d: 'A PBEKeySpec is built with an iteration count below 10,000. The iteration count sets how costly each password guess is, so a low value lets an attacker test guesses quickly. A key or hash derived from a weak password can be brute-forced offline in a short time.', sev: 'low', skip: (m) => Number(m[1]) >= 10000 }],
    ['Home-made XOR encryption', /\b\w*(?:encrypt|decrypt|obfuscate|cipher)\w*\s*\([^)]*\)\s*\{[\s\S]{0,400}?\^\s*[\w(]/gi, { d: 'A method named like encrypt, decrypt or obfuscate applies an XOR operation as its transformation. XOR with a short or repeating key is trivially reversed, and the key is part of the app\'s code. Data protected this way can be recovered by anyone who has the APK.', sev: 'low', detection: 'heuristic' }],
    ['Bouncy Castle provider requested by name', /getInstance\s*\([^;)]*,\s*"BC"\s*\)/g, { d: 'A JCA call requests the Bouncy Castle provider by the name BC. On Android 9 and later such a request can throw NoSuchAlgorithmException for algorithms the platform now provides itself. The app may crash or silently use different behaviour, and a bundled old Bouncy Castle copy carries its own known flaws.', sev: 'low' }],
    ['MD5 or SHA-1 digest', /MessageDigest\.getInstance\(\s*"(?:MD[245]|SHA-?1)"/gi, { d: 'The app computes an MD5 or SHA-1 digest. Both have practical collision attacks, so they cannot prove that data is authentic, and fast unsalted digests of passwords are reversed with lookup tables or brute force. If the digest protects a password, token or integrity check, an attacker can forge or recover the input.', sev: 'low' }]
  ]);

const webview = appRule('code.webview-js-local', 'WebView runs JavaScript on local or untrusted content', 'PLATFORM',
  (o) => `JavaScript is enabled in a WebView${o.sev === 'high' ? ' that also loads a file from storage' : ''}. Script in the loaded content runs with the WebView\'s privileges. If an attacker can alter that content, their script runs inside the app.`,
  [
    ['WebView loads a local file with JavaScript on', /setJavaScriptEnabled\(\s*true\s*\)/g, { d: 'JavaScript is enabled in a WebView in a class that also loads a file:// URL or reads from external storage. Script inside a local file runs with the WebView\'s privileges, including any exposed Java objects. An attacker who can write that file, for example on shared storage, gets script execution inside the app.', sev: 'high', gate: /loadUrl\(\s*"file:\/\/|getExternalStorageDirectory/ }],
    ['WebView with JavaScript on', /setJavaScriptEnabled\(\s*true\s*\)/g, { d: 'JavaScript is enabled in a WebView. Any script on a page the WebView loads runs inside the app\'s process. If that content comes from an untrusted site or can be altered in transit, it can attack the app through any JavaScript bridge or steal what the page shows.', sev: 'low', skip: (m, t) => /loadUrl\(\s*"file:\/\/|getExternalStorageDirectory/.test(t) }]
  ]);

const cleartext = appRule('code.cleartext-url', 'Hardcoded cleartext HTTP URL', 'NETWORK',
  () => 'The app builds requests with http:// or ftp:// URLs. Anyone on the network path can read or change that traffic. Credentials and data sent this way are exposed unless something else upgrades the connection.',
  [['Cleartext http:// or ftp:// URL', /"(?:http|ftp):\/\/([^"\s]*)"/g, { d: 'The app contains a URL that uses http:// or ftp://, so requests to it are not encrypted. Anyone on the network path can read or change that traffic. Credentials, session tokens and responses sent over it are exposed unless something else upgrades the connection.', sev: 'low', skip: (m) => hostOk(m[1]) }]]);

const logging = appRule('code.sensitive-logging', 'Sensitive value written to the log', 'STORAGE',
  () => 'A credential is passed to Log or System.out, which writes it to logcat in clear text. Apps with log access on older Android and adb on a debuggable device can read it. The credential can then be used to take over the account.',
  [['Credential written to the log', /\b(?:Log\.[vdiwe]|System\.(?:out|err)\.print(?:ln)?)\s*\([^;\n]*\b\w*(?:password|passwd|pwd|secret|token|credential|login(?:data|info|request|response)|authdata)\w*/gi, { d: 'A variable named like a password, token or secret is passed to Log or System.out, which writes it to logcat in clear text. Logcat is readable through adb on a debuggable device or with USB debugging, and apps holding READ_LOGS could read it on older Android versions. The logged credential can be used to take over the account or session.', sev: 'high' }]]);

const storage = appRule('code.external-storage', 'Data written to shared external storage', 'STORAGE',
  () => 'The app writes to the shared storage root. Other apps with storage access can read or replace what it writes.',
  [['Shared external storage', /Environment\.getExternalStorage(?:Public)?Directory\s*\(/g, { d: 'The app uses Environment.getExternalStorageDirectory or getExternalStoragePublicDirectory, which point at shared storage. On Android 10 and earlier any app with the storage permission can read, replace or delete files placed there. Sensitive data written there leaks, and files the app reads back later can be swapped for attacker-controlled content.', sev: 'low' }]]);

const root = appRule('code.client-root-check', 'Client-side root detection', 'RESILIENCE',
  () => 'The app decides on the device whether it is rooted. That check lives in code the user controls, so it can be hooked or patched out.',
  [['Root check by file or su lookup', /Superuser\.apk|\/system\/(?:x?bin|app)\/su\b|"which"\s*,\s*"su"|\bRootBeer\b|\bisDeviceRooted\s*\(|\bRootTools\b/g, { d: 'The app looks for su binaries, Superuser.apk, or uses RootBeer or RootTools to decide whether the device is rooted. The check runs in code on a device the user controls, so it can be hooked with Frida or Xposed or patched out of the APK. An attacker on a rooted device can bypass it, and the app then runs with its client-side restriction removed.', sev: 'low', detection: 'heuristic' }]]);

const SMS = appRule('code.sms-send', 'App sends SMS from code', 'PRIVACY',
  () => 'The app can send text messages. If it does so on request from another app, any app that can trigger it can make it send message content the app holds.',
  [['SMS sent by the app', /SmsManager\.getDefault\(\)|\.sendTextMessage\s*\(/g, { d: 'The app calls SmsManager or sendTextMessage to send text messages itself. If another app or a deep link can drive that call with an attacker-chosen number or text, the app sends messages on the user\'s behalf. The result can be premium-rate charges, spam from the user\'s number, or leakage of data placed in the message body.', sev: 'low' }]]);

const worldFiles = appRule('code.world-readable-file', 'World-readable or world-writable file mode', 'STORAGE',
  () => 'The app creates a file, preference or database that other apps can read or change. Android ignores these modes from API 24, but older devices honour them.',
  [['World-readable or writable mode', /MODE_WORLD_(?:READABLE|WRITEABLE)/g, { d: 'The code uses MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE when creating a file, preference or database. Those modes grant every other app on the device access to the file. Android throws a SecurityException for them when targeting API 24 or later, but older devices honour them, so other apps can read or alter the data.', sev: 'high' }],
   ['World-readable mode as a number', /\b(?:openFileOutput|openOrCreateDatabase)\s*\([^;]*,\s*(?:[1-3]|[5-7])\s*[,)]|\bgetSharedPreferences\s*\([^;]*,\s*(?:[1-3]|[5-7])\s*\)/g, { sev: 'high', d: 'A file, database or preference is opened with a numeric mode of 1, 2, 3, 5, 6 or 7. The decompiler writes MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE as these numbers. They grant every other app on the device access, and older devices honour them.' }],
   ['File opened to every app', /\.set(?:Readable|Writable)\s*\(\s*true\s*,\s*false\s*\)/g, { sev: 'medium', d: 'A file is made readable or writable by all users with setReadable(true, false) or setWritable(true, false). The false argument drops the owner-only restriction, so other apps on the device can open it. Data in it is exposed.' }]]);

const webviewSettings = appRule('code.webview-settings', 'Risky WebView settings', 'PLATFORM',
  () => 'This WebView setting widens what web content can reach: app code, local files, or cleartext resources. It matters when the WebView loads content the app does not control.',
  [
    ['Java object exposed to web content', /addJavascriptInterface\s*\(/g, { d: 'A Java object is exposed to JavaScript in a WebView through addJavascriptInterface. Any page loaded in that WebView, including injected content, can call its @JavascriptInterface methods. On Android 4.1 and earlier the bridge can be abused to reach any Java method by reflection, and on newer versions every annotated method is still callable by attacker script.', sev: 'medium' }],
    ['WebView can read files through file URLs', /setAllow(?:File|Universal)AccessFromFileURLs\s*\(\s*true\s*\)/g, { d: 'setAllowFileAccessFromFileURLs or setAllowUniversalAccessFromFileURLs is set to true. A page loaded from file:// can then read other local files, and with universal access it can read content from any origin. A malicious local or injected page can steal the app\'s private files, cookies or tokens.', sev: 'high' }],
    ['WebView file access enabled', /setAllowFileAccess\s*\(\s*true\s*\)/g, { d: 'setAllowFileAccess(true) lets the WebView load file:// URLs, and it is the default below API 30. Pages loaded that way can reach files on the device that the app can read. If an attacker can influence which page loads, local files become readable.', sev: 'low' }],
    ['Mixed content in compatibility mode', /setMixedContentMode\s*\(\s*(?:WebSettings\.)?(?:MIXED_CONTENT_COMPATIBILITY_MODE|2)\s*\)/g, { d: 'setMixedContentMode is set to MIXED_CONTENT_COMPATIBILITY_MODE, which lets HTTPS pages load some passive content such as images and media over http. A network attacker can change that content in transit. The page can then show altered content, and the secure page loses its transport guarantees for those resources.', sev: 'low' }],
    ['WebView can read content providers', /setAllowContentAccess\s*\(\s*true\s*\)/g, { d: 'setAllowContentAccess(true) lets the WebView load content:// URLs, and it is the default. A page the attacker controls can reference content URIs, including the app\'s own providers. The page can then read data from those providers.', sev: 'low' }],
    ['Page loaded with a file:// base URL', /loadDataWithBaseURL\s*\(\s*"file:\/\//g, { d: 'loadDataWithBaseURL is called with a file:// base URL, so the loaded HTML takes a file origin. Script in that HTML runs with file-scheme privileges and can read local files when the file access settings allow it. If the HTML contains attacker-influenced data, the result is local file theft or script injection.', sev: 'low' }],
    ['JavaScript built from data and run in a WebView', /loadUrl\s*\(\s*"javascript:[^"]*"\s*\+|evaluateJavascript\s*\([^;]*\+/g, { d: 'A javascript: URL passed to loadUrl or a script given to evaluateJavascript is built by concatenating data into the script text. If any part of that data is attacker-controlled, it can close the string literal and inject its own script. The injected script runs in the page with access to the page\'s data and any JavaScript bridge.', sev: 'medium', detection: 'heuristic' }],
    ['Intercepted request answered from a local file', /shouldInterceptRequest[\s\S]{0,700}?new\s+WebResourceResponse\s*\([^;]*(?:FileInputStream|openFileInput|getAssets|openInputStream)/g, { d: 'shouldInterceptRequest returns a WebResourceResponse backed by a file, asset or content stream. If the requested URL decides which file is served without being validated, a page can request paths such as ../ to reach other local files. The response goes to the page, so an attacker-controlled page can read private files of the app.', sev: 'low', detection: 'heuristic' }],
    ['Mixed content always allowed', /setMixedContentMode\s*\(\s*(?:WebSettings\.)?(?:MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)/g, { d: 'setMixedContentMode is set to MIXED_CONTENT_ALWAYS_ALLOW, so HTTPS pages load scripts, frames and other active content over http. A network attacker can replace such a resource, and the replacement runs inside the secure page. This removes the integrity guarantee of HTTPS for the whole page.', sev: 'low' }]
  ]);

const SENSITIVE = '(?:token|nonce|passw\\w*|secret|session|otp|salt|iv|key)';
const random = appRule('code.insecure-random', 'Non-cryptographic random value for a secret', 'CRYPTO',
  () => 'java.util.Random and Math.random are predictable, and here they produce a token, key, IV or one-time code. An attacker who observes a few outputs can reconstruct the generator state. The secret can then be guessed or reproduced.',
  [['Predictable random source', new RegExp(`\\b\\w*${SENSITIVE}\\w*\\s*=[^;\\n]*(?:new\\s+Random\\s*\\(|Math\\.random\\s*\\()`, 'gi'), { d: 'A variable named like a token, key, nonce, salt or password is assigned from java.util.Random or Math.random. These generators are predictable, and their state can be reconstructed from a few observed outputs. An attacker can guess or reproduce the secret, such as a session token or one-time code.', sev: 'medium', detection: 'heuristic' }]]);

const tokenPrefs = appRule('code.plaintext-token-prefs', 'Token or credential saved in SharedPreferences', 'STORAGE',
  () => 'SharedPreferences are plain XML in the app\'s data directory. Anyone who can read that directory (a backup, a debuggable build, a rooted device) can read the value.',
  [['Credential-named SharedPreferences entry', /\.putString\(\s*"[^"]*(?:token|session|secret|auth|passw\w*|pwd)[^"]*"/gi, { d: 'A SharedPreferences entry with a name such as token, session, secret, auth or password is written with putString. SharedPreferences are stored as plain XML in the app\'s data directory, so the value is unencrypted. A backup, a rooted device or a debuggable build exposes it, which gives access to the account.', sev: 'low', detection: 'heuristic' }]]);

const execution = appRule('code.dynamic-execution', 'Dynamic code loading or OS command execution', 'CODE',
  () => 'The app loads code at runtime or runs a command. If the code or command comes from somewhere an attacker can write, that is code execution inside the app.',
  [
    ['Dynamic code loading', /new\s+(?:Dex|InMemoryDex|Path)ClassLoader\s*\(/g, { d: 'The app creates a DexClassLoader, InMemoryDexClassLoader or PathClassLoader to load classes at runtime. Code loaded this way is not part of the APK that was signed and reviewed. If the dex file comes from writable storage or the network, an attacker who replaces it runs code with the app\'s permissions.', sev: 'low' }],
    ['Code loaded from another app', /createPackageContext\s*\([^;]*(?:CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY|,\s*[1-3]\s*\))/g, { d: 'createPackageContext is called with flags that include code or ignore security checks, so the app loads and runs classes from another package. If that package is attacker-controlled or can be replaced, its code executes inside this app. It then runs with all of the app\'s permissions.', sev: 'high', detection: 'heuristic' }],
    ['Native library loaded from a built path', /System\.load\s*\(\s*[^")][^;]*\+|System\.load\s*\(\s*\w+\s*\)/g, { d: 'System.load is called with a variable or concatenated path. If the path points to writable or attacker-influenced storage, a replaced .so file gets loaded. Native code runs inside the app\'s process with its files and permissions.', sev: 'low', detection: 'heuristic' }],
    ['OS command execution', /Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(/g, { skip: (m, text) => /\.exec\s*\(\s*(?:"[^"\n]*"\s*\+\s*\w|\w+\s*\+\s*")/.test(text), d: 'The app calls Runtime.exec or ProcessBuilder to run an operating-system command. If any part of the command line comes from attacker-influenced input, extra arguments or shell metacharacters change what is executed. The command runs as the app\'s user, so injection gives access to its private data.', sev: 'low' }],
    ['OS command built from a string', /\.exec\s*\(\s*(?:\"[^\"\n]*\"\s*\+\s*\w|\w+\s*\+\s*\")/g, { sev: 'medium', detection: 'heuristic', d: 'A command passed to exec is built by joining strings. If any part comes from the user, a link or another app, it can add commands of its own. Pass the command as an argument array and validate each part.' }],
    ['Over-the-air code update library', /\bcom\.(?:microsoft\.codepush|tencent\.tinker|taobao\.sophix|meituan\.robust)\b|\bTinkerInstaller\b|\bCodePush\b/g, { sev: 'low', d: 'The app includes a library that replaces its code from a server after release, such as CodePush, Tinker or Sophix. If the update channel is not signed and pinned, whoever controls it can run code in the app. Check that updates are verified before they load.' }]
  ]);

const intents = appRule('code.intent-safety', 'Unsafe Intent or PendingIntent use', 'PLATFORM',
  () => 'This Intent pattern lets another app influence what the app starts, sends or receives. Depending on the surrounding code, data leaks to other apps or another app drives the app\'s actions with its permissions.',
  [
    ['PendingIntent without a mutability flag', /PendingIntent\.get(?:Activity|Activities|Broadcast|Service|ForegroundService)\s*\([^;]*\)/g, { d: 'A PendingIntent is created with neither FLAG_IMMUTABLE nor FLAG_MUTABLE. Apps targeting Android 12 or later must set one, and older targets default to mutable. Without FLAG_IMMUTABLE the receiving app may fill in unset fields of the base Intent, so it can redirect the action to a component of its choice with this app\'s identity and permissions.', sev: 'low', detection: 'heuristic', skip: (m) => /FLAG_(?:IM)?MUTABLE|\b(?:33554432|67108864)\b/.test(m[0]) }],
    ['Broadcast sent without a receiver permission', /\bsendBroadcast\s*\([^;]*;/g, { d: 'sendBroadcast is called without a receiver permission argument. Any app that registers a matching receiver gets the Intent and its extras. Data in the broadcast leaks to other apps, and a malicious receiver can also abort ordered broadcasts.', sev: 'medium', detection: 'heuristic', skip: (m, t) => topLevelArgs(m[0]) > 1 || /LocalBroadcastManager/.test(t.slice(Math.max(0, m.index - 80), m.index)) }],
    ['Intent built from a URL', /Intent\.parseUri\s*\(|Intent\.getIntent\s*\(/g, { d: 'Intent.parseUri or Intent.getIntent builds an Intent from a string. If the string comes from a link or another external source, the attacker chooses the component, action and extras. The app then starts any activity it can reach, including non-exported ones, with its own privileges (intent redirection).', sev: 'high', detection: 'heuristic' }],
    ['Sensitive data in an implicit Intent', /new\s+Intent\s*\(\s*"[\w.]+"\s*\)[\s\S]{0,300}?\.putExtra\s*\(\s*"[^"]*(?:token|passw|secret|session|auth|otp|pin\b|card)[^"]*"/gi, { d: 'An Intent that carries only an action name also has an extra named like a token, password, secret or card. Implicit Intents are delivered to any app with a matching filter, so a malicious app can register for the action. The extra value leaks to that app.', sev: 'medium', detection: 'heuristic', skip: (m) => /setPackage|setComponent|setClass(?:Name)?\s*\(/.test(m[0]) }],
    ['Receiver registered for any app', /registerReceiver\s*\([^;]*;/g, { d: 'registerReceiver is called with neither a permission nor the RECEIVER_NOT_EXPORTED flag, so the receiver is open to every app. Any app can send it broadcasts with crafted extras. The receiver\'s handler can then be triggered or fed data by an attacker.', sev: 'low', detection: 'heuristic', skip: (m) => /RECEIVER_NOT_EXPORTED|\b4\s*\)\s*;$|"[\w.]+\.permission\.[\w.]+"|Manifest\.permission|LocalBroadcastManager/.test(m[0]) || (topLevelArgs(m[0]) < 2) }],
    ['Mutable PendingIntent', /PendingIntent\.get\w+\([^;]*(?:FLAG_MUTABLE|\b33554432\b)/g, { d: 'A PendingIntent is created with FLAG_MUTABLE. Whoever receives it can fill in or change parts of the wrapped Intent. If the base Intent is implicit or empty, a malicious app can redirect it, and the action runs with this app\'s identity and permissions.', sev: 'low' }],
    ['Unsafe implicit PendingIntent override', /FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT/g, { d: 'FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT is used on a PendingIntent. The flag turns off the Android 14 rule that a mutable PendingIntent must wrap an explicit Intent. A malicious app can then intercept or redirect the implicit Intent, and the action runs with this app\'s identity.', sev: 'medium' }],
    ['Sticky broadcast', /sendStickyBroadcast\w*\s*\(/g, { d: 'The app calls sendStickyBroadcast. Sticky broadcasts are deprecated and cannot be restricted to specific receivers, so every app on the device can read the Intent and its extras. Any data in it leaks, and a malicious app can replace the stored value.', sev: 'medium' }],
    ['Launch protection removed', /removeLaunchSecurityProtection\s*\(/g, { d: 'removeLaunchSecurityProtection is called on an Intent. It disables the platform\'s launch-time check that blocks an Intent nested inside another Intent from starting activities. An Intent supplied by another app in an extra can then start components the app did not mean to expose, which enables intent redirection.', sev: 'low' }],
    ['Nested Intent forwarded', /get(?:Parcelable|Serializable)Extra\s*\([^;]*;[\s\S]{0,1200}?\bstartActivity\s*\(/g, { d: 'The app reads an Intent, Parcelable or Serializable from an extra and passes it to startActivity. Another app can supply any Intent in that extra, including one that targets non-exported components. The app then launches it with its own identity and permissions, which enables intent redirection.', sev: 'medium', detection: 'heuristic', gate: /\bIntent\b/ }],
    ['Service returns a binder without a caller check', /IBinder\s+onBind\s*\([^)]*\)\s*\{[\s\S]{0,300}?return\s+(?!null)[\s\S]{0,120}?;/g, { sev: 'low', detection: 'heuristic', skip: (m, text) => /checkCallingPermission|checkCallingOrSelfPermission|enforceCallingPermission|enforceCallingOrSelfPermission|getCallingUid|getCallingPackage/.test(text), d: 'onBind returns a binder or Messenger and the class never checks who is calling. If the service is exported without a permission, any app can bind to it and call its methods. Check the caller with checkCallingPermission or getCallingUid inside the binder.' }],
    ['Token returned in an activity result', /setResult\s*\([^;]{0,200}?putExtra\s*\(\s*\"[^\"]*(?:token|password|passwd|secret|session|credential)[^\"]*\"/gi, { sev: 'medium', d: 'setResult hands a value named like a token, password or session back to whichever app started the activity. If that caller is not the one the user meant, it receives the secret. Return only what the caller needs and check the calling package first.' }]
  ]);

const sql = appRule('code.sql-concatenation', 'SQL built by string concatenation', 'CODE',
  () => 'A query string is concatenated with a value instead of using bound arguments. If the value is attacker-controlled this is SQL injection, including through an exported content provider.',
  [['SQL built by concatenation', /\b(?:rawQuery|execSQL)\s*\([^;)]*"\s*\+/g, { d: 'A rawQuery or execSQL call builds its SQL text by concatenating a value with + instead of binding arguments. A value containing quotes or SQL keywords changes the structure of the query. If the value is attacker-controlled, for example through an exported content provider, the result is SQL injection that reads, alters or deletes database rows.', sev: 'medium', detection: 'heuristic' }]]);

const sqlVariable = appRule('code.sql-from-variable', 'SQL statement taken from a variable', 'CODE',
  () => 'A SQL statement comes from a variable and not from a fixed string. If that value can carry input from another app, a link or a field, the query structure is under the caller\'s control.',
  [['SQL statement run from a variable', /\b(?:execSQL|rawQuery|executeQuery|executeUpdate|compileStatement)\s*\(\s*(?!")[a-z]\w*\s*[,)]/g, { sev: 'medium', detection: 'heuristic', d: 'A SQL statement is passed to execSQL, rawQuery or executeQuery as a variable. Anything that reaches that variable from a deep link, an Intent extra or a text field can change the query, which is SQL injection. Bound arguments protect values but not a statement built from input.' }]]);

const downloadManager = appRule('code.download-mobile-only', 'Download forced onto the mobile network', 'NETWORK',
  () => 'The app restricts a download to the mobile network. The download then ignores Wi-Fi and its protections and can cost the user money.',
  [['Download limited to mobile data', /setAllowedNetworkTypes\s*\(\s*(?:1|(?:DownloadManager\.Request\.)?NETWORK_MOBILE)\s*\)/g, { sev: 'low', d: 'The app calls setAllowedNetworkTypes with NETWORK_MOBILE, so the download runs only over mobile data. It skips a trusted Wi-Fi or VPN path and can use the user\'s data plan without a choice. Large files over mobile data also expose users to carrier-level tampering.' }]]);

const zip = appRule('code.zip-slip', 'Zip entry written without a path check', 'CODE',
  () => 'A file is created from a zip entry name with no canonical-path check anywhere in the file. An entry named ../x can write outside the target directory.',
  [['Zip entry name used as a file path', /new\s+File\s*\([^;]*\.getName\s*\(\)/g, { d: 'A File is created from a ZipEntry name, and no canonical-path or normalize call appears anywhere in the same file. An entry named ../x resolves outside the extraction directory (zip slip). A crafted archive can overwrite files in the app\'s data, including code or configuration.', sev: 'medium', detection: 'heuristic', gate: /ZipEntry|ZipInputStream/, skip: (m, t) => /getCanonicalPath|\.normalize\s*\(/.test(t) }]]);

const legacyTls = appRule('code.legacy-tls', 'Weak TLS configuration', 'NETWORK',
  () => 'The app weakens TLS: an old protocol, weak cipher suites, a socket factory that skips certificate checks, or the deprecated Apache client. Traffic it protects is easier to read or change on the network.',
  [
    ['Weak TLS cipher suites enabled', /setEnabledCipherSuites\s*\([^;]*(?:NULL|EXPORT|RC4|_DES_|anon)/g, { d: 'setEnabledCipherSuites is called with NULL, EXPORT, RC4, DES or anonymous suites. These suites offer no encryption, very short keys or no server authentication. A network attacker can read or modify the TLS traffic or impersonate the server.', sev: 'low' }],
    ['TLS checks turned off by an insecure socket factory', /SSLCertificateSocketFactory\.getInsecure\s*\(/g, { d: 'SSLCertificateSocketFactory.getInsecure creates sockets that skip certificate and hostname checks. Any server presenting any certificate is accepted. A network attacker can run a man-in-the-middle attack and read or modify the traffic.', sev: 'high' }],
    ['Deprecated Apache HTTP client', /new\s+DefaultHttpClient\s*\(/g, { d: 'The app uses DefaultHttpClient, the deprecated Apache HTTP client that Android no longer maintains. It does not receive TLS fixes, and its defaults reflect older protocol and cipher choices. Connections made through it are more exposed to downgrade and interception.', sev: 'low' }],
    ['Legacy protocol', /SSLContext\.getInstance\s*\(\s*"(?:SSL|SSLv3|TLSv1|TLSv1\.1)"\s*\)|setEnabledProtocols\s*\([^)]*"SSLv3"/g, { d: 'The code requests SSL, SSLv3, TLSv1 or TLSv1.1 through SSLContext.getInstance, or enables SSLv3. These protocol versions have known attacks such as POODLE and BEAST. A network attacker can downgrade the connection and decrypt traffic.', sev: 'low' }]]);

const FP_PATHS = /\/res\/xml(?:-[\w-]+)?\/[^/]+\.xml$/;
const fileProvider = {
  id: 'code.fileprovider-root', title: 'FileProvider shares a broad directory', category: 'PLATFORM', needs: ['manifest'], code: true,
  async run({ input }) {
    const findings = [];
    for await (const { rel, text } of input.walk('resources', /\.xml$/)) {
      if (!FP_PATHS.test(rel)) continue;
      for (const m of text.matchAll(/<root-path\b[^>]*>|<(?:files|cache|external|external-files|external-cache)-path\b[^>]*\bpath\s*=\s*"(?:\.|\/)?"[^>]*>/g)) {
        if (findings.length >= MAX) return { findings };
        findings.push(finding('code.fileprovider-root', {
          key: `${scrub(rel)}|${m.index}`, title: `Broad FileProvider path: ${rel.split('/').pop()}`, severity: 'medium', detection: 'exact', conclusion: 'weakness',
          summary: 'A FileProvider paths entry exposes a whole directory tree, such as the root path or an entire files, cache or external directory. Any URI grant for this provider can then reach every file under it. An attacker who obtains a grant, for example through a vulnerable exported component, can read private files such as databases and tokens.',
          evidence: [sourceEv(rel, text, m.index, 'broad path')], repro: { steps: ['Open the evidence location and narrow the path to the folder that holds shared files.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

/** The statement around `index`: from the previous `;`, `{` or `}` to the next `;`. */
const statementAt = (t, index, end = 0) => {
  const from = Math.max(t.lastIndexOf(';', index), t.lastIndexOf('{', index), t.lastIndexOf('}', index)) + 1;
  const to = t.indexOf(';', index + end);
  return [from, to < 0 ? t.length : to];
};

/** Whether the File built at `m` is canonicalized: in the same statement, or through the variable it is assigned to, in the code that follows. */
function pathChecked(t, m) {
  const [from, to] = statementAt(t, m.index, m[0].length);
  if (/getCanonical(?:Path|File)|\.normalize\s*\(/.test(t.slice(m.index, to))) return true;
  const v = /(\w+)\s*=\s*$/.exec(t.slice(from, m.index));
  if (!v) return false;
  const after = t.slice(to, to + 1200), name = v[1];
  return new RegExp(`\\b${name}\\s*\\.\\s*(?:getCanonicalPath|getCanonicalFile)|\\b${name}\\b[^;]{0,80}\\.normalize\\s*\\(`).test(after);
}

/** The innermost class around `index` (its header and body), by brace matching, or null. */
function enclosingClass(t, index) {
  let best = null;
  for (const h of t.matchAll(/\b(?:class|interface|enum)\s+\w+[^{;]*\{/g)) {
    if (h.index > index) break;
    let depth = 0, end = -1;
    for (let i = h.index + h[0].length - 1; i < t.length; i++) { if (t[i] === '{') depth++; else if (t[i] === '}' && --depth === 0) { end = i; break; } }
    if (end >= index) best = { header: h[0], body: t.slice(h.index + h[0].length, end) };
  }
  return best;
}

// Copying the value of a visible sensitive field puts it on the clipboard. Nothing in the app limits that when no field or code turns it off.
const copyPaste = {
  id: 'code.copy-paste-allowed', title: 'Sensitive field can be copied', category: 'PRIVACY', needs: ['manifest'], code: true,
  async run({ input }) {
    const fields = [];
    for (const d of (await input.list('resources/res')) || []) {
      if (!/^layout/.test(d)) continue;
      for await (const { rel, text } of input.walk(`resources/res/${d}`, /\.xml$/)) {
        for (const m of text.matchAll(/<(?:EditText|TextView|com\.google\.android\.material\.textfield\.TextInputEditText)\b[^>]*>/g)) {
          const tag = m[0], type = /inputType\s*=\s*"([^"]*)"/.exec(tag)?.[1] || '';
          if (/[Pp]assword/.test(type) || /longClickable\s*=\s*"false"|textIsSelectable\s*=\s*"false"/.test(tag)) continue;
          if ([...tag.matchAll(/(?:id|hint|contentDescription)\s*=\s*"([^"]*)"/g)].some((x) => SENSITIVE_FIELD.test(x[1])) && fields.length < MAX) fields.push([rel, text, m.index]);
        }
      }
    }
    if (!fields.length) return { findings: [] };
    const skipped0 = input.stats.skipped, damaged0 = input.stats.damaged;
    for await (const { text } of appCode(input)) if (/setCustomSelectionActionModeCallback|setCustomInsertionActionModeCallback|setLongClickable\s*\(\s*false|setTextIsSelectable\s*\(\s*false|setHasTransientState/.test(text)) return { findings: [] };
    if (input.stats.truncated || input.stats.skipped > skipped0 || input.stats.damaged > damaged0) return { inconclusive: ABSENCE };
    const [rel, text, idx] = fields[0];
    return { findings: [finding('code.copy-paste-allowed', { key: scrub(rel), severity: 'low', detection: 'heuristic', conclusion: 'weakness',
      summary: `${fields.length} field${fields.length === 1 ? '' : 's'} that show a PIN, card number or similar value can be selected and copied, and the app never turns that off. The copied value goes to the clipboard, where other apps and clipboard history can read it. Nothing in the layouts or code limits copying.`,
      evidence: [sourceEv(rel, text, idx, 'sensitive field')], repro: { steps: ['Long-press the field on a device and see whether Copy is offered.'], command: [] } })] };
  }
};

const traversal = appRule('code.path-traversal', 'File path built from a Uri or request value without a check', 'PLATFORM',
  () => 'A path taken from a Uri (getLastPathSegment, getPath) is used to build a File with no canonical-path check. A value such as ../../x reaches files outside the intended folder, which in a content provider lets another app read or overwrite them.',
  [
    ['Display name from a provider used as a file name', /(?:_display_name|DISPLAY_NAME)[\s\S]{0,500}?new\s+File(?:OutputStream)?\s*\(/g, { d: 'A file name taken from a provider\'s _display_name column is used to build a File without being sanitised. The source can return a name such as ../../x, which resolves outside the intended folder. Another app that supplies the name can write or overwrite files in the app\'s directories.', sev: 'medium', detection: 'heuristic', skip: (m, t) => /getCanonical(?:Path|File)|\.normalize\s*\(|new\s+File\s*\([^;]*\)\.getName\s*\(\)/.test(t.slice(m.index, m.index + m[0].length + 500)) }],
    ['File built from a Uri path segment', /new\s+File\s*\([^;]*\.(?:getLastPathSegment|getPath|getEncodedPath)\s*\(/g, { d: 'A File path is built from a Uri\'s last path segment, path or encoded path with no canonical-path check. A value such as ../../x or its encoded form reaches files outside the intended folder. In a content provider, another app can use this to read or overwrite the app\'s private files.', sev: 'high', detection: 'heuristic', skip: (m, t) => pathChecked(t, m) }],
    ['Remote file name used as a path', /Content-Disposition[\s\S]{0,500}?new\s+File\s*\([^;]{0,160}\)/g, { sev: 'medium', detection: 'heuristic', skip: (m) => /getCanonicalPath|getCanonicalFile|startsWith\(|replaceAll\([^)]*\.\./.test(m[0]), d: 'A file name taken from a Content-Disposition header or an upload goes into new File(...). A name such as ../../x can then write outside the intended folder, which overwrites the app\'s own files or plants code. Keep only the last path segment and check the canonical path before writing.' }]]);

const deserialization = appRule('code.unsafe-deserialization', 'Deserialization that acts on its input', 'CODE',
  () => 'An object is rebuilt from data another app can supply, and the rebuild itself touches files, runs code or picks the class to create. Anyone who can send that object can trigger that behaviour. The result can be file changes or code execution with the app\'s permissions.',
  [
    ['readObject that deletes or opens files', /void\s+readObject\s*\([^)]*\)[^{]*\{[\s\S]{0,500}?(?:new\s+File\s*\(|\.delete\s*\(|deleteRecursive|Runtime\.getRuntime|\.exec\s*\()/g, { d: 'A readObject method creates files, deletes files or runs commands while an object is being deserialized. It runs before the caller can inspect the data. Anyone who can supply the serialized object can delete or write files or execute commands with the app\'s permissions.', sev: 'high', detection: 'heuristic' }],
    ['Jackson polymorphic typing turned on', /enableDefaultTyping\s*\(|activateDefaultTyping\s*\(/g, { d: 'Jackson default typing is enabled, so JSON can name the Java class to instantiate. Attacker-supplied JSON can select gadget classes that are on the classpath. This can lead to code execution or file access when the app parses untrusted JSON.', sev: 'high' }],
    ['Object read from a stream', /new\s+ObjectInputStream\s*\([^;]*;[\s\S]{0,300}?\.readObject\s*\(/g, { d: 'An ObjectInputStream reads an object with readObject. Java deserialization instantiates whatever class the stream names and runs its code. If the stream comes from another app, a file or the network, an attacker can choose the class and trigger gadget chains in the app or its libraries.', sev: 'low', detection: 'heuristic' }],
    ['Class chosen from parcel or stream data', /Class\.forName\s*\(\s*\w+\.(?:readString|readUTF|readLine)\s*\(\s*\)\s*\)/g, { d: 'A class name read from a Parcel or stream is passed to Class.forName. The sender decides which class is loaded and initialised. An attacker who controls that data can run the static initialisers of arbitrary classes or reach hidden functionality.', sev: 'high', detection: 'heuristic' }]
  ]);

const hostCheck = appRule('code.weak-host-check', 'Host validated with a string suffix or substring check', 'PLATFORM',
  () => 'A URL host is checked with endsWith, contains or startsWith against a fixed string. Hosts such as evil-example.com or example.com.evil.net pass such a check. An attacker can register one and have the app treat it as trusted.',
  [['Host checked by suffix or substring', /(?:getHost\s*\(\s*\)[^;]{0,200}?|\bhost\w*)\.(?:endsWith|contains|startsWith)\s*\(/g, { d: 'A URL host is validated with endsWith, contains or startsWith against a fixed string. Hosts such as evil-example.com or example.com.evil.net satisfy such a check. An attacker can register one and have the app treat it as trusted, for example to receive tokens or load content in a WebView.', sev: 'medium', detection: 'heuristic' }]]);

const untrustedUrl = appRule('code.link-parameter-to-url', 'Deep link or Intent value used as a URL', 'PLATFORM',
  () => 'A query parameter or Intent extra flows into a place that loads or contacts a URL. If the link comes from another app or a web page, an attacker chooses where the app connects, which can leak what it sends there or load their content.',
  [
    ['Text field loaded as a URL', /loadUrl\s*\(\s*[\w.]*\.getText\s*\(/g, { d: 'The text of a field is passed straight to WebView.loadUrl with no validation of scheme or host. A file:// or javascript: URL, or a page the attacker controls, is then loaded inside the app\'s WebView. That page gets the WebView\'s settings and any exposed Java objects.', sev: 'low', detection: 'probable' }],
    ['Link parameter reaches a URL sink', /(?:getQueryParameter|getStringExtra)\s*\([^)]*\)[\s\S]{0,500}?(?:loadUrl\s*\(|Uri\.parse\s*\(|new\s+URL\s*\(|\.baseUrl\s*\(|setData\s*\()/g, { d: 'A getQueryParameter or getStringExtra value is later used in loadUrl, Uri.parse, new URL, baseUrl or setData. An attacker who controls a deep link or Intent extra chooses the destination. The app can then load attacker pages, send its requests and tokens to an attacker host, or start an arbitrary Intent.', sev: 'medium', detection: 'heuristic' }]
  ]);

const resultUri = appRule('code.untrusted-result-uri', 'Uri returned by another app is opened without checks', 'PLATFORM',
  () => 'onActivityResult reads a Uri from a picker or another app and opens it. A malicious app can answer with a file:// or content:// Uri that points at this app\'s own private files.',
  [['Result Uri used as is', /onActivityResult\s*\([^)]*\)\s*\{[\s\S]{0,700}?(?:openInputStream|openFileDescriptor|openAssetFileDescriptor|\.getPath\s*\(|[\w.]+\([^;]*\.getData\s*\(\s*\)\s*\))/g, { d: 'onActivityResult takes a Uri from the result and opens it with openInputStream, openFileDescriptor or getPath without validating its scheme or authority. A malicious app can return a file:// or content:// Uri that points at the app\'s own private files or providers. The app then reads those files and may copy their contents somewhere the attacker can read.', sev: 'medium', detection: 'heuristic' }]]);

const secretInUrl = appRule('code.secret-in-url', 'Secret placed in a URL query string', 'NETWORK',
  () => 'A token or password is appended to a URL. URLs end up in server logs, browser history, referrer headers and Intent extras that other components can read.',
  [['Secret in a URL query string', /"[^"]*[?&](?:token|passw\w*|pwd|secret|api_?key|auth\w*|session\w*)=\s*"\s*\+/gi, { d: 'A token, password or API key is concatenated into a URL query string. URLs are written to server and proxy logs, browser history and referrer headers, and can appear in Intent extras. The secret is exposed to anyone who can read those records.', sev: 'low', detection: 'probable' }]]);

const nativePointer = appRule('code.serializable-native-pointer', 'Serializable object that owns a native pointer', 'CODE',
  () => 'The class is Serializable, keeps a native pointer in a field that is not transient, and declares a native free or release method. A crafted serialized object can set the pointer to any value. If the free method runs on it, the result can be a double free or memory corruption.',
  [['Native pointer in a Serializable', /\blong\s+\w*(?:ptr|handle|pointer)\w*\s*;/gi, { d: 'The class is Serializable, keeps a native pointer in a field that is not transient, and declares a native free or release method. A crafted serialized object can set the pointer to any value. If the free method then runs on it, native code frees or uses an attacker-chosen address, which can cause a double free or memory corruption.', sev: 'low', detection: 'heuristic', skip: (m, t) => {
    if (/\btransient\b/.test(t.slice(t.lastIndexOf('\n', m.index) + 1, m.index))) return true;
    const c = enclosingClass(t, m.index);                       // all three conditions must hold in the same class
    return !c || !/\bSerializable\b/.test(c.header) || !/\bnative\s+\w+\s+\w*(?:free|delete|release|destroy|close|dispose|cleanup)\w*\s*\(/i.test(c.body);
  } }]]);

const encoded = appRule('code.encoded-constant', 'Constant decoded from Base64 at runtime', 'STORAGE',
  () => 'A fixed Base64 string is decoded in code, often to hide a PIN, key or password from a quick look at the source. Base64 is a reversible encoding. Anyone who decompiles the APK can decode the value and use it.',
  [['Base64 constant decoded in code', /Base64\.decode\s*\(\s*"([A-Za-z0-9+/]{4,}={0,2})"/g, { d: 'A fixed Base64 string is decoded in code at runtime. This is often used to hide a PIN, key, password or URL from a quick look at the source. Base64 is a reversible encoding, so anyone who decompiles the APK can decode the value and use whatever secret it holds.', sev: 'low', detection: 'heuristic' }]]);

const xxe = appRule('code.xxe', 'XML parsed with external entities allowed', 'CODE',
  () => 'An XML parser is created without turning off DTDs or external entities. If it parses data an attacker can influence, they can read local files or make the app send requests (XXE).',
  [
    ['XML parser without entity protection', /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(/g, { d: 'A DocumentBuilderFactory, SAXParserFactory or XMLInputFactory is created, and no setting that disables DTDs or external entities appears in the file. Such a parser can resolve external entities while it parses a document. If an attacker influences the XML, they can read local files, reach internal hosts or cause denial of service (XXE).', sev: 'medium', detection: 'heuristic', skip: (m, t) => /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES|setExpandEntityReferences\s*\(\s*false/.test(t) }],
    ['XML built from a string with input', /"<[\w:-]+[^"]*>"\s*\+\s*[\w.()\[\]]+\s*\+\s*"<\/[\w:-]+>"/g, { sev: 'medium', detection: 'heuristic', d: 'XML text is assembled by concatenating a value between tags. A value containing angle brackets can close the element and add its own, which is XML injection. The document then carries structure the app did not intend.' }],
    ['XMLDecoder on input', /new\s+XMLDecoder\s*\(/g, { d: 'XMLDecoder is used to read XML. It builds Java objects and calls the methods that the document names. XML supplied by an attacker can therefore run arbitrary code in the app.', sev: 'high', detection: 'heuristic' }]
  ]);

const fragments = appRule('code.fragment-injection', 'PreferenceActivity open to fragment injection', 'PLATFORM',
  () => 'A PreferenceActivity takes the fragment to show from its Intent, and isValidFragment returns true for every name. If the activity is exported, another app can open any fragment of this app inside it. That reaches screens and actions that were not meant to be exposed (fragment injection).',
  [['isValidFragment accepts any fragment', /boolean\s+isValidFragment\s*\([^)]*\)\s*\{\s*return\s+true\s*;/g, { d: 'A PreferenceActivity overrides isValidFragment to return true, so it accepts any fragment name passed in its Intent. If the activity is exported, another app can make it instantiate any fragment class of this app. That reaches screens and actions that were never meant to be exposed (fragment injection).', sev: 'medium', gate: /PreferenceActivity/ }]]);

const biometric = appRule('code.biometric-keystore', 'Biometric or Keystore protection that can be bypassed', 'AUTH',
  () => 'The biometric prompt or the Keystore key is set up so that a successful check is not tied to a key operation, or the key survives changes to the device\'s biometrics. On a rooted or instrumented device the check can then be skipped.',
  [
    ['Biometric prompt without a CryptoObject', /\.authenticate\s*\(/g, { skip: (m, t) => /CryptoObject/.test(t.slice(m.index, m.index + 500)), d: 'A biometric authenticate call is made without a CryptoObject. The result is then only a boolean callback in app code, with no cryptographic operation bound to it. On a rooted or hooked device an attacker can call the success path directly and skip the biometric check.', sev: 'medium', detection: 'heuristic', gate: /BiometricPrompt|FingerprintManager/ }],
    ['Device credential accepted as a biometric', /setDeviceCredentialAllowed\s*\(\s*true\s*\)|DEVICE_CREDENTIAL/g, { d: 'The biometric prompt also accepts the device PIN, pattern or password. Anyone who knows or has watched the lock screen credential can pass the check. The prompt then no longer proves that the legitimate user\'s biometric was presented.', sev: 'low', detection: 'heuristic', gate: /BiometricPrompt/ }],
    ['Key survives new biometric enrollment', /setInvalidatedByBiometricEnrollment\s*\(\s*false\s*\)/g, { d: 'A Keystore key is created with setInvalidatedByBiometricEnrollment(false), so it stays usable after a new fingerprint or face is enrolled. A person who adds their own biometric on an unlocked device can then use the key. The key no longer proves that only the original enrolled user can unlock it.', sev: 'low' }],
    ['Key usable without user authentication', /setUserAuthenticationRequired\s*\(\s*false\s*\)/g, { d: 'A Keystore key is created with setUserAuthenticationRequired(false). Any code running as the app can use the key without the user unlocking the device or authenticating. Malware inside the app\'s process or an attacker on a rooted device can use the key freely to decrypt data or sign requests.', sev: 'low' }],
    ['Key stays unlocked for a time window after authentication', /setUserAuthenticationValidityDurationSeconds\s*\(\s*(?!0\s*\))[-\d]+/g, { sev: 'low', d: 'A Keystore key is usable for a fixed number of seconds after one authentication, so any code in the app can use it during that window without another prompt. A negative value allows only the first use, but a positive one opens the key to every operation.' }],
    ['Key usable on a locked device', /setUnlockedDeviceRequired\s*\(\s*false\s*\)/g, { sev: 'low', d: 'A Keystore key is created with setUnlockedDeviceRequired(false), so it can be used while the screen is locked. Code that runs in the background on a stolen or locked phone can still decrypt with it.' }],
    ['Keystore key without StrongBox', /KeyGenParameterSpec\.Builder/g, { sev: 'low', detection: 'heuristic', gate: /^(?![\s\S]*setIsStrongBoxBacked)/, d: 'The app creates Keystore keys but never asks for StrongBox hardware. Keys then live in the main processor\'s trusted environment, which resists less physical and side-channel attack than a dedicated secure element.' }],
    ['Deprecated fingerprint API', /FingerprintManager(?:Compat)?\b/g, { sev: 'low', d: 'The app uses FingerprintManager, which was deprecated in Android 9 and covers fingerprints only. It lacks the strong-biometric class checks of BiometricPrompt, so the app cannot require a Class 3 biometric.' }],
  ]);

const notification = appRule('code.sensitive-notification', 'Sensitive value shown in a notification', 'PRIVACY',
  () => 'A code, token or password is put into a notification. Notifications show on the lock screen and apps with notification access can read them. Bystanders and other apps can therefore see the secret.',
  [['Secret in notification text', /\.set(?:ContentText|ContentTitle|Ticker|SubText)\s*\([^;]{0,200}?\b(?:[a-z]\w*(?:Otp|OTP|Token|Password|Passcode|Pin|PIN|Secret)\b|(?:otp|OTP|token|password|passcode|pin|PIN|secret|verificationCode)(?:[A-Z]\w*)?\b)/g, { d: 'A value named like an OTP, token, password, PIN or secret is placed in notification text, title, ticker or sub text. Notification content appears on the lock screen by default and is readable by apps with notification listener access. The secret is exposed to bystanders and to other apps.', sev: 'low', detection: 'heuristic' }]]);

const identifiers = appRule('code.device-identifiers', 'Hardware or device identifiers collected', 'PRIVACY',
  () => 'The app reads an identifier that is tied to the device or SIM. These identify a person across apps and resets, and Google Play restricts their use.',
  [['Wi-Fi network details read', /\.(?:getConfiguredNetworks|getDhcpInfo|getBSSID)\s*\(/g, { sev: 'low', d: 'The app reads Wi-Fi details such as saved networks, the DHCP lease or the access point BSSID. These values locate a user and identify their networks. Android restricts most of them behind location permission on current versions, and older versions hand them to any app.' }],
   ['Device identifier read', /\.(?:getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number|getMacAddress)\s*\(|Settings\.Secure\.ANDROID_ID|"android_id"|Build\.SERIAL\b|Build\.getSerial\s*\(/g, { d: 'The app reads a hardware or device identifier such as the IMEI, MEID, subscriber ID, SIM serial number, phone number, MAC address, ANDROID_ID or Build serial. These values persist across reinstalls, sometimes across factory resets, and are shared between apps. They allow a person to be tracked across apps and services, and Google Play policy restricts their use.', sev: 'low' }]]);

const bluetooth = appRule('code.insecure-bluetooth', 'Unauthenticated Bluetooth channel', 'NETWORK',
  () => 'The app opens a Bluetooth RFCOMM channel that skips authentication, or stays discoverable for a long time. A nearby device can listen to the channel or connect to it.',
  [
    ['Insecure RFCOMM socket', /createInsecureRfcommSocket\w*\s*\(|listenUsingInsecureRfcomm\w*\s*\(/g, { d: 'The app creates an RFCOMM socket with createInsecureRfcommSocket or listenUsingInsecureRfcomm. These sockets skip link-layer authentication, and encryption on older Bluetooth versions, so pairing is not required. A nearby device can connect to the socket or eavesdrop on the data exchanged.', sev: 'medium' }],
    ['Discoverable without a time limit', /EXTRA_DISCOVERABLE_DURATION\s*,\s*(?:0|[3-9]\d{2,}|\d{4,})\s*\)/g, { d: 'The app asks the system to make the device discoverable for 300 seconds or longer, or with no limit when the duration is 0. Nearby devices can find it and try to connect for that whole period. This widens exposure to pairing and connection attacks and to tracking.', sev: 'low' }]
  ]);

const server = appRule('code.local-server', 'App runs a network server', 'NETWORK',
  () => 'The app listens for connections. If it binds to all interfaces, other devices on the same network can reach it, and even on localhost other apps on the phone can. Whatever it serves or accepts is open to those callers unless the app authenticates them.',
  [['Server socket opened', /new\s+(?:ServerSocket|LocalServerSocket)\s*\(|extends\s+NanoHTTPD\b|\bNanoHTTPD\s*\(|embeddedServer\s*\(/g, { d: 'The app opens a ServerSocket, LocalServerSocket or an embedded HTTP server such as NanoHTTPD or Ktor. If it binds to all interfaces, other devices on the network can connect, and even on localhost any app on the phone can. Whatever it serves or accepts is open to those callers unless the app authenticates them.', sev: 'low', detection: 'heuristic' }]]);

const leftovers = appRule('code.debug-leftovers', 'Debug or internal leftovers', 'RESILIENCE',
  () => 'Something meant for development is still in the build: an internal address, a staging host, StrictMode logging or a debug flag. It can point to test backends or expose behaviour meant only for developers.',
  [
    ['Private IP address', /"(?:https?:\/\/)?(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?::\d+)?[/"]/g, { d: 'A string constant holds a private network address such as 10.x, 192.168.x or 172.16 to 172.31.x. It points to an internal or test server left in the build. It reveals the internal network layout and may mean the app talks to a backend that lacks production protections.', sev: 'low' }],
    ['Staging or development host', /"https?:\/\/[^"\s]*(?:staging|\bdev\.|-dev\.|\btest\.|\.local\b|localhost|ngrok)[^"\s]*"/gi, { d: 'A URL points to a staging, dev, test, ngrok or localhost host. The release build can reach a non-production backend, and the hostname discloses the infrastructure to anyone reading the APK. Such environments often have weaker access control than production.', sev: 'low', detection: 'heuristic' }],
    ['StrictMode left on', /StrictMode\.set(?:Thread|Vm)Policy\s*\([\s\S]{0,300}?penalty(?:Log|Death|Dialog)/g, { d: 'StrictMode policies with a log, dialog or death penalty are configured in code that ships in the build. StrictMode is a development aid, and its log output reveals internal behaviour such as disk and network use. With penaltyDeath it can also crash the app on a violation.', sev: 'low', detection: 'heuristic' }],
    ['Debug build flag set', /boolean\s+DEBUG\s*=\s*(?:true|Boolean\.parseBoolean\("true"\))/g, { d: 'A DEBUG constant is set to true in the app\'s code. Code guarded by it, such as verbose logging, test endpoints or relaxed checks, is active in the build. An attacker gets information or functionality that was intended only for developers.', sev: 'low' }],
    ['Debug or admin endpoint', /\"[^\"\s]*(?:\/actuator(?:\/\w+)?|\/swagger(?:-ui)?|\/graphiql|\/phpinfo|\/h2-console|\/\.env|\/debug\/\w+)[^\"\s]*\"/g, { sev: 'low', d: 'A string points to a management or debug URL such as /actuator, /swagger, /graphiql or /.env. These endpoints are meant for developers and often expose internals when left open. Check that the server blocks them in production.' }]
  ]);

// ponytail: tapjacking and pinning are absence rules with one extra place to look (layouts, the network security config).
const tapjacking = absenceRule('code.no-tapjacking-protection', 'No protection against overlays (tapjacking)', 'PLATFORM', /filterTouchesWhenObscured|setHideOverlayWindows|HIDE_OVERLAY_WINDOWS|FLAG_WINDOW_IS(?:_PARTIALLY)?_OBSCURED/, 'low',
  'No view or window filters touches while another app draws over it, and the app does not hide overlays. A malicious overlay can trick the user into tapping buttons on sensitive screens (tapjacking). Android 12 and later block most untrusted overlays.',
  'Check the sensitive screens for filterTouchesWhenObscured or setHideOverlayWindows(true).',
  async (input, model) => {
    if (model.manifest.uses.some((u) => /HIDE_OVERLAY_WINDOWS/.test(u.name))) return true;
    for (const d of (await input.list('resources/res')) || []) if (/^layout/.test(d)) for await (const { text } of input.walk(`resources/res/${d}`, /\.xml$/)) if (/filterTouchesWhenObscured="true"/.test(text)) return true;
    return false;
  });
const noPinning = absenceRule('network.no-pinning', 'No certificate pinning found', 'NETWORK', /CertificatePinner|TrustKit|X509TrustManagerExtensions|checkServerTrusted[\s\S]{0,400}?getPublicKey|setCertificatePinner/, 'low',
  'Neither the network security config nor the app\'s own code pins certificates or public keys. Anyone who gets a CA trusted on the device, such as a corporate profile or a user-installed CA on an older target SDK, can intercept the app\'s TLS traffic. Apps that handle money or accounts expose credentials and transactions this way.',
  'Route the phone through an intercepting proxy with its CA installed and see whether the app\'s HTTPS traffic decrypts.',
  async (input, model) => (model.nscError ? `the network security config could not be read: ${model.nscError}` : !!(model.nsc?.pins?.length)));

const oauth = appRule('code.oauth-pkce', 'OAuth login without PKCE or in a WebView', 'AUTH',
  () => 'The app runs an OAuth authorization-code login without a PKCE code challenge, or loads the login page in its own WebView. Without PKCE another app that registers the same redirect scheme can take the code; inside a WebView the app can read the password the user types.',
  [
    ['Authorization code flow without PKCE', /response_type=code\b|"authorization_code"/g, { d: 'The app starts an OAuth authorization-code flow with no code_challenge or code_verifier and no AppAuth library in the same file. Another app that registers the same redirect scheme can intercept the authorization code. It can exchange the code for tokens and take over the account session.', sev: 'medium', detection: 'heuristic', skip: (m, t) => /code_challenge|code_verifier|AuthorizationService|net\.openid\.appauth/.test(t) }],
    ['OAuth login page loaded in a WebView', /\.loadUrl\s*\([^;]*(?:oauth2?\/(?:v\d\/)?auth(?:orize)?|accounts\.google\.com\/o\/oauth2|\/authorize\?)/g, { d: 'The OAuth authorization page is loaded in the app\'s own WebView. Because the app controls that WebView, it or any injected script can read the username and password the user types. The user also has no browser address bar to confirm that the page is genuine.', sev: 'low', detection: 'heuristic' }]
  ]);

const antiDebug = absenceRule('code.no-anti-debug', 'No debugger, hooking or emulator detection found', 'RESILIENCE', /isDebuggerConnected|TracerPid|PTRACE_TRACEME|\b27042\b|frida|xposed|substrate|goldfish|ranchu|qemu|sdk_gphone|google_sdk|genymotion|vbox86|Build\.(?:FINGERPRINT|MODEL|PRODUCT|MANUFACTURER|HARDWARE)[\s\S]{0,80}?(?:generic|emulator|sdk)/i, 'low',
  'The app\'s own code never checks for an attached debugger, Frida, Xposed or an emulator. An attacker or tester can therefore instrument the app at runtime without it reacting. Such checks only slow an attacker down, and the app may have them in native code, so this matters mainly for apps that rely on client-side protection.',
  'Search the app\'s classes and native strings for isDebuggerConnected, TracerPid or frida.');

// Analytics and ad SDKs by package. They live in library code, so this looks for their directories, not their calls.
const TRACKERS = [['AppsFlyer', 'com/appsflyer'], ['Adjust', 'com/adjust/sdk'], ['Facebook App Events', 'com/facebook/appevents'], ['Mixpanel', 'com/mixpanel'],
  ['Firebase Analytics', 'com/google/firebase/analytics'], ['Google Mobile Ads', 'com/google/android/gms/ads'], ['Branch', 'io/branch'], ['Amplitude', 'com/amplitude'],
  ['Segment', 'com/segment/analytics'], ['CleverTap', 'com/clevertap'], ['OneSignal', 'com/onesignal'], ['Braze', 'com/braze'], ['AppLovin', 'com/applovin'], ['Unity Ads', 'com/unity3d/ads']];
// Payment, identity, messaging and monitoring SDKs. Not trackers, but each one handles sensitive data and brings its own update and key duties.
const SDKS = [['Stripe', 'com/stripe', 'payments'], ['PayPal', 'com/paypal', 'payments'], ['Braintree', 'com/braintreepayments', 'payments'], ['Razorpay', 'com/razorpay', 'payments'], ['Adyen', 'com/adyen', 'payments'],
  ['Square', 'com/squareup/sdk', 'payments'], ['Google Pay', 'com/google/android/gms/wallet', 'payments'], ['Auth0', 'com/auth0', 'sign-in'], ['Okta', 'com/okta', 'sign-in'], ['AppAuth', 'net/openid/appauth', 'sign-in'],
  ['Firebase Auth', 'com/google/firebase/auth', 'sign-in'], ['Facebook Login', 'com/facebook/login', 'sign-in'], ['Google Sign-In', 'com/google/android/gms/auth', 'sign-in'], ['Amazon Cognito', 'com/amazonaws/mobileconnectors/cognitoauth', 'sign-in'],
  ['Twilio', 'com/twilio', 'messaging'], ['Sendbird', 'com/sendbird', 'messaging'], ['Stream Chat', 'io/getstream', 'messaging'], ['Intercom', 'io/intercom', 'messaging'], ['Zendesk', 'zendesk', 'messaging'],
  ['Sentry', 'io/sentry', 'monitoring'], ['Bugsnag', 'com/bugsnag', 'monitoring'], ['Datadog', 'com/datadog', 'monitoring'], ['New Relic', 'com/newrelic', 'monitoring'], ['Firebase Crashlytics', 'com/google/firebase/crashlytics', 'monitoring']];
const sdkInventory = {
  id: 'privacy.sdk-inventory', title: 'Third-party SDKs bundled', category: 'PRIVACY', needs: ['sources'], code: true,
  async run({ input }) {
    const found = [];
    for (const [name, dir, kind] of SDKS) if (await input.exists(`sources/${dir}`)) found.push([name, kind]);
    const strings = await input.read('resources/res/values/strings.xml', 2 * 1024 ** 2);
    const fb = strings && /<string name="facebook_client_token">([^<]+)</.exec(strings);
    const findings = [];
    if (found.length) {
      const kinds = [...new Set(found.map(([, k]) => k))];
      findings.push(finding('privacy.sdk-inventory', { key: found.map(([n]) => n).join(','), title: `SDKs: ${found.map(([n]) => n).join(', ')}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `The APK bundles SDKs for ${kinds.join(', ')}: ${found.map(([n]) => n).join(', ')}. Each one processes sensitive data and ships code that the app's team does not write. A flaw in any of them becomes a flaw in this app until the dependency is updated.`,
        evidence: [], repro: { steps: ['Open the package folders in the Decompiler.'], command: [] } }));
    }
    if (fb) findings.push(finding('privacy.sdk-inventory', { key: 'facebook-client-token', title: 'Facebook client token in resources', severity: 'low', detection: 'exact', conclusion: 'weakness',
      summary: 'The resources hold a Facebook client token. It identifies the app to Facebook and can be used with the app ID to call some Graph API endpoints as the app. Anyone who unpacks the APK can read it, so it must not grant more than public access.',
      evidence: [sourceEv('resources/res/values/strings.xml', strings, fb.index, 'facebook_client_token')], repro: { steps: ['Open res/values/strings.xml in the Decompiler.'], command: [] } }));
    return { findings };
  }
};

const trackers = {
  id: 'privacy.trackers', title: 'Analytics or advertising SDK bundled', category: 'PRIVACY', needs: ['sources'], code: true,
  async run({ input }) {
    const found = [];
    for (const [name, dir] of TRACKERS) if (await input.exists(`sources/${dir}`)) found.push(name);
    if (!found.length) return { findings: [] };
    return { findings: [finding('privacy.trackers', { key: found.join(','), title: `Trackers: ${found.join(', ')}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
      summary: `The APK bundles ${found.join(', ')}. These SDKs send usage and device data to third parties. Users\' behaviour and identifiers therefore leave the app\'s own backend and fall under privacy disclosure rules.`,
      evidence: [], repro: { steps: ['Open the package folders in the Decompiler.'], command: [] } })] };
  }
};

const clipRead = appRule('code.clipboard-read', 'App reads the clipboard', 'PRIVACY',
  () => 'The app reads the clipboard or listens for clipboard changes. Whatever the user copied from a password manager or a banking app lands in this app. A malicious or careless app can collect it.',
  [
    ['Clipboard read', /\.getPrimaryClip\s*\(\)/g, { sev: 'low', detection: 'heuristic', d: 'The app reads the current clipboard with getPrimaryClip. Whatever the user copied elsewhere, such as a password or a one-time code, becomes visible to this app. Android 10 and later limit this to the app in the foreground, which many clipboard-stealing apps still satisfy.' }],
    ['Clipboard change listener', /addPrimaryClipChangedListener\s*\(/g, { sev: 'low', detection: 'heuristic', d: 'The app registers a listener that fires whenever the clipboard changes. It sees each value the user copies, which includes passwords and codes from other apps. Clipboard monitors are a common trait of data-stealing malware.' }]
  ]);

const deprecatedSecurity = appRule('code.deprecated-security-api', 'Deprecated security library in use', 'CRYPTO',
  () => 'The app relies on a security API that Google deprecated. It receives no fixes, and its key handling can differ across devices.',
  [
    ['EncryptedSharedPreferences from security-crypto', /EncryptedSharedPreferences|EncryptedFile\b|MasterKeys?\b/g, { sev: 'low', d: 'The app stores data with the androidx.security:security-crypto library, which Google deprecated and no longer updates. It is known to fail on some devices when its Keystore keys break. Failures there can silently lose data or push developers into storing it unencrypted.' }],
    ['AES128_GCM key scheme', /KeyScheme\.AES128_GCM|AES128_GCM_HKDF|AES128_SIV/g, { sev: 'low', d: 'The app encrypts with a 128-bit key scheme from the deprecated security-crypto library. 128-bit AES-GCM is still considered strong, but this key scheme is derived through a master key that is no longer maintained. The library will not receive fixes if a flaw is found.' }],
    ['SafetyNet Attestation', /\bSafetyNet(?:Api|Client)\b|com\.google\.android\.gms\.safetynet/g, { sev: 'low', d: 'The app calls the SafetyNet Attestation API, which Google replaced with Play Integrity. Device and app checks built on the old verdicts stop working as it is phased out. Move to the Play Integrity API and check the verdict on the server.' }]
  ]);

const passkey = appRule('code.passkey-weak-config', 'Weak passkey or WebAuthn setup', 'AUTH',
  () => 'The passkey or WebAuthn request is built in a way that weakens its guarantees. An attacker who can reach the flow may replay it or skip the user check.',
  [
    ['Passkey does not require user verification', /userVerification\\*["']?\s*[:=]\s*\\*["'](?:discouraged|preferred)|UserVerificationRequirement\.(?:DISCOURAGED|PREFERRED)/gi, { sev: 'low', d: 'The passkey request sets userVerification to preferred or discouraged. The authenticator can then approve the sign-in without a PIN, fingerprint or face check. A thief who holds the unlocked phone can authenticate.' }],
    ['Hardcoded passkey challenge', /challenge\\*["']\s*[:=]\s*\\*["'][A-Za-z0-9_-]{8,}\\*["']/g, { sev: 'high', d: 'The WebAuthn challenge is a fixed string in the app. The server must send a fresh random challenge for every sign-in, because a fixed one lets a recorded response be replayed. Anyone who captures one valid response can log in again.' }]
  ]);

const tempFiles = appRule('code.temp-file-write', 'Data written to temporary files', 'STORAGE',
  () => 'The app writes data to temporary or cache files. Those files are often world-listable by file managers on old devices and are rarely cleaned up. Sensitive content in them outlives the screen that created it.',
  [
    ['Temporary file created', /File\.createTempFile\s*\(/g, { sev: 'low', detection: 'heuristic', d: 'The app creates a temporary file with File.createTempFile. If the file holds a document, an image or a token, it stays on disk until something deletes it. Other tools with access to the app data, such as backups and rooted shells, can read the leftover content.' }],
    ['Data written into the cache directory', /getCacheDir\s*\(\)[^;]*;[\s\S]{0,300}?new\s+FileOutputStream/g, { sev: 'low', detection: 'heuristic', d: 'The app writes a file into getCacheDir. The system can keep cache content across app launches and does not encrypt it. Anything sensitive placed there remains readable to anyone who can read the app data.' }]
  ]);

const timingEquals = appRule('code.timing-unsafe-compare', 'Secret compared with String.equals', 'CRYPTO',
  () => 'A password, PIN or token is compared with String.equals. That comparison stops at the first different character, so its running time leaks how much of a guess was right. An attacker with precise timing can recover the value one character at a time.',
  [['Secret compared with equals', /\b\w*(?:[Pp]ass(?:word|wd)?|[Pp][Ii][Nn]|[Tt]oken|[Ss]ecret|[Hh]mac|[Ss]ignature)\w*\s*\.equals\s*\(\s*(?!")|\.equals\s*\(\s*\w*(?:[Pp]ass(?:word|wd)?|[Pp][Ii][Nn]|[Tt]oken|[Hh]mac)\w*\s*\)/g, { sev: 'low', detection: 'heuristic', skip: (m, t) => /MessageDigest\.isEqual/.test(t), d: 'A password, PIN, token or MAC is compared with String.equals. That method returns at the first mismatch, so the time it takes reveals how many leading characters matched. An attacker who can measure responses precisely can guess the value piece by piece.' }]]);

const stackTrace = appRule('code.stack-trace-leak', 'Stack traces printed', 'PRIVACY',
  () => 'The app prints exception stack traces to the log or to the screen. A stack trace names classes, files and sometimes data from the failing request. That information helps an attacker map the app.',
  [
    ['printStackTrace call', /\.printStackTrace\s*\(\s*\)/g, { sev: 'low', detection: 'heuristic', d: 'The app calls printStackTrace, which writes the exception and its call chain to the system log. Any app holding the log permission on older Android versions, and anyone with adb on a debuggable build, can read it. The trace exposes class names, file names and often values from the failing request.' }],
    ['Stack trace shown to the user', /(?:setText|Toast\.makeText)\s*\([^;]*(?:getStackTrace|Log\.getStackTraceString|printStackTrace)/g, { sev: 'low', detection: 'heuristic', d: 'The app puts a stack trace into a text field or toast. Anyone looking at the screen, including a screenshot or a recording, sees internal class names and error details. Those details help someone who is probing the app for flaws.' }]
  ]);

const malwareSigns = appRule('code.malware-indicators', 'Indicators found in malware', 'CODE',
  () => 'The code contains an address or call that legitimate apps rarely use. It matches the pattern of command-and-control links or device takeover.',
  [
    ['Tor onion address', /["'][^"'\s]*\.onion(?::\d+)?[^"'\s]*["']/g, { sev: 'low', detection: 'heuristic', d: 'The code holds a Tor .onion address. Legitimate apps almost never contact hidden services directly, while malware uses them for command-and-control servers it can keep hidden. The address may also belong to a privacy-focused feature, so confirm what the app does with it.' }],
    ['Link on a free-registration domain', /["']https?:\/\/[^"'\s\/]+\.(?:tk|ml|ga|cf|gq)(?:[\/:"'])/g, { sev: 'low', detection: 'heuristic', d: 'The code contains a URL on a free-registration top-level domain (.tk, .ml, .ga, .cf or .gq). Attackers favor these domains for short-lived command-and-control and phishing servers. Their presence does not prove abuse, but a production app rarely depends on them.' }],
    ['Device wipe or lock call', /\.(?:wipeData|lockNow|resetPassword)\s*\(/g, { sev: 'low', detection: 'heuristic', d: 'The app calls a DevicePolicyManager method that locks the phone, resets its password or wipes it. Ransomware and device-locking malware use exactly these calls. A legitimate management app uses them too, so the context decides.' }]
  ]);

const composeState = appRule('code.compose-saved-secret', 'Secret kept in saved UI state', 'STORAGE',
  () => 'A password or token is kept in rememberSaveable state. That state is written to the saved-instance bundle, which the system persists while the app is in the background. The secret then sits in a place the app did not mean to store it.',
  [['Secret in rememberSaveable', /rememberSaveable\s*(?:\([^)]*\))?\s*\{[^}]*(?:password|passwd|token|secret|pin)\b/gi, { sev: 'low', detection: 'heuristic', d: 'A password, PIN or token is held in rememberSaveable, which stores its value in the saved-instance-state bundle. The system can write that bundle to disk and restore it after the process dies. The secret then outlives the screen and can be read from backups and crash reports.' }]]);


// Obfuscators (R8, ProGuard, DexGuard) rename classes to a, b, aa. An app whose own classes keep real names ships no obfuscation.
const noObfuscation = {
  id: 'code.no-obfuscation', title: 'No code obfuscation found', category: 'RESILIENCE', needs: ['sources', 'manifest'], code: true,
  async run({ input, model }) {
    let n = 0, short = 0;
    const skipped0 = input.stats.skipped, damaged0 = input.stats.damaged;
    for await (const { rel } of appCode(input)) { n++; if (/\/[A-Za-z]{1,2}\.java$/.test(rel)) short++; }
    if (input.stats.truncated || input.stats.skipped > skipped0 || input.stats.damaged > damaged0) return { inconclusive: ABSENCE };
    if (n < 25) return n ? { findings: [] } : { inconclusive: NO_CLASSES };
    if (short / n >= 0.03) return { findings: [] };
    return { findings: [finding('code.no-obfuscation', { key: model.manifest.package, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
      summary: `Only ${short} of ${n} classes outside the library packages have short, renamed names such as a or ab. The app was built without R8 or ProGuard renaming, so class, method and field names still describe what the code does. Reverse engineers read the logic, and find security checks, much faster.`,
      evidence: [], repro: { steps: ['Decompile the APK and look at the class names in the app\'s own package.'], command: [] } })] };
  }
};

const noRootCheck = absenceRule('code.no-root-detection', 'No root detection found', 'RESILIENCE', /RootBeer|isRooted|checkRoot|detectRoot|RootTools|\/system\/x?bin\/su\b|Superuser\.apk|com\.topjohnwu\.magisk|test-keys/i, 'low',
  'The app\'s own code never checks whether the phone is rooted. On a rooted device other apps and the user can read its private data, hook its functions and bypass its checks. That matters for apps that hold money, health or corporate data.',
  'Search the app\'s classes for su paths, RootBeer or similar checks. Run the app on a rooted phone to see if it reacts.');

// Obfuscated apps rename classes to a, b, aa. A readable name left on a security class tells a reverse engineer where to look.
const partialObfuscation = {
  id: 'code.partial-obfuscation', title: 'Security classes keep readable names', category: 'RESILIENCE', needs: ['sources', 'manifest'], code: true,
  async run({ input, model }) {
    let n = 0, short = 0;
    const named = [];
    const skipped0 = input.stats.skipped, damaged0 = input.stats.damaged;
    for await (const { rel } of appCode(input)) {
      n++;
      const f = rel.split('/').pop().replace(/\.java$/, '');
      if (/^[A-Za-z]{1,2}$/.test(f)) short++;
      else if (/^(?:\w*(?:Login|Auth|Crypto|Cipher|Encrypt|Decrypt|Password|Passcode|Biometric|Payment|License|Keystore|TokenManager|SecureStorage)\w*)$/.test(f)) named.push(rel);
    }
    if (input.stats.truncated || input.stats.skipped > skipped0 || input.stats.damaged > damaged0) return { inconclusive: ABSENCE };
    if (n < 25 || short / n < 0.2 || !named.length) return { findings: [] };
    return { findings: [finding('code.partial-obfuscation', { key: model.manifest.package, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
      summary: `Most classes were renamed by an obfuscator, but ${named.length} security-related classes kept their names, such as ${named.slice(0, 3).map((x) => x.split('/').pop()).join(', ')}. A reverse engineer reads those names first and goes straight to the login, crypto and payment code. The keep rules in the shrinker configuration are probably too broad.`,
      evidence: [{ kind: 'source', ref: { path: named[0], startLine: null, endLine: null }, excerpt: named.slice(0, 10).join('\n'), note: 'classes with readable security names' }], repro: { steps: ['Decompile the APK and look for the named classes.'], command: [] } })] };
  }
};

const keyReuse = appRule('code.key-reuse', 'One key used for more than one purpose', 'CRYPTO',
  () => 'The same key material feeds both an encryption cipher and a MAC. Reusing a key across purposes can let a flaw in one use break the other. Separate keys keep a compromise contained.',
  [['One key for encryption and a MAC', /new\s+SecretKeySpec\(\s*([\w.]+(?:\(\))?)\s*,\s*"(?:AES|DES|DESede)[^"]*"\s*\)[\s\S]{0,3000}?new\s+SecretKeySpec\(\s*\1\s*,\s*"Hmac\w+"|new\s+SecretKeySpec\(\s*([\w.]+(?:\(\))?)\s*,\s*"Hmac\w+"\s*\)[\s\S]{0,3000}?new\s+SecretKeySpec\(\s*\2\s*,\s*"(?:AES|DES|DESede)[^"]*"/g, { sev: 'low', detection: 'heuristic', gate: /^(?=[\s\S]*SecretKeySpec)(?=[\s\S]*Hmac)/, d: 'The same key variable builds an encryption key and an HMAC key. Using one key for two jobs breaks the separation that security proofs assume, so a weakness in either use can expose the other. An attacker who learns the key from one place can forge MACs and decrypt data.' }]]);


const clipboard = appRule('code.clipboard-write', 'Data copied to the clipboard', 'PRIVACY',
  () => 'Anything the app puts on the clipboard can be read by other apps on older Android versions and shown in keyboard suggestions and clipboard history. A password, token or account number copied this way can leak to other apps or onto the screen.',
  [['Clipboard write', /\.setPrimaryClip\s*\(/g, { d: 'The app writes data to the clipboard with setPrimaryClip. On Android 9 and earlier any app can read the clipboard in the background, and later versions show clip content in keyboard suggestions and clipboard history. Anything copied this way, such as a password, token or account number, can leak to other apps or onto the screen.', sev: 'low', detection: 'heuristic' }]]);

/** A rule that reports when the app's own code never mentions something. Heuristic: the protection could live in native code or a library. */
function absenceRule(id, title, category, re, sev, summary, steps, elsewhere) {
  return {
    id, title, category, needs: ['sources', 'manifest'], code: true,
    async run({ input, model, partial }) {
      const other = elsewhere && await elsewhere(input, model);
      if (other === true) return { findings: [] };
      if (other) return { inconclusive: other };                                            // a string: the other place could not be read
      let seen = false;
      const skipped0 = input.stats.skipped, damaged0 = input.stats.damaged;
      for await (const { text } of appCode(input)) {
        seen = true;
        if (re.test(text)) return { findings: [] };
      }
      if (input.stats.damaged > damaged0 || input.stats.truncated || input.stats.skipped > skipped0) return { inconclusive: ABSENCE };           // a missing class could hold the thing, so absence proves nothing
      if (!seen) return { inconclusive: NO_CLASSES };
      return { findings: [finding(id, { key: model.manifest.package, severity: sev, detection: 'heuristic', conclusion: 'weakness', summary, evidence: [], repro: { steps: [steps], command: [] } })] };
    }
  };
}
const tamper = absenceRule('code.no-tamper-check', 'No app-side integrity check found', 'RESILIENCE', /GET_SIGNATURES|GET_SIGNING_CERTIFICATES|getApkContentsSigners|PackageInstaller|Play Integrity|IntegrityManager/, 'low',
  'No signature or integrity check was found in the app\'s own code. A modified copy re-signed with another key would run unchanged, so logic such as login or root checks can be patched out. A check could still live in native code or a library.',
  'Search the app\'s classes for signature checks. Rebuilding and re-signing the APK shows whether it still runs.');
const flagSecure = absenceRule('code.no-flag-secure', 'No screenshot protection found', 'PRIVACY', /FLAG_SECURE|setSecure\s*\(|(?:setFlags|addFlags)\s*\(\s*(?:8192|0x2000)\b|setRecentsScreenshotEnabled\s*\(\s*false/, 'low',
  'The app\'s own code never sets FLAG_SECURE, so its screens appear in screenshots, screen recordings and the recent-apps preview. That matters for screens that show balances, tokens or personal data.',
  'Search the app\'s activities for FLAG_SECURE. Open the recent-apps screen on a device to see whether the app\'s content is visible.',
  async (input) => /excludeFromRecents\s*=\s*"true"/.test((await input.read('resources/AndroidManifest.xml')) || ''));

// Permissions an app declares but whose API never appears anywhere in the decompiled code (libraries count, since they need the permission too).
const PERM_USE = [
  [['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION'], /LocationManager|FusedLocationProvider|requestLocationUpdates|getLastKnownLocation|getLastLocation/],
  [['READ_PHONE_STATE'], /TelephonyManager/],
  [['CAMERA'], /android\.hardware\.Camera\b|CameraManager|CameraDevice|androidx\.camera/],
  [['READ_CONTACTS', 'WRITE_CONTACTS', 'READ_PROFILE', 'WRITE_PROFILE'], /ContactsContract/],
  [['READ_SMS'], /Telephony\.Sms|content:\/\/sms/],
  [['RECEIVE_SMS'], /SMS_RECEIVED|createFromPdu/],
  [['SEND_SMS'], /SmsManager/],
  [['RECORD_AUDIO'], /AudioRecord|MediaRecorder|SpeechRecognizer/],
  [['READ_CALL_LOG', 'WRITE_CALL_LOG'], /CallLog/],
  [['READ_CALENDAR', 'WRITE_CALENDAR'], /CalendarContract/],
  [['CALL_PHONE'], /ACTION_CALL\b/],
  [['GET_ACCOUNTS', 'USE_CREDENTIALS', 'AUTHENTICATE_ACCOUNTS', 'MANAGE_ACCOUNTS'], /AccountManager|GoogleAuthUtil/],
  [['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'], /getExternalStorage|MediaStore|\/sdcard/],
  [['SYSTEM_ALERT_WINDOW'], /TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|canDrawOverlays/],
  [['REQUEST_INSTALL_PACKAGES'], /PackageInstaller|ACTION_INSTALL_PACKAGE|vnd\.android\.package-archive/]
];
const unusedPermissions = {
  id: 'code.unused-permissions', title: 'Dangerous permission declared but not used', category: 'PRIVACY', needs: ['sources', 'manifest'], code: true,
  async run({ input, model, partial }) {
    const declared = new Map(model.manifest.uses.map((u) => [u.name.replace(/^android\.permission\./, ''), u]));
    const skipped0 = input.stats.skipped, damaged0 = input.stats.damaged;
    const todo = PERM_USE.filter(([names]) => names.some((n) => declared.has(n)));
    if (!todo.length) return { findings: [] };
    const used = new Set();
    for await (const { text } of input.walk('sources', JAVA)) {
      for (const [i, [, re]] of todo.entries()) if (!used.has(i) && re.test(text)) used.add(i);
      if (used.size === todo.length) return { findings: [] };
    }
    if (input.stats.damaged > damaged0 || input.stats.truncated || input.stats.skipped > skipped0) return { inconclusive: ABSENCE };
    const findings = [];
    for (const [i, [names]] of todo.entries()) {
      if (used.has(i)) continue;
      for (const n of names.filter((x) => declared.has(x))) {
        const u = declared.get(n);
        findings.push(finding('code.unused-permissions', {
          key: n, title: `Declared but no matching API found: ${n}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
          summary: `The manifest requests ${n}, but no code that needs it was found in the decompiled classes. Extra permissions widen what a compromised app can reach and what users are asked to grant. The permission may still be used through reflection, native code or a framework that is not decompiled here.`,
          evidence: [manifestEv(model, u, `uses-permission ${n}`)], repro: { steps: ['Search the decompiled code for the APIs that need this permission, then remove the permission if nothing uses it.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

const SENSITIVE_FIELD = /pass(?:word|wd|code)?|(?:(?<![A-Za-z])[Pp]|(?<=[a-z])P)in(?![a-z])|cvv|cvc|card|ssn|secret|\botp\b/i;
const keyboardCache = {
  id: 'code.keyboard-cache', title: 'Sensitive input field may be cached by the keyboard', category: 'STORAGE', needs: ['manifest'], code: true,
  async run({ input }) {
    const findings = [];
    let examined = 0;
    for (const d of (await input.list('resources/res')) || []) {
      if (!/^layout/.test(d)) continue;
      for await (const { rel, text } of input.walk(`resources/res/${d}`, /\.xml$/)) {
        examined++;
        for (const m of text.matchAll(/<EditText\b[^>]*>/g)) {
          const tag = m[0], type = /inputType\s*=\s*"([^"]*)"/.exec(tag)?.[1] || '';
          const sensitive = [...tag.matchAll(/(?:id|hint|contentDescription)\s*=\s*"([^"]*)"/g)].some((x) => SENSITIVE_FIELD.test(x[1]));
          if (sensitive && /NoSuggestions/.test(type) && !/flagNoPersonalizedLearning/.test(tag) && findings.length < MAX) findings.push(finding('code.keyboard-cache', {
            key: `learn|${scrub(rel)}|${m.index}`, title: `Sensitive field lets the keyboard learn: ${rel.split('/').pop()}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
            summary: 'A sensitive EditText turns off suggestions but does not set flagNoPersonalizedLearning. Keyboards, including third-party ones the user installed, may still record what is typed to personalize predictions. The value can then end up in the keyboard\'s own storage or cloud sync.',
            evidence: [sourceEv(rel, text, m.index, 'EditText')], repro: { steps: ['Open the layout and add flagNoPersonalizedLearning to android:imeOptions.'], command: [] }
          }));
          if (!sensitive || /[Pp]assword|NoSuggestions/.test(type)) continue;
          if (findings.length >= MAX) return { findings };
          findings.push(finding('code.keyboard-cache', {
            key: `${scrub(rel)}|${m.index}`, title: `Sensitive field without a no-suggestions input type: ${rel.split('/').pop()}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
            summary: `An EditText that looks like it takes a password, PIN or card number has inputType "${type || 'none'}". Without textNoSuggestions or a password type, the keyboard may learn and suggest what is typed. A field that sets its type in code is not seen here.`,
            evidence: [sourceEv(rel, text, m.index, 'EditText')], repro: { steps: ['Open the layout and set android:inputType to textPassword, numberPassword or textNoSuggestions.'], command: [] }
          }));
        }
      }
    }
    // Fields built in code: setInputType on a view named like a secret, and Compose text fields whose label names one.
    const NAMED = /\b(\w*(?:pass(?:word|wd)?|pin|cvv|otp|secret|card)\w*)\s*\.setInputType\s*\(([^)]*)\)/gi;
    for await (const { rel, text } of appCode(input)) {
      examined++;
      const hits = [...text.matchAll(NAMED)].filter((m) => !/PASSWORD|NO_SUGGESTIONS|NO_PERSONALIZED/.test(m[2])).map((m) => [m.index, `${m[1]}.setInputType(${m[2].trim()})`]);
      for (const m of text.matchAll(/\b(?:Outlined|Basic)?TextField\s*\(/g)) {
        const body = text.slice(m.index, m.index + 800);
        if (/"[^"]*(?:[Pp]assword|\bPIN\b|CVV|OTP|[Cc]ard number|[Ss]ecret)[^"]*"/.test(body) && !/KeyboardType\.(?:Password|NumberPassword)|PasswordVisualTransformation|autoCorrect\s*=\s*false/.test(body)) hits.push([m.index, 'TextField']);
      }
      for (const [at, what] of hits.slice(0, 3)) {
        if (findings.length >= MAX) return { findings };
        findings.push(finding('code.keyboard-cache', {
          key: `code|${scrub(rel)}|${at}`, title: `Sensitive field built in code lets the keyboard learn: ${rel.split('/').pop()}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
          summary: `A field that looks like it takes a password, PIN or card number is created in code (${what}) without a password type or a no-suggestions flag. The keyboard may then learn and suggest what is typed, and keep it in its own storage. Set a password input type, textNoSuggestions or flagNoPersonalizedLearning.`,
          evidence: [sourceEv(rel, text, at, what)], repro: { steps: ['Open the evidence location and check the field\'s input type and keyboard options.'], command: [] }
        }));
      }
    }
    if (!examined) return { inconclusive: 'no layout files or decompiled sources were found, so no input field was checked' };
    return { findings };
  }
};

/** `text` with every comment, and by default every string or character literal, blanked out (same length, same line breaks), so declarations and braces can be found without being fooled by them. */
function mask(text, strings = true) {
  const out = text.split('');
  let str = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (str) { if (c === '\\') { if (strings) out[i] = out[i + 1] = ' '; i++; } else if (c === str) str = null; else if (strings && c !== '\n') out[i] = ' '; continue; }
    if (c === '/' && text[i + 1] === '/') { for (; i < text.length && text[i] !== '\n'; i++) out[i] = ' '; continue; }
    if (c === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2), stop = e < 0 ? text.length : e + 2; for (; i < stop; i++) if (text[i] !== '\n') out[i] = ' '; i--; continue; }
    if (c === '"' || c === "'") str = c;
  }
  return out.join('');
}
/** Index of the bracket that closes the one at `open` in masked text, or -1 when it does not close within a sane distance. */
function closer(masked, open) {
  const [a, b] = masked[open] === '(' ? ['(', ')'] : ['{', '}'];
  let depth = 0;
  for (let i = open, end = Math.min(masked.length, open + 30000); i < end; i++) {
    if (masked[i] === a) depth++;
    else if (masked[i] === b && --depth === 0) return i;
  }
  return -1;
}
const LOGOUT_NAME = /log-?out|sign-?out|logoff|clearsession/i;
const LOGOUT_METHOD = /(?<=[\w>\]]\s+)\b(?:on|perform|handle|do|force|execute)?(?:[Ll]og[oO]ut|[Ss]ign[oO]ut|[Ll]ogOff|[Cc]learSession)\w*\s*\(/g;
// What counts as clearing the session: a preferences edit that clears or removes, cookie removal, deleting app files, removing or revoking something named like a token, or a call to another sign-out. A bare .clear(), .commit() or .remove() does not.
const SESSION_CLEARED = /\.edit\s*\(\s*\)[^;]{0,200}?\.(?:clear\s*\(\s*\)|remove\s*\([^)]*(?:token|session|auth|credential|cookie|jwt|password|account|login)[^)]*\))|\.(?:removeAllCookies?|removeSessionCookies?)\s*\(|\b(?:deleteSharedPreferences|deleteFile|deleteDatabase|clearApplicationUserData)\s*\(|\.(?:remove|delete|clear|revoke|invalidate|reset)\w*\s*\([^)]{0,80}(?:token|session|auth|credential|cookie|jwt|password|account)|\b\w*(?:token|session|auth|credential|cookie|jwt|account)\w*(?:\s*\(\s*\))?\s*\.\s*(?:clear|remove|delete|reset|invalidate|revoke|logout|signOut)\w*\s*\(|\b(?:signOut|logOut|logout|clearSession|clearData|clearTokens|clearCredentials|revoke\w*)\s*\(/i;
const LOGOUT_LABEL = 'Logout without clearing stored state';
const logout = {
  id: 'code.logout-keeps-session', title: 'Logout does not clear the session', category: 'AUTH', needs: ['sources', 'manifest'], code: true,
  async run({ input }) {
    const findings = [];
    let scanned = 0, unparsed = 0;
    for await (const { rel, text } of appCode(input)) {
      scanned++;
      if (!LOGOUT_NAME.test(text)) continue;
      const masked = mask(text), noComments = mask(text, false);                        // names in comments and strings are not methods
      for (const m of masked.matchAll(LOGOUT_METHOD)) {
        const params = closer(masked, m.index + m[0].length - 1);                       // parameters may hold annotations with their own brackets
        if (params < 0) { unparsed++; continue; }
        const head = /^\s*(?:throws\s+[\w.,\s]+)?([{;])/.exec(masked.slice(params + 1, params + 200));
        if (!head) continue;                                                            // a call, not a declaration
        if (head[1] === ';') continue;                                                  // an interface or abstract method has no body to read
        const open = params + 1 + head[0].length - 1, end = closer(masked, open);
        if (end < 0) { unparsed++; continue; }
        if (SESSION_CLEARED.test(noComments.slice(open, end + 1))) continue;            // comments do not clear anything, but the key names in strings matter
        if (findings.length >= MAX) return { findings };
        findings.push(finding('code.logout-keeps-session', {
          key: `${LOGOUT_LABEL}|${scrub(rel)}`, title: `${LOGOUT_LABEL}: ${rel.split('/').pop()}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
          summary: 'A method named like logout never clears tokens, cookies or preferences in its own body. If the session survives, the next person to use the phone, or an attacker with file access, stays logged in. The clearing may happen in a method it calls, so follow the call chain.',
          evidence: [sourceEv(rel, text, m.index, LOGOUT_LABEL)], repro: { steps: ['Open the evidence location and follow what the logout method clears.'], command: [] }
        }));
        break;
      }
    }
    if (findings.length) return { findings };
    if (unparsed) return { inconclusive: 'a logout method was found whose parameters or body could not be read to the end, so whether it clears the session is unknown' };
    return scanned || input.stats.truncated ? { findings } : { inconclusive: NO_CLASSES };
  }
};
const jwt = appRule('code.jwt-misuse', 'JSON Web Token handled unsafely', 'AUTH',
  () => 'The code creates or reads JSON Web Tokens in a way that skips or weakens the signature, so the claims cannot be trusted.',
  [
    ['JWT signature algorithm none', /\bAlgorithm\.none\s*\(\s*\)|"alg"\s*:\s*"none"|\bSignatureAlgorithm\.NONE\b/g, { sev: 'low', detection: 'heuristic', d: 'Code selects the "none" algorithm for a JSON Web Token or writes it into a header. A token with no signature proves nothing, so anyone can forge one wherever a parser accepts it. Always sign tokens and make the verifier require a named algorithm.' }],
    ['JWT signed with a literal secret', /\bAlgorithm\.HMAC(?:256|384|512)\s*\(\s*"[^"]{4,}"|\bsignWith\s*\([^;]{0,80}"[^"]{8,}"\s*\.getBytes\s*\(/g, { sev: 'medium', detection: 'heuristic', d: 'A JWT is signed or verified with an HMAC key written in the code. Anyone who decompiles the app can read it and mint tokens that the server accepts. Keep signing keys on the server, and use asymmetric keys if the app has to verify.' }],
    ['JWT parsed without a signing key', /\bJwts\.parser\s*\(\s*\)((?:(?!\.parse)[\s\S]){0,160}?)\.parse\w*\s*\(/g, { sev: 'low', detection: 'heuristic', skip: (m) => /setSigningKey|verifyWith|setSigningKeyResolver/.test(m[1]), d: 'A JWT parser is built without a signing key before it parses a token. The claims then come from data nobody verified, so an attacker can change them. Set the key with setSigningKey or verifyWith before parsing.' }],
    ['JWT only decoded', /\bJWT\.decode\s*\(/g, { sev: 'low', detection: 'heuristic', d: 'The app reads a JWT with JWT.decode, which does not check the signature. That is fine for showing a name, but not for deciding what a user may do. Let the server verify tokens and treat decoded claims on the client as display data.' }]
  ], 'Open the evidence location and check where the token comes from and who verifies it.');

const ENDPOINT_NOISE = /(?:^|\.)(?:schemas\.android\.com|w3\.org|apache\.org|xmlns|developer\.android\.com|android\.com|googleapis\.com\/auth|example\.(?:com|org)|github\.com|play\.google\.com|goo\.gl|creativecommons\.org|mozilla\.org|xml\.org|java\.sun\.com|oracle\.com|ietf\.org|eclipse\.org)$/;
const endpoints = {
  id: 'network.endpoint-inventory', title: 'Backend hosts named in the app', category: 'NETWORK', needs: ['sources', 'manifest'], code: true,
  async run({ input }) {
    const hosts = new Map();
    // Every host keeps the first place it appears as evidence. At most 500 distinct hosts are tracked: when the table is full, the oldest hosts seen only once are dropped to make room, so a generated app cannot grow it without bound and a busy host is not shut out.
    let capped = false;
    const add = (rel, text) => { for (const m of text.matchAll(/https?:\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g)) { const h = m[1].toLowerCase(); if (hostOk(h) || ENDPOINT_NOISE.test(h)) continue; let e = hosts.get(h); if (!e) { if (hosts.size >= 500) { for (const [k, v] of hosts) if (v.n === 1 && hosts.size > 400) hosts.delete(k); if (hosts.size >= 500) { capped = true; continue; } } e = { n: 0, ev: sourceEv(rel, text, m.index, h) }; hosts.set(h, e); } e.n++; } };
    for await (const { rel, text } of appCode(input)) add(rel, text);
    for await (const { rel, text } of input.walk('resources/res/values', /\.xml$/)) add(rel, text);
    if (!hosts.size) return { findings: [] };
    const sorted = [...hosts.entries()].sort((a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]));
    const top = sorted.map(([h]) => h);
    return { findings: [finding('network.endpoint-inventory', { key: 'hosts', title: `${top.length} backend host${top.length === 1 ? '' : 's'} named in the app`, severity: 'low', detection: 'exact', conclusion: 'exposure',
      summary: `The code and resources name these hosts: ${top.slice(0, 40).join(', ')}${top.length > 40 ? ` and ${top.length - 40} more` : ''}${capped ? ' (the list stops at 500 hosts)' : ''}. This is the list to test on the server side, because every host is an attack surface that the APK cannot show the settings of.`,
      evidence: sorted.slice(0, 40).map(([, e]) => e.ev), repro: { steps: ['Open each evidence location, then search the decompiled code for the other host names and test each one with a proxy.'], command: [] } })] };
  }
};

export default [credentials, crypto, webview, cleartext, logging, storage, root, SMS, tamper, worldFiles, webviewSettings, random, tokenPrefs, execution, intents, sql, zip, legacyTls, fileProvider, clipboard, flagSecure, unusedPermissions, keyboardCache, traversal, deserialization, hostCheck, untrustedUrl, resultUri, secretInUrl, nativePointer, encoded, xxe, fragments, biometric, notification, identifiers, bluetooth, server, leftovers, tapjacking, noPinning, oauth, antiDebug, trackers, clipRead, deprecatedSecurity, passkey, tempFiles, timingEquals, stackTrace, malwareSigns, composeState, noObfuscation, sdkInventory, noRootCheck, partialObfuscation, keyReuse, copyPaste, sqlVariable, downloadManager, logout, jwt, endpoints];
