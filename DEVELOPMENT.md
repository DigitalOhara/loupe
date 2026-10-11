# Loupe development notes

Internal reference for working on Loupe: requirements, how each feature works, the security model, the architecture and troubleshooting. The public overview is in [`README.md`](README.md). Keep deep or sensitive detail here.

Loupe speaks the ADB wire protocol from the browser, over WebUSB when the phone is plugged in or over Wi-Fi through a small Node bridge. It mirrors the screen with scrcpy decoded through WebCodecs. Over USB it needs no host `adb` server, no drivers and no agent app. Over Wi-Fi it uses the host `adb` for pairing, discovery and transport.

## Requirements

| | |
|---|---|
| Browser | Chrome or Edge. WebUSB is Chromium only. |
| Node | 20 or newer (`.nvmrc` pins `v24.20.0`) |
| Phone | USB debugging on |
| Context | `localhost` or HTTPS, because WebUSB needs a secure context |
| Decompiler | Nothing to install. Java and jadx download on first use, after a click. macOS and Linux only. |
| `adb` | Wi-Fi only: pairing, mDNS discovery and transport go through the host binary |
| `xz` | Frida install only, to unpack the server (`brew install xz`). Not bundled with Windows. |
| `openssl` | Proxy CA step only, to convert the certificate. Not bundled with Windows. |
| `bubblewrap` | Linux decompiler only. macOS uses its built-in `sandbox-exec`. |
| Root | Optional. Needed for the system CA install, starting `frida-server`, `/data/data` and other processes' memory. |

## Quick start

```bash
nvm use            # picks up .nvmrc
npm install
npm run dev
```

Open <http://localhost:5173>. This also starts the bridge on port `8090` (the loopback `/__loupe/*` API for ADB, Frida, cert preparation, the decompiler and the analyzer). Vite proxies `/__loupe` to it, so the page only talks to its own origin.

```bash
npm run build      # production bundle into dist/
npm run proxy      # the bridge alone (port 8090, or pass one: node proxy/server.js 9000)
npm test           # all tests; real-jadx tests skip without the toolchain
```

The page only calls same-origin `/__loupe/*`, and `/__loupe/session` refuses cross-origin requests, so a standalone bridge works only behind a reverse proxy that serves it on the UI's origin. For normal use, run `npm run dev`.

## Connecting a device

### Over USB

1. Enable Developer options → USB debugging and plug the phone in.
2. Stop any desktop adb server, which holds the USB interface and blocks the browser. Do not run `adb devices` afterwards, because that starts it again.
   ```bash
   adb kill-server
   ```
3. Device menu → Connect a device over USB, pick the phone, and tap Allow USB debugging on it (tick Always allow).

The connect sequence prints a trace into the Shell panel (`opening USB picker…`, `claiming interface…`, `authenticating…`, `reading device info…`, `connected`). On timeout, `rx=0` means the phone never replied (usually another adb owns it), and `rx: CNXN,AUTH…` means it replied but authorisation did not finish.

### Over Wi-Fi

Device menu → Connect over Wi-Fi:

| Tab | Use when |
|---|---|
| Pair code | First time. The phone shows an address and a 6-digit code under Wireless debugging → Pair device with pairing code. |
| QR code | First time, hands-free. Scan Loupe's QR from Pair device with QR code. |
| Connect | Already paired. Type `192.168.1.42:5555`. |

A browser cannot open TCP sockets, do mDNS or perform the TLS/SPAKE2 handshake Android 11+ requires. The bridge (`proxy/adb-bridge.js`) drives the host `adb`, which pairs correctly, and relays each ADB service (`shell:`, `sync:`, `localabstract:scrcpy` and so on) to the browser over a WebSocket. The browser runs ya-webadb's `AdbTransport` against that relay, so shell, files, logcat, mirroring and memory work the same as over USB. QR pairing follows Android Studio's path: the QR carries a service name and password, the phone advertises `_adb-tls-pairing._tcp` once scanned, and Loupe finds it with `adb mdns services`.

The host adb server claims USB devices, so USB and Wi-Fi cannot both be live. The Wi-Fi panel has Stop adb server (free USB) to hand USB back. The bridge uses `~/Library/Android/sdk/platform-tools/adb` when present and otherwise `adb` from `PATH`.

### Disconnecting and rebooting

Disconnect (device bar, or the device's row in the device menu) asks first, stops mirroring, tears down the logcat and shell streams, closes the transport and clears every panel's state. Over Wi-Fi it leaves the host adb attached, so the device stays listed under Wireless devices for a one-click re-attach. The header's Reboot menu runs `reboot`, `reboot recovery` or `reboot bootloader`, and Loupe resets the UI as it does for a disconnect.

## Console features

### Root mode

Loupe detects root on connect (`su -c id`) and turns on elevated mode. The header shows `$ shell` or `# root`, and you can toggle it. With it on, Files reaches `/data/data` and other protected paths, Shell runs through `su`, Memory reads any process's maps and dumps non-debuggable heaps, and Processes can kill anything.

The ADB sync service runs as the shell user and ignores `su`, so Loupe lists protected directories through a root shell (`ls -laL`, symlinks dereferenced so `/sdcard` stays navigable) and moves file contents by staging them through `/data/local/tmp`, then `cp`-ing with `su`. Transfers stay binary-safe. Non-root devices keep the sync path, and Loupe falls back to a root shell only if sync is refused and `su` works.

### Mirror and control

The official scrcpy 3.3.3 server is pushed to the device, started over ADB and decoded with WebCodecs. The canvas matches the phone's aspect ratio. Pointer events become real touches mapped to device coordinates. Also available: hardware keys, notification shade, wake, rotate, text input into the focused field, and start/stop beside the LIVE indicator.

Screenshots save a PNG and try to copy it (the copy can fail on browser permissions). They use the mirror frame when mirroring and `screencap` otherwise. Screen recording records the mirror in the first format MediaRecorder supports (VP9 WebM, VP8 WebM, WebM, then MP4), with no 3-minute cap.

### Logcat, Network, Performance

- **Logcat:** `logcat -v brief`, level toggles, a text filter, and an app filter that resolves the app's PIDs with `pidof`. Pause, clear and export to `.txt`. Output is buffered and the render window is capped so a log storm does not freeze the UI. It starts paused.
- **Network:** the device's socket table (`ss -tunp`, falling back to `netstat`) with state colours and a filter.
- **Performance:** CPU and memory from `/proc` every 2 s, FPS from the foreground app's `dumpsys gfxinfo` frame counter (a per-interval delta, 0 when idle), plus battery, network, storage and uptime.

### Memory

Pick a process (sorted by RSS) to load its `dumpsys meminfo`, view `/proc/<pid>/maps`, and capture memory to your computer. Capture tries `am dumpheap` for an `.hprof` and falls back to an ELF core dump. Force core dump skips the hprof attempt: it reads the process's readable memory from `/proc/<pid>/mem` and packages it with each region as a `PT_LOAD` at its real address and permissions, plus an `NT_FILE` note naming the backing libraries. Regions the kernel refuses are skipped, which keeps later offsets in place. The core opens in gdb, LLDB, radare2 or Ghidra.

`am dumpheap` hands the target app a file descriptor and the app writes the file, so it works only on debuggable builds. For a release app it accepts the request and the VM writes nothing. Loupe checks the package's `DEBUGGABLE` flag first and goes straight to the core path when it is off. It captures stderr (the ADB `exec:` service carries stdout only), waits up to three minutes for a growing file, tries the app's data dir, `/data/local/tmp` and `/sdcard`, and tries both the pid and the process name. With root, `/proc/<pid>/mem` needs no cooperation, so capture works on every process and only the format changes.

### Inspector, Settings, Device Info

- **Inspector:** `uiautomator dump` parsed into an indented tree with per-node attributes.
- **Settings:** list, filter, set (`settings put`, single-quoted) and delete keys in `system`, `secure` and `global`. Some keys reject writes.
- **Device Info:** `getprop` grouped into cards, with filter, reload and copy-all.

### Files

Browse over the ADB sync service with breadcrumbs. Typing filters the current folder, and Enter runs a recursive `find`. The preview pane picks by type: images inline, text and config as text, HTML in a script-disabled iframe with a Source toggle, PDFs in the browser viewer, audio and video in players, and SQLite databases (by extension or header) as a table browser with the first 200 rows per table. Download, multi-file upload with progress, copy/cut/paste, delete with confirmation and new folder also work.

Reads are capped by type: images 16 MiB, PDFs 32 MiB, audio, video and SQLite 64 MiB, HTML 2 MiB, text 512 KiB. Downloads stop at 512 MiB.

### Apps

Lists user, system or all packages, with a launcher icon and a name. The name comes from the package (`friendlyName` in `ui.jsx`), because ADB cannot read the real label without `aapt`. `loadAppIcons` pulls the highest-density raster `ic_launcher` from the first 80 packages' APKs with `unzip`. Vector-only icons and later packages get a letter badge. The details pane comes from `dumpsys package`.

Install APK pushes the file, runs `pm install -r` and cleans up. Two Android blocks get an in-app prompt (`Dialogs.jsx`):

- **Play Protect hold.** `pm install` waits on Play Protect's dialog and returns no error. `installApk` polls the focused window, and on `PlayProtectDialogsActivity` it asks. Install anyway sets `verifier_verify_adb_installs=0`, stops the waiting `pm` and installs again. Cancel install stops it and sends the phone HOME. The setting stays at 0 until you set it back to 1 (Settings tab, `global`).
- **Old target SDK.** Android 14+ can refuse an old app (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`). Install anyway retries with `--bypass-low-target-sdk-block`.

Per-app actions: launch, force-stop, enable/disable, clear data (`pm clear`), clear cache (root-only `rm -rf` of the cache dirs), uninstall, and jump to the data dir in Files.

### Processes and Shell

Processes is the `ps -A` table (sortable, filterable) with force-stop and kill. Shell is an `adb shell` with history and `clear`, and a `#` or `$` prompt that follows root mode. It also logs connect traces, installs and mirror start-up.

### Proxy

Loupe points the device at your intercepting proxy (Burp, HTTP Toolkit). It is not the proxy itself.

- **Device proxy:** Start/Stop sets and clears `settings put global http_proxy <host>:<port>` and reads it back, so the status reflects the device. Test connection is a TCP connect from the bridge (`/__loupe/proxy/test`), so it shows only that this computer reaches the proxy. The host defaults to this machine's LAN address. The proxy must listen on all interfaces.
- **CA certificate:** upload DER or PEM. The host's openssl converts it to PEM with the Android `subject_hash_old` name (`/__loupe/cert/prepare`, `proxy/cert.js`). On Magisk or KernelSU (`/data/adb/modules` present), `installCert` writes a boot module (`loupe-cacerts`) whose `post-fs-data.sh` re-applies the store over `/system/etc/security/cacerts` and the Conscrypt APEX on every boot, and runs once at install. Without a module manager it does a one-shot tmpfs mount that resets on reboot. Both need root. Remove deletes the module and unmounts the live store.

### Frida

Installs, starts and stops `frida-server`, and runs scripts from the browser.

- **Install:** the bridge downloads the `frida-server` release matching the `frida` client in `node_modules`, for the device's ABI, unpacks it and pushes it to `/data/local/tmp`. The browser cannot reach GitHub's release assets or unpack `.xz`. A server from a different release can hang on spawn or crash the agent in the target app, so Loupe never installs a newer one.
- **Start/Stop** needs root, to ptrace other processes.
- **Script editor:** CodeMirror with a `Java.perform` template. Pasting one link in place of a script makes Run fetch it. `resolveScript` in `proxy/frida.js` normalises a CodeShare project (via its `api/project/...` JSON), a GitHub `/blob/` file (to `raw.githubusercontent.com`) and a single-file Gist, and rejects repos, folders and multi-file Gists. Anything with whitespace is treated as the script itself.
- **Run:** pick a target (tick spawn to launch it fresh), press Run, and `console.log` and `send()` stream into the log. frida-node runs in the bridge, so no `frida` CLI is needed.

**Reaching frida-server.** frida-server listens only on the device's loopback, and the host adb cannot claim a USB interface the browser's WebUSB session already holds. So the run WebSocket carries a tunnel. The browser opens an ADB socket to `tcp:27042` (`openTcpSocket` in `webadb.js`, over whichever transport is live). `runSession` in `proxy/frida.js` listens on a local port and hands `127.0.0.1:<port>` to `frida.addRemoteDevice`. The proxy relays that connection to the browser as binary WebSocket frames, and the browser pumps the bytes into the ADB socket. Text frames on the same socket stay JSON control. One socket is one run, and closing it unloads the script and drops the tunnel.

**Pre-17 scripts.** Frida 17 moved the language bridges out of the agent runtime and dropped several globals, so scripts written for Frida 16 and earlier fail on load. `withBridge()` in `proxy/frida.js` prepends only the shims a script needs, each gated on a regex:

- `Java`, restored from `frida-java-bridge` and built with `frida-compile` and esbuild into `proxy/agent/bridge-prelude.js` (source: `proxy/agent/bridge-entry.js`; rebuild with `npm run build:frida-bridge`). It is about 1900 lines because the bridge embeds C source.
- `Module.findExportByName`, `getExportByName`, `findBaseAddress` and `getBaseAddress`, as one-line forwarders.
- `Memory.readX` and `Memory.writeX`, as forwarders onto `NativePointer` methods.

Error line numbers are shifted by the prelude's length. `frida-compile`, `frida-java-bridge` and `esbuild` are dev-only, and the built prelude is committed.

### What it cannot do

- Wi-Fi needs the bridge and `adb`. USB needs neither. USB and Wi-Fi cannot be live together.
- HTTPS interception needs your own proxy and its CA. Pinned apps need their own unpinning, which you run in the Frida tab. Loupe bundles no unpinning script because none works for every app.
- `/data/data`, other processes' maps and non-debuggable heap dumps need root.
- Frida has no interactive REPL. That is the `frida` CLI's job.

## Decompiler

A second full-window view (`Console | Decompiler` in the header), loaded lazily. It opens an APK from disk, drag-and-drop, the connected phone (Decompile in Apps) or an `.apk` in Files, and reads it like jadx-gui.

### Setup

The first time, Loupe asks once before downloading a Java runtime (Temurin 21) and jadx 1.5.0 into `~/.loupe/tools` (about 140 MB), pinned by SHA-256 in `proxy/toolchain-manifest.json`. It unpacks them with its own code (`tar.js`, `zipfile.js`), proves they run and publishes them atomically. Nothing is installed system-wide. `LOUPE_JAVA` and `LOUPE_JADX_JAR` point it at your own Java and jadx.

### What you get

- **Dashboard.** With no project open: a drop box above a Decompiled apps table (search, sort, app icon and name, package, version, SDK range, MD5, size, relative scan time with the exact time on hover, and when it was last analyzed). Click a row to reopen it. Copy icons copy the package or MD5, and the trash icon deletes the cache entry. `‹ Apps` returns here. Facts come from `manifestFacts` in `proxy/jadx.js`. The MD5 is computed at upload and filled in for older scans when the table loads.
- **Source tree** with single-child packages folded, file-type icons, a filter box (it matches what is already loaded) and document tabs.
- **Search** over code, resources and the manifest (regex, case, whole word), `Ctrl/Cmd+Shift+F`. Clicking a hit jumps to it.
- **Deobf:** jadx's deobfuscator with min and max name length and the use-source-name option. Each combination is cached as its own decompile.
- **Info:** manifest facts (identity, SDK, build, security flags, signature) and signature verdicts for v1, v2, v3 and v3.1 from Google's apksig, which the jadx jar already bundles. `proxy/apk/Verify.class` (source `Verify.java`; recompile with `javac --release 17 -cp <jadx-all.jar> -d proxy/apk proxy/apk/Verify.java`) prints JSON, runs in the jadx sandbox and is cached per scan.
- **Binary files** open as a hex dump of the first 64 KB. Images preview inline. Text files over 2 MB are refused.

### How it runs

`proxy/jadx.js` passes the upload through a zip preflight (`zipfile.js`: entry count, declared size, per-entry size, unsafe names; no compression-ratio check, because real native libraries compress 200:1). It then runs one job at a time, single-flight per cache key, with reference-counted cancel, a timeout and an output cap.

The cache key hashes the jadx version, the exact flags and the APK parts, so changed options never serve stale output. A job is published only when jadx exits 0. jadx exits 0 even when some classes failed ("finished with errors"), and that count only marks the result partial. Any other exit, a signal, a timeout or output over the cap never reaches the cache. Log text never turns a failure into a success.

Output lives in `~/.loupe/decompiled` (LRU). Search runs in a worker thread limited by query length, results, files and time.

Limits: APK upload 1 GiB, output 4 GiB per job, a job 30 minutes (`LOUPE_JADX_TIMEOUT_MS`), cache 10 GiB, decompiled text file 2 MB. `LOUPE_HOME` moves everything, but full decompiles are rejected when its path contains whitespace (the JVM options are space-separated).

### Hostile input

The APK and its output are untrusted. The file API never follows symlinks and never serves output as HTML. jadx runs in `proxy/sandbox.js` with no network, reads denied by default and writes only to the job dir. On macOS only the job, the toolchain, the root directory and `/System` are readable, through `sandbox-exec`. On Linux it uses bubblewrap with a deny-by-default filesystem. JVM limits (`-Xmx`, temp and home dirs) go in argv so they hold under bwrap's `--clearenv`.

Before the first run, `selfTest` starts a probe in the sandbox and checks that it cannot read canaries (one in `/var/tmp`, a path no rule names) or reach the network. If it cannot, the decompiler stays off, with no override.

### Platforms

macOS is tested. Linux has run under WSL2 (Ubuntu, bubblewrap). It needs `bwrap` and permitted user namespaces, which some distros restrict, and the self-test turns the decompiler off with the reason shown. Windows has no sandbox available to Node, so the decompiler is unavailable there and the rest of Loupe is unaffected.

### Tests

`npm test`. The real-jadx tests need the toolchain (`LOUPE_TOOLS` pointing at an installed one, which also enables the signature tests, or `LOUPE_TEST_INSTALL=1` to download it) and skip otherwise.

## Analyzer

A third view. Static mode scans a decompiled app. Dynamic mode records a session on the phone.

- **Input.** The decompile cache entry (`~/.loupe/decompiled/<id>/out`) and its `sig.json`. A scan never decompiles again. Results go to `~/.loupe/analyzer/<artifactId>/` (0700 directories, 0600 files), where `artifactId` is the SHA-256 of the APK part hashes, so they survive cache eviction and do not change with decompiler options.
- **Dashboard.** `Analyzer.jsx` keeps a `screen` state (`dashboard` or `result`) and opens on the dashboard. `AnalyzerDashboard.jsx` lists apps with a stored result in the current mode, from the `/summary` endpoint (per mode: severity counts, status, scan id, artifact id). `rowsFor` in `src/lib/dashboardRows.js` keeps one row per artifact, because the same APK decompiled twice shares one result. Apps without a result are listed in the Decompiler table instead. A running dynamic session always shows the recording page.
- **Rules.** One file per family under `proxy/analyzer/rules/`. A rule returns findings, or says it is inconclusive or not applicable. `engine.js` turns that into outcomes. A rule is "checked" only when it read its whole input, so a spent budget or decompiler errors make it inconclusive.
- **Worker.** `run.js` runs the rules in a worker thread with memory limits and a wall-clock timeout. Every rule that did not report becomes an `error` outcome, so a timed-out, cancelled or crashed scan never looks clean. Worker messages are rebuilt from whitelisted, size-capped fields in `outcome.js`.
- **Hostile input.** `xml.js` is a strict reader that refuses DTDs and entities and caps size, depth and node count. `files.js` checks every path with `lstat`, never follows a symlink and enforces file, byte and time budgets. Repro commands are argv arrays built only from validated names.
- **Findings.** Each has a detection level (`exact`, `probable`, `heuristic`) and a conclusion (`exposure`, `weakness`, `confirmed`). The fingerprint is the rule plus what it is about, never a line number, so a finding keeps its identity across rescans. Recommendations are looked up by rule id at read time (`recommendationFor` in `api.js`).
- **Standards.** `proxy/analyzer/standards.json` holds the MASWE, MASTG and CWE IDs per rule (read from mas.owasp.org on 2026-10-10). They are related references.
- **API.** `/__loupe/analyzer/{status,scan,results,summary,plan,session}` in `proxy/analyzer/api.js`, behind the same token as the rest. The page polls `scan` for progress.
- **Secrets and masking.** Evidence, stored results, API responses and Markdown exports contain real secret values, because a finding that hides its value is harder to verify. Treat `~/.loupe/analyzer` and exports like the APK and the phone's data. Only fingerprints are scrubbed.
- **App-code rules.** `rules/appcode.js` builds most code rules from one factory: `appRule(id, title, category, summary, patterns, repro)`, where a pattern is `[label, regex, { sev, gate, detection, skip, d }]` and `d` is its own description. They walk all of `sources/` except well-known library packages (`LIBRARY`, pruned with `walk`'s `skipDir`), and report one finding per pattern and file. An unrecognised third-party library is scanned and can add noise. A rule that finds no classes outside the library list is inconclusive. `rules/hybrid.js` reads Cordova, React Native, Flutter, Unity and .NET files and protector names straight from the APK zip, and `apksig.js` reads signing certificates from the APK Signing Block without a Java toolchain.
- **Secrets by name and shape.** `secretscan.js` holds the detectors for `rules/secretvalues.js`. A name counts only when a whole word of it is secret-like (`aesKey`, `client_secret`, not `tokenizer`). UI labels, identifiers, placeholders and translations are filtered out, and the binary rule reads printable strings from the dex, native libraries and binary assets.
- **Own code.** A code rule is inconclusive only when a file it read carries a jadx failure marker (`DAMAGE` in `files.js`) and that file is the app's own code: the packages of the manifest package, the launcher activity and the Application class, two levels deep (set by `runAll` through `setOwnRoots`). Damage elsewhere is counted as `libraryDamaged` and shown in the coverage line without downgrading a rule. If the manifest names nothing to go by, all code counts.
- **Adding a rule.** Add it to a file in `rules/`, list it in `rules/index.js` and `standards.json`, and add a positive and a negative case to `rules.test.mjs`.
- **Left out on purpose.** Probes that send requests to the app's backend or Google (open Firebase databases, Remote Config, API key scope, `assetlinks.json`), anything that needs Frida or an intercepting proxy, dependency CVE lookups, deep link payload fuzzing, `adb backup` (it needs on-device confirmation) and heap dump searches.

### Dynamic sessions

- **Recorder.** `src/lib/recorder.js` holds the logic and takes the ADB connection as an argument, so `recorder.test.mjs` drives it with a fake phone. `session.js` binds it to the real connection and adds the React hook. `probe()` checks the log, the app's uid, the SHA-256 of every installed APK (base and splits, compared as a set with the decompiled parts), `run-as`, root, `/proc/net/tcp` and shared storage. `startSession()` snapshots `/data/data/<pkg>`, streams `logcat -v threadtime -v epoch` filtered to the app's pids and runs the opted-in probes.
- **Connections** come from one long command on the phone (`timeout 1800 sh -c 'while :; do grep -h " <uid> " /proc/net/tcp /proc/net/tcp6; done'` piped to an `awk` that de-duplicates), because a request can open and close in milliseconds and a page-side poll pays an ADB round trip per read. Closing the ADB stream does not stop a loop on the phone, so Stop kills it by a marker as well. Connections are still sampled: seeing none is inconclusive, never clean.
- **Probe groups.** Without the "may change app state" group the session only reads. The read-only group queries providers (a plain query, a lone quote for SQL errors and a `../` path to `/etc/hosts`). The changing group restarts the app, starts services, broadcasts to receivers, fuzzes activities with odd extras, checks window flags, and tests provider writes: a marked row (random `loupe-<hex>` per session, matched exactly) is inserted, updated and deleted, and removed at the end. Write probes run only on providers the manifest leaves open for writes. Each write command runs under `timeout 5` on the phone, so a stalled one cannot finish after the cleanup, and the page gives up on it after 6 s. A timeout adds a warning that the marked row may remain.
- **Stop.** `stopSession()` is safe at any moment and idempotent: a second call shares the first teardown. It waits a bounded time (8 s) for start-up and the probe in flight, takes the "after" snapshot (searching for the typed values and their Base64 form), reads shared storage, `pm get-app-links`, the package flags and granted permissions, the work-profile users, `/proc/net/unix` (WebView `devtools_remote`) and `dumpsys notification --noredact`, then hands the recording to the analyzer. Anything unreadable is `null`, which makes its rule not tested. Anything dropped at a cap, cut short or still running at stop is counted in `limits`, which makes the affected rules inconclusive and the session partial.
- **Parsers.** `src/lib/sessionParse.js` holds the pure parts (`/proc/net` rows, log lines, the snapshot script and output). Every name that reaches a shell command is validated first (`PKG`, `COMPONENT`, `AUTHORITY`, `DEEPLINK`), and every typed value is quoted. The snapshot prints names and contents as Base64, whose alphabet has no `@`, so a hostile app cannot forge a `@@` record. Output without exactly one final `@@N` record is incomplete, never "no files".
- **Analysis.** `POST /__loupe/analyzer/session` takes the recording. `cleanRecording` rebuilds it from whitelisted, capped fields, and `analyzeRecording` runs `DYN_RULES` in `proxy/analyzer/dynamic.js`. `redact.js` decides what counts as sensitive (typed values, key=value credentials, JWTs, provider tokens, card numbers). Provider findings keep only the row count and column names. A rule whose capability was missing, or whose probe group was off, is `not_tested` with the reason. The result is stored as `dynamic.json` beside the static `latest.json`. `GET plan` lists the exported activities, providers and deep links a session may probe.
- **Console takeover.** `Analyzer.jsx` saves the pane layout and switches to the Console at once, puts Logcat on top and Network below, un-pauses and filters the log to the app, and restores the layout when the recording ends or fails to start. Whether an activity opened is read from `topResumedActivity` (`mCurrentFocus` is `null` on some phones). `SessionBar.jsx` is the pinned recording bar.
- **Export.** `src/lib/exportScan.js` writes a Markdown report. `reportCode` makes a four-letter code from the app name and `findingIds` numbers findings by severity (`INSH-01`). The report escapes hostile text and uses a code fence longer than any backtick run inside it.
- **Hot reload.** Editing `session.js` while a session runs orphans the recorder. Reload the page.

### Tests

`npm test` runs `proxy/analyzer/*.test.mjs` too. They need no Java: the API test builds a fake cache entry, and the session tests feed recordings straight to the analyzer.

## Security model

Loupe gives shell access to an attached phone, so it matters who can reach it. Every `/__loupe/*` request must pass these checks:

- **Loopback only.** Other hosts get `403`.
- **Origin allow-list** (`localhost:5173`, `localhost:4173`). Loopback alone is not enough, because any page in your browser can reach localhost, and WebSockets ignore CORS. Without this check any site you had open could shell into your phone through the ADB relay.
- **Host check.** `Host` must be `localhost`, `127.0.0.1` or `[::1]`, which blunts DNS rebinding.
- **Per-launch token.** The bridge binds `0.0.0.0` and `accessOk` lets requests with no `Origin` through, so every request except the session request also needs a random token generated at startup. The page gets it from `/__loupe/session`, keeps it in memory and sends it as `Authorization: Bearer` (fetch) or a `loupe.<token>` WebSocket subprotocol (`proxy/auth.js`, `src/lib/bridge.js`). Restarting the bridge rotates it, and the page re-fetches on `401`.

`/__loupe/session` is the one exception to the token check, because it issues the token. It answers only same-origin browser requests (`Sec-Fetch-Site: same-origin`) on top of the loopback, origin and Host checks. `npm test` attacks all of this (forged Origin and Host, missing token, WebSocket without a token).

Serving the UI from another port means the bridge rejects it. Add that origin to `ALLOWED_ORIGINS` in `proxy/adb-bridge.js`.

Installing a proxy CA is powerful, so you trigger it yourself. It is root-only, and dumps reach your downloads only when you ask.

## Architecture

```
index.html            Vite entry
vite.config.js        dev server; starts the bridge
proxy/server.js       bridge: the loopback /__loupe API and access gate
proxy/auth.js         per-launch token and Host check
proxy/http.js         shared JSON and body helpers
proxy/adb-bridge.js   Wi-Fi ADB: pair, connect, mDNS, service relay
proxy/frida.js        frida-server install, script runs via frida-node
proxy/cert.js         proxy CA to PEM and Android hash name
proxy/jadx.js         decompiler jobs and API (sandbox, toolchain, zipfile, tar, jadx-search)
proxy/apk/            Verify.class, the apksig launcher
proxy/analyzer/       rules, worker runner, store, dynamic rules, API
public/               scrcpy-server.bin, favicon.svg
src/
  main.jsx, App.jsx   mount, layout, resizable split
  store.jsx           reducer store and all actions, via useLoupe()
  styles.css          design tokens (dark and light) and shared classes
  lib/
    webadb.js         all ADB I/O: connect, shell, sync, packages, root, heap, /proc mem
    scrcpy.js         mirroring and input injection
    wireless.js       AdbTransport over the bridge
    bridge.js         fetch and WebSocket helpers that attach the token
    record.js, elfcore.js, sqlite.js
    jadx.js, analyzer.js        clients for the decompiler and analyzer routes
    recorder.js, session.js, sessionParse.js    dynamic sessions
    exportScan.js, codeSpans.js, titleCase.js, dashboardRows.js, format.js
  components/
    Header, Mirror, PanelSlot, Dialogs, ErrorBoundary, Toast, Wireless, ui
    Decompiler, JxPanels, CodePane
    Analyzer, AnalyzerDashboard, AnalyzerPanels, SessionBar
    panels/           DeviceInfo, Logcat, Sockets, Proxy, Perf, Memory, Inspector,
                      Settings, Files, Apps, Procs, Shell, Frida
```

Browser-side Android operations go through `src/lib/webadb.js`. Wi-Fi devices reach the same code through `wireless.js` and the bridge, which also handles Frida, the proxy CA, the decompiler and the analyzer. Pane sizes and the mirror width are saved in `localStorage` (`loupe.layout`, `loupe.splits`).

The Network panel's file is `Sockets.jsx`, not `Traffic.jsx`. Ad and privacy blockers match filenames like `Traffic` and `Capture`, block the module and blank the whole app.

ya-webadb needs one shared copy of its `@yume-chan/*` packages, and mismatched copies make the ADB handshake fail silently. That is why Loupe uses a bundler: npm and the lockfile give one deduped copy, which loading the packages from a CDN could not.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `env: node: No such file or directory` | No active nvm version. Run `nvm use`. A stale `/usr/local/bin/npm` can shadow nvm's. |
| Blank white page | A blocker extension blocked a module (`ERR_BLOCKED_BY_CLIENT` in the console), or you are on a dead port. The app is on 5173. |
| `Invalid hook call` in dev | Stale Vite cache. Hard-reload, or `rm -rf node_modules/.vite`. |
| `Loupe proxy failed to start on 8090` | Something else owns port 8090. Stop it and restart `npm run dev`. |
| `403 forbidden` from the bridge, or Wi-Fi sees no devices | The API is loopback-only and origin-checked. Another machine is refused by design, and another UI port needs adding to `ALLOWED_ORIGINS`. |
| USB connect stalls at `authenticating…` | Accept Allow USB debugging on the phone. No prompt? Revoke USB debugging authorisations, replug and retry. |
| USB connect fails claiming the interface | A desktop adb server owns the device. Run `adb kill-server` and replug. |
| USB stopped working after Wi-Fi | The adb server claimed it. Press Stop adb server (free USB), then reconnect. |
| Switching phones, or USB to Wi-Fi | Press Disconnect first. Only one transport is live, and disconnecting clears the old device's panel state. |
| Wi-Fi tab does nothing | Needs `adb` on `PATH` and the bridge running (`npm run dev`). |
| Paired but the device will not connect | Pairing and connect use different ports. Loupe finds the connect port with `adb mdns services`. If mDNS is blocked, use the Connect tab with `<ip>:5555`. |
| Wi-Fi pairing or discovery fails in WSL2 | Ubuntu's apt `adb` (34.0.4) has no mDNS, so QR pairing and port discovery find nothing. Use Pair code, then Connect with the `ip:port` from Wireless debugging. With mirrored networking `adb start-server` hangs, so on Linux Loupe starts `adb -L tcp:5037 server nodaemon` itself. USB runs in Windows Chrome and never touches WSL. |
| Mirror will not start | Needs WebCodecs H.264. The Shell shows which step failed. |
| `/data/data` unreadable on a rooted phone | Check the header reads `# root`. If `su` prompts on the device, grant it in your superuser app, then toggle. |
| Capture produced a `.core`, not `.hprof` | Expected on release builds. Open the core in gdb, radare2 or Ghidra. |
| Heap dump seems stuck | Large heaps take a while. The panel streams `writing… N MB` and waits up to 3 minutes. |
| Proxy set but no traffic reaches Burp | The proxy must listen on all interfaces (`0.0.0.0`), not only `127.0.0.1`. |
| CA install fails, or HTTPS will not decrypt | The system-store install needs root, and without Magisk or KernelSU it resets on reboot. Pinned apps need unpinning. |
| Frida install fails with an `xz` error | Install `xz` on the host. |
| CA step fails with an `openssl` error | Install `openssl` or put it on `PATH`. |
| Frida spawn hangs, or the app dies on attach | The server release differs from Loupe's client. Press Reinstall matching server. |
| Install stops with a Play Protect dialog on the phone | Use Install anyway in Loupe's prompt, or answer on the phone. See Apps. |
| Decompiler is unavailable | Windows has no sandbox, or the Linux self-test failed (the panel shows why; `bwrap` and user namespaces are required). Under WSL2, open Loupe from Windows Chrome. |
| jadx ran out of memory | Raise the heap with `LOUPE_JADX_XMX_MB`. The default is half of RAM, up to 8 GB. |
| `Full decompile needs LOUPE_HOME without spaces` | Point `LOUPE_HOME` at a path with no spaces. |
| Decompile fails with `timed out` or the output cap | Jobs stop at 30 minutes or 4 GiB of output. The cache holds 10 GiB, and Decompiled apps can delete entries. |
