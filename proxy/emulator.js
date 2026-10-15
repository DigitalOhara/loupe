/**
 * Android Emulator management for Loupe.
 *
 * Downloads Android SDK command-line tools, system images, and the emulator on
 * demand into ~/.loupe/android-sdk. Manages AVDs and emulator processes so the
 * user can spin up a rooted Android emulator directly from the Loupe UI without
 * installing Genymotion or Android Studio.
 *
 * Uses google_apis images (not google_apis_playstore) so `adb root` works.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pipeline } from 'node:stream/promises';
import { json, readJson, NOSNIFF, HttpErr } from './http.js';
import { adbCli } from './adb-bridge.js';

const run = promisify(execFile);
const SDK_ROOT = () => process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT ||
  path.join(process.env.LOUPE_HOME || path.join(os.homedir(), '.loupe'), 'android-sdk');

const isWin = process.platform === 'win32';
const ext = isWin ? '.bat' : '';

const sdkmanager = () => path.join(SDK_ROOT(), 'cmdline-tools', 'latest', 'bin', `sdkmanager${ext}`);
const avdmanager = () => path.join(SDK_ROOT(), 'cmdline-tools', 'latest', 'bin', `avdmanager${ext}`);
const emulatorBin = () => path.join(SDK_ROOT(), 'emulator', isWin ? 'emulator.exe' : 'emulator');
const adbBin = () => path.join(SDK_ROOT(), 'platform-tools', isWin ? 'adb.exe' : 'adb');

// Default image: Android 14 (API 34), google_apis (rooted), x86_64
const DEFAULT_API = '34';
const DEFAULT_TAG = 'google_apis';
const DEFAULT_ABI = 'x86_64';
const DEFAULT_IMAGE = `system-images;android-${DEFAULT_API};${DEFAULT_TAG};${DEFAULT_ABI}`;
const DEFAULT_AVD = 'loupe_device';

// cmdline-tools download URLs by platform
const CMDLINE_TOOLS = {
  'win32':  { url: 'https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip',   name: 'commandlinetools-win.zip' },
  'darwin': { url: 'https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip',   name: 'commandlinetools-mac.zip' },
  'linux':  { url: 'https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip', name: 'commandlinetools-linux.zip' },
};

// ── state ──────────────────────────────────────────────────────────────────
let setupInFlight = null;
let progress = { phase: '', pct: 0, detail: '' };
const emulatorProcs = new Map(); // avdName → { proc, port, pid }

function setProgress(phase, pct = 0, detail = '') {
  progress = { phase, pct, detail };
}

// ── helpers ────────────────────────────────────────────────────────────────
function fetchUrl(url, dest) {
  return new Promise((resolve, reject) => {
    const follow = (u, hop = 0) => {
      if (hop > 5) return reject(new Error('too many redirects'));
      const parsed = new URL(u);
      https.get(parsed, { headers: { 'User-Agent': 'loupe-emulator' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return follow(new URL(res.headers.location, parsed).toString(), hop + 1);
        }
        if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
        pipeline(res, fs.createWriteStream(dest)).then(resolve, reject);
      }).on('error', reject);
    };
    follow(url);
  });
}

async function runCmd(cmd, args, opts = {}) {
  const env = { ...process.env, ANDROID_HOME: SDK_ROOT(), ANDROID_SDK_ROOT: SDK_ROOT() };
  // sdkmanager needs JAVA_HOME — try to find one
  if (!env.JAVA_HOME) {
    const javaInSdk = path.join(SDK_ROOT(), 'cmdline-tools', 'latest', 'lib', 'java');
    if (fs.existsSync(javaInSdk)) env.JAVA_HOME = javaInSdk;
  }
  const timeout = opts.timeout || 600_000;
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
      shell: isWin,
      ...opts,
    });
    let out = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('timed out')); }, timeout);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    // Auto-accept licenses by writing 'y' to stdin
    if (opts.acceptLicenses) {
      const feeder = setInterval(() => { try { child.stdin.write('y\n'); } catch {} }, 500);
      child.on('close', () => clearInterval(feeder));
    }
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out: out.trim() }); });
  });
}

function installed() {
  return fs.existsSync(sdkmanager()) &&
         fs.existsSync(emulatorBin()) &&
         fs.existsSync(adbBin());
}

function imageInstalled() {
  const imgPath = path.join(SDK_ROOT(), 'system-images', `android-${DEFAULT_API}`, DEFAULT_TAG, DEFAULT_ABI);
  return fs.existsSync(imgPath);
}

// ── AVD management ─────────────────────────────────────────────────────────
async function listAvds() {
  if (!fs.existsSync(avdmanager())) return [];
  const { out } = await runCmd(avdmanager(), ['list', 'avd', '-c']);
  return out.split('\n').map((l) => l.trim()).filter(Boolean);
}

async function listRunning() {
  const running = [];
  for (const [name, info] of emulatorProcs) {
    const alive = !info.proc.killed && info.proc.exitCode === null;
    if (alive) {
      running.push({ name, port: info.port, grpcPort: info.grpcPort, serial: `emulator-${info.port}`, booted: !!info.booted });
    } else {
      emulatorProcs.delete(name);
    }
  }
  return running;
}

async function createAvd(name, imageId) {
  name = name || DEFAULT_AVD;
  imageId = imageId || DEFAULT_IMAGE;
  const args = ['create', 'avd', '-n', name, '-k', imageId, '--force', '--device', 'pixel_6'];
  const { code, out } = await runCmd(avdmanager(), args, { acceptLicenses: true });
  if (code !== 0 && !out.includes('already exists')) throw new HttpErr(500, out || 'avdmanager failed');
  // Patch config for better performance + root
  const avdDir = path.join(os.homedir(), '.android', 'avd', `${name}.avd`);
  const configPath = path.join(avdDir, 'config.ini');
  if (fs.existsSync(configPath)) {
    let cfg = fs.readFileSync(configPath, 'utf8');
    const patches = {
      'hw.ramSize': '4096',
      'hw.cpu.ncore': '4',
      'disk.dataPartition.size': '8G',
      'hw.keyboard': 'yes',
      'hw.gpu.enabled': 'yes',
      'hw.gpu.mode': 'auto',
      'vm.heapSize': '512',
      'image.sysdir.1': path.join(SDK_ROOT(), 'system-images', `android-${DEFAULT_API}`, DEFAULT_TAG, DEFAULT_ABI) + path.sep,
    };
    for (const [k, v] of Object.entries(patches)) {
      const re = new RegExp(`^${k.replace('.', '\\.')}\\s*=.*$`, 'm');
      if (re.test(cfg)) cfg = cfg.replace(re, `${k}=${v}`);
      else cfg += `\n${k}=${v}`;
    }
    fs.writeFileSync(configPath, cfg);
  }
  return { ok: true, name };
}

async function deleteAvd(name) {
  if (emulatorProcs.has(name)) {
    const info = emulatorProcs.get(name);
    info.proc.kill('SIGTERM');
    emulatorProcs.delete(name);
    await new Promise((r) => setTimeout(r, 2000));
  }
  const { code, out } = await runCmd(avdmanager(), ['delete', 'avd', '-n', name]);
  if (code !== 0) throw new HttpErr(500, out || 'delete failed');
  return { ok: true };
}

// ── emulator lifecycle ─────────────────────────────────────────────────────
function findFreePort() {
  // Emulator uses consecutive even ports starting at 5554
  const used = new Set([...emulatorProcs.values()].map((i) => i.port));
  for (let p = 5554; p < 5600; p += 2) {
    if (!used.has(p)) return p;
  }
  return 5554;
}

async function startEmulator(name) {
  name = name || DEFAULT_AVD;
  if (emulatorProcs.has(name)) {
    const info = emulatorProcs.get(name);
    if (!info.proc.killed && info.proc.exitCode === null) {
      return { ok: true, name, port: info.port, grpcPort: info.grpcPort, serial: `emulator-${info.port}`, already: true };
    }
    emulatorProcs.delete(name);
  }
  if (!fs.existsSync(emulatorBin())) throw new HttpErr(400, 'emulator not installed — run setup first');

  const port = findFreePort();
  const grpcPort = port + 3000;
  const args = [
    '-avd', name,
    '-port', String(port),
    '-grpc', String(grpcPort),
    '-no-window',
    '-no-audio',
    '-no-boot-anim',
    '-gpu', 'auto',
    '-no-snapshot-load',
  ];
  const env = { ...process.env, ANDROID_HOME: SDK_ROOT(), ANDROID_SDK_ROOT: SDK_ROOT() };
  const proc = spawn(emulatorBin(), args, { stdio: ['ignore', 'pipe', 'pipe'], env, detached: true });
  proc.stdout.on('data', () => {});
  proc.stderr.on('data', () => {});
  proc.unref();
  proc.on('error', () => { emulatorProcs.delete(name); });
  proc.on('exit', () => { emulatorProcs.delete(name); });

  const entry = { proc, port, grpcPort, pid: proc.pid, booted: false };
  emulatorProcs.set(name, entry);

  // Wait for the emulator to become available via ADB, enable root, then mark booted
  const serial = `emulator-${port}`;
  (async () => {
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const { out } = await adbCli(['devices']);
      if (out.includes(serial) && out.includes('device')) {
        for (let j = 0; j < 30; j++) {
          const { out: bootProp } = await adbCli(['-s', serial, 'shell', 'getprop', 'sys.boot_completed']);
          if (bootProp.trim() === '1') break;
          await new Promise((r) => setTimeout(r, 2000));
        }
        await adbCli(['-s', serial, 'root']);
        await new Promise((r) => setTimeout(r, 1000));
        await adbCli(['-s', serial, 'shell', 'setenforce', '0']);
        entry.booted = true;
        break;
      }
    }
  })().catch(() => {});

  return { ok: true, name, port, grpcPort, serial, pid: proc.pid };
}

async function stopEmulator(name) {
  name = name || DEFAULT_AVD;
  const info = emulatorProcs.get(name);
  if (info) {
    const serial = `emulator-${info.port}`;
    await adbCli(['-s', serial, 'emu', 'kill']).catch(() => {});
    await new Promise((r) => setTimeout(r, 1000));
    if (!info.proc.killed) info.proc.kill('SIGTERM');
    emulatorProcs.delete(name);
  }
  return { ok: true };
}

// ── SDK setup ──────────────────────────────────────────────────────────────
async function doSetup() {
  const root = SDK_ROOT();
  await fsp.mkdir(root, { recursive: true });

  // Step 1: Download cmdline-tools if needed
  if (!fs.existsSync(sdkmanager())) {
    const plat = CMDLINE_TOOLS[process.platform];
    if (!plat) throw new Error(`unsupported platform: ${process.platform}`);

    setProgress('downloading SDK command-line tools', 10, plat.name);
    const zipPath = path.join(root, plat.name);
    await fetchUrl(plat.url, zipPath);

    setProgress('extracting command-line tools', 20);
    const targetDir = path.join(root, 'cmdline-tools', 'latest');
    const tmpDir = path.join(root, '_tmp_cmdline');

    // Clean up any prior partial extraction
    await fsp.rm(tmpDir, { recursive: true, force: true });
    // Remove the entire cmdline-tools tree so rename has a clean target
    await fsp.rm(path.join(root, 'cmdline-tools'), { recursive: true, force: true });

    // Extract zip — use PowerShell on Windows, unzip on Unix
    if (isWin) {
      await run('powershell', ['-NoProfile', '-Command',
        `Expand-Archive -Path '${zipPath}' -DestinationPath '${tmpDir}' -Force`
      ], { timeout: 120_000 });
    } else {
      await run('unzip', ['-o', zipPath, '-d', tmpDir], { timeout: 120_000 });
    }

    // The zip extracts to cmdline-tools/ inside the temp dir — move it into place
    const extracted = path.join(tmpDir, 'cmdline-tools');
    if (!fs.existsSync(extracted)) throw new Error('unexpected zip layout — cmdline-tools/ not found');
    await fsp.mkdir(path.join(root, 'cmdline-tools'), { recursive: true });
    // On Windows, rename across dirs can EPERM if handles linger — retry once
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await fsp.rename(extracted, targetDir);
        break;
      } catch (e) {
        if (attempt === 2) throw e;
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    await fsp.rm(tmpDir, { recursive: true, force: true });
    await fsp.rm(zipPath, { force: true });
  }

  if (!fs.existsSync(sdkmanager())) throw new Error('sdkmanager not found after extraction');

  // Step 2: Accept licenses
  setProgress('accepting SDK licenses', 30);
  await runCmd(sdkmanager(), ['--licenses', `--sdk_root=${SDK_ROOT()}`], { acceptLicenses: true, timeout: 60_000 });

  // Step 3: Install emulator + platform-tools
  if (!fs.existsSync(emulatorBin())) {
    setProgress('installing emulator & platform-tools', 40, 'this may take a few minutes');
    const { code, out } = await runCmd(sdkmanager(), [
      'emulator', 'platform-tools', `--sdk_root=${SDK_ROOT()}`
    ], { acceptLicenses: true, timeout: 600_000 });
    if (code !== 0 && !out.includes('done')) throw new Error('failed to install emulator: ' + out.slice(0, 200));
  }

  // Step 4: Install system image
  if (!imageInstalled()) {
    setProgress('downloading Android system image (rooted)', 55, `API ${DEFAULT_API} ${DEFAULT_TAG} ${DEFAULT_ABI} — ~1.5 GB`);
    const { code, out } = await runCmd(sdkmanager(), [
      DEFAULT_IMAGE, `--sdk_root=${SDK_ROOT()}`
    ], { acceptLicenses: true, timeout: 1200_000 });
    if (code !== 0 && !out.includes('done')) throw new Error('failed to install system image: ' + out.slice(0, 200));
  }

  // Step 5: Create default AVD
  setProgress('creating default AVD', 90, DEFAULT_AVD);
  await createAvd(DEFAULT_AVD, DEFAULT_IMAGE);

  setProgress('done', 100, 'ready');
  return { ok: true };
}

function setup() {
  if (setupInFlight) return setupInFlight;
  setProgress('starting', 0);
  setupInFlight = doSetup()
    .catch((e) => { setProgress('error', 0, e.message); throw e; })
    .finally(() => { setupInFlight = null; });
  setupInFlight.catch(() => {});
  return setupInFlight;
}

// ── HTTP handler ───────────────────────────────────────────────────────────
export async function handleEmulatorApi(req, res, urlPath) {
  try {
    // GET /__loupe/emulator/status
    if (urlPath === '/__loupe/emulator/status' && req.method === 'GET') {
      const avds = installed() ? await listAvds() : [];
      const running = await listRunning();
      return json(res, 200, {
        ok: true,
        installed: installed(),
        imageInstalled: imageInstalled(),
        sdkRoot: SDK_ROOT(),
        avds,
        running,
        setupBusy: !!setupInFlight,
        progress,
        defaultAvd: DEFAULT_AVD,
        defaultImage: DEFAULT_IMAGE,
      });
    }

    // POST /__loupe/emulator/setup
    if (urlPath === '/__loupe/emulator/setup' && req.method === 'POST') {
      if (setupInFlight) return json(res, 200, { ok: true, already: true, progress });
      setup();
      return json(res, 200, { ok: true, started: true });
    }

    // GET /__loupe/emulator/setup/progress — SSE stream
    if (urlPath === '/__loupe/emulator/setup/progress' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'keep-alive', ...NOSNIFF });
      const send = () => {
        res.write(`data: ${JSON.stringify(progress)}\n\n`);
        if (progress.phase === 'done' || (progress.phase === 'error' && !setupInFlight)) {
          clearInterval(iv);
          res.end();
        }
      };
      send();
      const iv = setInterval(send, 1500);
      req.on('close', () => clearInterval(iv));
      return;
    }

    // GET /__loupe/emulator/avds
    if (urlPath === '/__loupe/emulator/avds' && req.method === 'GET') {
      return json(res, 200, { ok: true, avds: await listAvds() });
    }

    // POST /__loupe/emulator/avd — create AVD
    if (urlPath === '/__loupe/emulator/avd' && req.method === 'POST') {
      const body = await readJson(req);
      const result = await createAvd(body.name, body.image);
      return json(res, 200, result);
    }

    // DELETE /__loupe/emulator/avd?name=X
    if (urlPath === '/__loupe/emulator/avd' && req.method === 'DELETE') {
      const u = new URL(req.url, 'http://x');
      const name = u.searchParams.get('name');
      if (!name) throw new HttpErr(400, 'name required');
      const result = await deleteAvd(name);
      return json(res, 200, result);
    }

    // POST /__loupe/emulator/start
    if (urlPath === '/__loupe/emulator/start' && req.method === 'POST') {
      const body = await readJson(req);
      const result = await startEmulator(body.name);
      return json(res, 200, result);
    }

    // POST /__loupe/emulator/stop
    if (urlPath === '/__loupe/emulator/stop' && req.method === 'POST') {
      const body = await readJson(req);
      const result = await stopEmulator(body.name);
      return json(res, 200, result);
    }

    // POST /__loupe/emulator/connect — connect a running emulator to ADB for Loupe
    if (urlPath === '/__loupe/emulator/connect' && req.method === 'POST') {
      const body = await readJson(req);
      const name = body.name || DEFAULT_AVD;
      const info = emulatorProcs.get(name);
      if (!info) throw new HttpErr(400, 'emulator not running');
      const serial = `emulator-${info.port}`;
      // Ensure ADB knows about it
      const { out } = await adbCli(['devices']);
      const online = out.includes(serial) && out.includes('device');
      if (!online) throw new HttpErr(400, `emulator ${serial} not yet online — wait for boot`);
      // Enable root
      await adbCli(['-s', serial, 'root']);
      await new Promise((r) => setTimeout(r, 1000));
      await adbCli(['-s', serial, 'shell', 'setenforce', '0']);
      // Connect via ADB TCP for Loupe's wireless transport
      const { out: fwd } = await adbCli(['-s', serial, 'shell', 'getprop', 'ro.product.model']);
      return json(res, 200, { ok: true, serial, model: fwd.trim() || 'Android Emulator', rooted: true });
    }

    json(res, 404, { ok: false, error: 'unknown emulator endpoint' });
  } catch (e) {
    const status = e instanceof HttpErr ? e.status : 500;
    json(res, status, { ok: false, error: e.message, ...((e instanceof HttpErr) ? e.extra : {}) });
  }
}
