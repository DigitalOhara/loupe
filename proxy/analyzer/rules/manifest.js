/** Rules over the parsed manifest. All exact: they report what the manifest says, with the lines that say it. */
import { finding, manifestEv, validPackage } from '../evidence.js';
import { backedUp } from '../model.js';

const COMP = /^[\w.$]+$/;
const KIND_CMD = { activity: ['start', '-n'], service: ['startservice', '-n'], receiver: ['broadcast', '-n'] };

const debuggable = {
  id: 'manifest.debuggable', title: 'App is debuggable', category: 'RESILIENCE', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest;
    if (m.app?.debuggable !== 'true') return { findings: [] };
    return {
      findings: [finding('manifest.debuggable', {
        key: m.package, severity: 'high', detection: 'exact', conclusion: 'exposure',
        summary: 'The app sets android:debuggable to true. Anyone with adb access can attach a debugger and read its private data without root, and can run commands as the app with run-as.',
        evidence: [manifestEv(model, m.app, 'android:debuggable="true"')],
        repro: { steps: ['Install the APK on a device with USB debugging on.', 'Run the command. It runs as the app without root.'], command: validPackage(m.package) ? ['adb', 'shell', 'run-as', m.package, 'id'] : [] }
      })]
    };
  }
};

const exportedComponents = {
  id: 'manifest.exported-components', title: 'Exported component without permission', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, findings = [];
    for (const c of m.components) {
      if (c.kind === 'provider' || !c.exported || c.permission || c.launcher) continue;
      const cmd = KIND_CMD[c.kind];
      findings.push(finding('manifest.exported-components', {
        key: `${c.kind}:${c.name}`, title: `Exported ${c.kind} without permission: ${c.name.split('.').pop()}`,
        severity: c.browsable ? 'low' : 'medium', detection: 'exact', conclusion: 'exposure',
        summary: `${c.name} is an exported ${c.kind} with no permission${c.browsable ? ' that also accepts links from the browser' : ''}. Any app on the device can ${c.kind === 'receiver' ? 'send it an intent' : 'start it with an intent of its choosing'}. What that gives an attacker depends on what the ${c.kind} does with the intent.`,
        evidence: [manifestEv(model, c, c.filters.length ? 'exported by its intent filter' : 'android:exported="true"')],
        repro: { steps: ['Run the command from adb. It runs as the shell user, which is more privileged than an ordinary app, so this shows reachability from the shell only.'], command: validPackage(m.package) && COMP.test(c.name) && cmd ? ['adb', 'shell', 'am', cmd[0], cmd[1], `${m.package}/${c.name}`] : [] }
      }));
    }
    return { findings };
  }
};

const unprotectedProviders = {
  id: 'manifest.exported-provider', title: 'Exported content provider without permission', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, findings = [];
    for (const c of m.components) {
      if (c.kind !== 'provider' || !c.exported) continue;
      // Each direction falls back to android:permission. A direction with no permission at all is open to every app.
      const read = !(c.readPermission ?? c.permission), write = !(c.writePermission ?? c.permission);
      if (!read && !write) continue;
      const authority = (c.authorities || '').split(';')[0], short = c.name.split('.').pop();
      const what = read && write ? 'Exported content provider without permission' : read ? 'Exported content provider readable without permission' : 'Exported content provider writable without permission';
      const query = /^[\w.\-]+$/.test(authority) ? ['adb', 'shell', 'content', 'query', '--uri', `content://${authority}`] : [];
      findings.push(finding('manifest.exported-provider', {
        key: c.name, title: `${what}: ${short}`, severity: 'high', detection: 'exact', conclusion: 'exposure',
        summary: `${c.name} is an exported content provider with ${read && write ? 'no read or write permission' : read ? 'no read permission' : 'no write permission'}. Any app can ${read && write ? 'query and change its data' : read ? 'query its data' : 'insert, update and delete its data'}.${c.grantUriPermissions ? ' The provider also has grantUriPermissions enabled.' : ''}`,
        evidence: [manifestEv(model, c, 'android:exported="true", with no android:permission')],
        repro: read
          ? { steps: ['Run the command from adb to query the provider (read only). Shell privileges exceed an ordinary app, so this shows reachability from the shell.'], command: query }
          : { steps: ['Writes change data, so no command is run for you. From a test app or adb, try `content insert` or `content update` on a path this provider handles, on a device you can reset.'], command: [] }
      }));
    }
    return { findings };
  }
};

// Exact platform permissions by protection level. Anything else under android.permission.* is unresolved (the rule says so), since a prefix is not a
// protection level: BROADCAST_STICKY and MANAGE_ACCOUNTS are normal, BROADCAST_SMS is signature. Only BIND_* is safe by prefix: every one is signature.
const P = (list) => new Set(list.split(/\s+/).filter(Boolean).map((x) => `android.permission.${x}`));
const WEAK_PLATFORM = P(`INTERNET ACCESS_NETWORK_STATE ACCESS_WIFI_STATE BLUETOOTH BLUETOOTH_ADMIN BROADCAST_STICKY CHANGE_NETWORK_STATE CHANGE_WIFI_STATE EXPAND_STATUS_BAR
  FOREGROUND_SERVICE GET_PACKAGE_SIZE KILL_BACKGROUND_PROCESSES MODIFY_AUDIO_SETTINGS NFC READ_SYNC_SETTINGS READ_SYNC_STATS RECEIVE_BOOT_COMPLETED REORDER_TASKS
  REQUEST_INSTALL_PACKAGES SET_ALARM SET_WALLPAPER USE_BIOMETRIC USE_FINGERPRINT VIBRATE WAKE_LOCK WRITE_SYNC_SETTINGS QUERY_ALL_PACKAGES SCHEDULE_EXACT_ALARM MANAGE_ACCOUNTS
  CAMERA RECORD_AUDIO READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS READ_CALENDAR WRITE_CALENDAR ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION
  READ_PHONE_STATE CALL_PHONE READ_CALL_LOG WRITE_CALL_LOG SEND_SMS RECEIVE_SMS READ_SMS READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE BODY_SENSORS POST_NOTIFICATIONS
  READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO BLUETOOTH_CONNECT BLUETOOTH_SCAN BLUETOOTH_ADVERTISE NEARBY_WIFI_DEVICES ACTIVITY_RECOGNITION PROCESS_OUTGOING_CALLS`);
const STRONG_PLATFORM = P('INSTALL_PACKAGES DELETE_PACKAGES WRITE_SECURE_SETTINGS DUMP REBOOT MASTER_CLEAR CAPTURE_AUDIO_OUTPUT BROADCAST_SMS BROADCAST_WAP_PUSH BROADCAST_PACKAGE_REMOVED');
const platformLevel = (name) => (WEAK_PLATFORM.has(name) ? 'weak' : STRONG_PLATFORM.has(name) || /^android\.permission\.BIND_/.test(name) ? 'strong' : null);

const weakPermission = {
  id: 'manifest.weak-permission', title: 'Component guarded by a weak permission', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, findings = [], unresolved = new Set();
    const declared = new Map(m.permissions.map((p) => [p.name, p]));
    for (const c of m.components) {
      if (!c.exported) continue;
      // A provider is judged per direction: the read and write permission may differ, and each falls back to android:permission.
      const wanted = c.kind === 'provider' ? [c.readPermission ?? c.permission, c.writePermission ?? c.permission] : [c.permission];
      for (const name of new Set(wanted.filter(Boolean))) {
        const p = declared.get(name);
        const weak = p ? !/signature/i.test(p.protectionLevel) : platformLevel(name) === 'weak';
        if (!p && !platformLevel(name)) { unresolved.add(name); continue; }
        if (!weak) continue;
        const level = p ? p.protectionLevel : 'normal or dangerous';
        findings.push(finding('manifest.weak-permission', {
          key: `${c.kind}:${c.name}:${name}`, title: `Weak permission on ${c.name.split('.').pop()}`, severity: 'medium', detection: 'exact', conclusion: 'weakness',
          summary: `${c.name} is exported and guarded by ${name}, whose protection level is ${level}${p ? '' : ' (a platform permission)'}. Any app can request a ${level} permission, so it does not restrict who can call the component.`,
          evidence: [manifestEv(model, c, `android:permission="${name}"`), ...(p ? [manifestEv(model, { line: p.line, endLine: p.line }, 'where the permission is declared')] : [])],
          repro: { steps: ['Open the manifest at the component and check the permission\'s protection level.'], command: [] }
        }));
      }
    }
    if (unresolved.size) return { findings, inconclusive: `${[...unresolved].slice(0, 3).join(', ')} guard${unresolved.size === 1 ? 's' : ''} an exported component but ${unresolved.size === 1 ? 'is' : 'are'} not declared here or in the platform list, so their protection level is unknown` };
    return { findings };
  }
};

const backup = {
  id: 'manifest.backup', title: 'Backups are allowed', category: 'STORAGE', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, a = m.app;
    if (!a || a.allowBackup === 'false') return { findings: [] };
    const modern = (m.targetSdk ?? 0) >= 31, debug = a.debuggable === 'true', configured = !!(a.fullBackupContent || a.dataExtractionRules);
    let severity = debug ? 'medium' : modern || configured ? 'low' : 'medium', rulesNote = '';
    if (configured && model.backup) {
      const per = Object.entries(model.backup).map(([name, r]) => [name, backedUp(r)]);
      const bad = per.filter(([, b]) => b.open.length || b.partial.length);
      rulesNote = bad.length ? ` The backup rules still back up: ${bad.map(([n, b]) => `${n}: ${[...b.open, ...b.partial.map((d) => `${d} (only some paths excluded)`)].join(', ')}`).join('; ')}.` : ' The backup rules exclude shared preferences and databases in every context.';
      if (bad.length) severity = 'medium'; else if (!debug) severity = 'low';
    } else if (configured) rulesNote = ' A backup configuration is declared, but it could not be read or understood, so what it excludes is unknown.';
    const note = debug ? ' The app is debuggable, so adb backup can copy its data.' : modern ? ' Cloud and device-to-device backups still copy its data, although apps targeting API 31 or higher are excluded from adb backup unless debuggable.' : ' adb backup can copy its data off the device.';
    return {
      findings: [finding('manifest.backup', {
        key: m.package, severity, detection: 'exact', conclusion: 'exposure',
        summary: `The app allows backups: allowBackup is ${a.allowBackup ?? 'not set, and the default is true'}.${note}${rulesNote}`,
        evidence: [manifestEv(model, a, a.allowBackup ? `android:allowBackup="${a.allowBackup}"` : 'android:allowBackup is not set')],
        repro: { steps: ['Run the command and confirm on the device. It works on apps that allow adb backup.', 'Unpack app.ab to read shared_prefs and databases.'], command: validPackage(m.package) ? ['adb', 'backup', '-f', 'app.ab', m.package] : [] }
      })]
    };
  }
};

const taskAffinity = {
  id: 'manifest.task-affinity', title: 'Activity with a custom task affinity or single-task launch mode', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, findings = [];
    for (const c of m.components) {
      const custom = c.taskAffinity && c.taskAffinity !== m.package, single = /^single(Task|Instance)$/.test(c.launchMode || '');
      if (c.kind !== 'activity' || (!custom && !single)) continue;
      findings.push(finding('manifest.task-affinity', {
        key: c.name, title: `Task hijacking exposure: ${c.name.split('.').pop()}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `${c.name} sets ${custom ? `taskAffinity="${c.taskAffinity}"` : `launchMode="${c.launchMode}"`}. A malicious app can declare the same affinity and have its own screen placed into this app's task (StrandHogg, task hijacking).`,
        evidence: [manifestEv(model, c, custom ? 'android:taskAffinity' : 'android:launchMode')], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

const sdkLevels = {
  id: 'manifest.sdk-levels', title: 'Old minimum or target SDK', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest;
    if (m.minSdk === null && m.targetSdk === null) return { inconclusive: 'the manifest declares no SDK version' };
    const notes = [];
    if (m.targetSdk !== null && m.targetSdk < 28) notes.push([`targetSdkVersion ${m.targetSdk} keeps older platform defaults`, 'Cleartext traffic is allowed, user CAs are trusted below 24, and runtime permission and background limits are skipped.']);
    if (m.minSdk !== null && m.minSdk < 29) notes.push([`minSdkVersion ${m.minSdk} lets the app install on Android 9 and older`, 'Unpatched builds of those versions still have the StrandHogg 2.0 (CVE-2020-0096) task hijacking flaw.']);
    if (!notes.length) return { findings: [] };
    return {
      findings: [finding('manifest.sdk-levels', {
        key: `${m.minSdk}|${m.targetSdk}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `${notes.map((n) => n[0]).join(', and ')}. ${notes.map((n) => n[1]).join(' ')}`,
        evidence: [manifestEv(model, m.sdk || m.app, `minSdkVersion ${m.minSdk}, targetSdkVersion ${m.targetSdk}`)], repro: { steps: ['Open the evidence location.'], command: [] }
      })]
    };
  }
};

const grantUri = {
  id: 'manifest.grant-uri', title: 'Provider grants URI permissions', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const findings = [];
    for (const c of model.manifest.components) {
      if (c.kind !== 'provider' || !c.grantUriPermissions) continue;
      findings.push(finding('manifest.grant-uri', {
        key: c.name, title: `Provider grants URI permissions: ${c.name.split('.').pop()}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `${c.name} sets grantUriPermissions="true". The provider can hand any app temporary access to its data through an Intent.`,
        evidence: [manifestEv(model, c, 'android:grantUriPermissions="true"')], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

const safeBrowsing = {
  id: 'manifest.safe-browsing-off', title: 'WebView Safe Browsing disabled', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const el = model.manifest.app?.safeBrowsingOff;
    if (!el) return { findings: [] };
    return {
      findings: [finding('manifest.safe-browsing-off', {
        key: model.manifest.package, severity: 'low', detection: 'exact', conclusion: 'weakness',
        summary: 'The manifest turns off WebView Safe Browsing. WebViews in the app then show no warning for known malicious pages.',
        evidence: [manifestEv(model, el, 'EnableSafeBrowsing = false')], repro: { steps: ['Open the evidence location.'], command: [] }
      })]
    };
  }
};

const deepLinks = {
  id: 'manifest.deeplinks', title: 'Weakly constrained deep link', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const findings = [];
    for (const c of model.manifest.components) {
      if (c.kind !== 'activity' || !c.exported) continue;
      const reasons = new Set();
      let wild = false;
      for (const f of c.filters) {
        if (!f.categories.includes('android.intent.category.BROWSABLE')) continue;
        for (const d of f.data) {
          if (!d.scheme) continue;
          if (d.scheme === 'http') reasons.add('plain http scheme');
          else if (d.scheme !== 'https') reasons.add(`custom scheme "${d.scheme}", which any other app can also claim`);
          else if (!f.autoVerify) reasons.add('https link without android:autoVerify, so it is not a verified App Link');
          if (d.host && /^\*/.test(d.host)) { reasons.add(`wildcard host "${d.host}"`); wild = true; }
        }
      }
      if (!reasons.size) continue;
      findings.push(finding('manifest.deeplinks', {
        key: c.name, title: `Deep link: ${c.name.split('.').pop()}`, severity: wild || reasons.has('plain http scheme') ? 'medium' : 'low', detection: 'exact', conclusion: 'exposure',
        summary: `${c.name} accepts links from the browser, with these weaknesses: ${[...reasons].join('; ')}. Any web page can open such a link, so the data that reaches the activity is attacker-controlled.`,
        evidence: [manifestEv(model, c, 'BROWSABLE intent filter')], repro: { steps: ['Open the evidence location and check what the activity does with the link data.'], command: [] }
      }));
    }
    return { findings };
  }
};

// Manifest switches that each widen what another app or a person with the device can do. One finding per switch.
const RISKY = [
  ['testOnly', 'Test-only build', (m) => m.app?.attrs['android:testOnly'] === 'true' && m.app, 'android:testOnly', 'medium', 'The app is marked android:testOnly, so this is a test build. Test builds install only with adb install -t and are not meant to ship.'],
  ['sharedUserId', 'Shared user ID', (m) => m.attrs['android:sharedUserId'] && m, 'android:sharedUserId', 'low', 'The app sets android:sharedUserId, so it shares a Linux user ID with other apps signed by the same key. Each of them can read the others\' private files.'],
  ['legacyStorage', 'Legacy external storage', (m) => (m.app?.attrs['android:requestLegacyExternalStorage'] === 'true' || m.app?.attrs['android:preserveLegacyExternalStorage'] === 'true') && m.app, 'LegacyExternalStorage', 'low', 'The app opts out of scoped storage. On Android 10 it keeps the old shared-storage model, so files it writes there are readable by any app with the storage permission.'],
  ['taskReparenting', 'Task reparenting allowed', (m) => (m.app?.attrs['android:allowTaskReparenting'] === 'true' && m.app) || m.components.find((c) => c.attrs['android:allowTaskReparenting'] === 'true'), 'android:allowTaskReparenting', 'low', 'The manifest sets allowTaskReparenting="true", which lets an activity move into the task of the app that has its affinity. A malicious app can use this to show its own screen in place of this one (task hijacking).'],
  ['secretCode', 'Dialer secret code', (m) => m.components.find((c) => c.filters.some((f) => f.data.some((d) => d.scheme === 'android_secret_code'))), 'android_secret_code', 'low', 'A receiver answers a dialer secret code (*#*#code#*#*). Anyone holding the phone can trigger it, and hidden debug menus are often reached this way.']
];
const riskyAttributes = {
  id: 'manifest.risky-attributes', title: 'Risky manifest setting', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const findings = [];
    for (const [key, label, pick, needle, severity, summary] of RISKY) {
      const el = pick(model.manifest);
      if (!el) continue;
      findings.push(finding('manifest.risky-attributes', {
        key, title: el.kind ? `${label}: ${el.name.split('.').pop()}` : label, severity, detection: 'exact', conclusion: 'exposure',
        summary, evidence: [manifestEv(model, el, needle)], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

// Services and receivers that give an app broad reach over the phone. Each is legitimate in the right product, so the finding says what the app can do, not that it misuses it.
const BIND = (c, perm) => c.permission === `android.permission.${perm}`;
const SENSITIVE = [
  ['accessibility', 'Accessibility service', (m) => m.components.filter((c) => c.kind === 'service' && BIND(c, 'BIND_ACCESSIBILITY_SERVICE')), 'BIND_ACCESSIBILITY_SERVICE', 'medium',
    'The app declares an accessibility service. Such a service can read the text on every screen, see what the user types, and tap and swipe for them. Banking trojans use this to steal credentials and approve their own prompts.'],
  ['notification-listener', 'Notification listener', (m) => m.components.filter((c) => c.kind === 'service' && BIND(c, 'BIND_NOTIFICATION_LISTENER_SERVICE')), 'BIND_NOTIFICATION_LISTENER_SERVICE', 'medium',
    'The app declares a notification listener. Once the user grants access it receives the content of every notification on the phone, including one-time codes and private messages. Malware uses this to intercept two-factor codes.'],
  ['device-admin', 'Device administrator', (m) => m.components.filter((c) => c.kind === 'receiver' && BIND(c, 'BIND_DEVICE_ADMIN')), 'BIND_DEVICE_ADMIN', 'medium',
    'The app registers as a device administrator. An administrator can lock the screen, reset the password and wipe the phone, and it resists being uninstalled. Ransomware and stalkerware rely on these powers.'],
  ['boot', 'Starts at boot', (m) => m.components.filter((c) => c.kind === 'receiver' && c.filters.some((f) => f.actions.some((a) => /BOOT_COMPLETED|QUICKBOOT_POWERON/.test(a)))), 'BOOT_COMPLETED', 'info',
    'A receiver starts the app\'s code every time the phone boots. The app then runs in the background without the user opening it. Persistence like this is normal for messaging apps and common in malware.'],
  ['sms-priority', 'SMS receiver with raised priority', (m) => m.components.filter((c) => c.kind === 'receiver' && c.filters.some((f) => f.actions.includes('android.provider.Telephony.SMS_RECEIVED') && f.priority > 0)), 'android:priority', 'medium',
    'A receiver for incoming SMS sets a raised priority, so it sees each message before lower-priority apps and, for ordered broadcasts, can stop it from reaching them. Apps use this to intercept one-time codes. Since Android 4.4 only the default SMS app can abort the broadcast, but the early read still works.'],
  ['cross-profile', 'Cross-profile access', (m) => [m.app?.attrs['android:crossProfile'] === 'true' && m.app, ...m.components.filter((c) => c.attrs?.['android:crossProfile'] === 'true'), ...m.uses.filter((u) => u.name === 'android.permission.INTERACT_ACROSS_PROFILES')].filter(Boolean), 'crossProfile', 'low',
    'The app allows its personal and work-profile instances to talk to each other, through crossProfile or INTERACT_ACROSS_PROFILES. That breaks the separation between work data and personal apps. A flaw in the exchange can leak corporate data into the personal side.']
];
const sensitiveServices = {
  id: 'manifest.sensitive-services', title: 'App holds a broad system capability', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const findings = [];
    for (const [key, label, pick, needle, severity, summary] of SENSITIVE) {
      for (const el of pick(model.manifest)) {
        findings.push(finding('manifest.sensitive-services', {
          key: `${key}|${el.name || el.name === '' ? el.name : model.manifest.package}`, title: el.name && el.kind ? `${label}: ${el.name.split('.').pop()}` : label, severity, detection: 'exact', conclusion: 'exposure',
          summary, evidence: [manifestEv(model, el, needle)], repro: { steps: ['Open the evidence location.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

// Behavior changes that apply to apps targeting Android 14 (API 34) and later.
const android14 = {
  id: 'manifest.android14-requirements', title: 'Manifest does not meet Android 14 requirements', category: 'PLATFORM', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, findings = [];
    const fg = m.uses.some((u) => /FOREGROUND_SERVICE$/.test(u.name));
    for (const c of m.components) {
      if (c.kind === 'service' && fg && m.targetSdk >= 34 && !c.attrs?.['android:foregroundServiceType'] && !/^android\.permission\.BIND_/.test(c.permission || '')) {
        findings.push(finding('manifest.android14-requirements', {
          key: `fgs|${c.name}`, title: `Service without foregroundServiceType: ${c.name.split('.').pop()}`, severity: 'low', detection: 'heuristic', conclusion: 'weakness',
          summary: `The app targets Android 14 and requests FOREGROUND_SERVICE, but ${c.name} declares no android:foregroundServiceType. If it runs in the foreground, Android 14 throws a SecurityException when it starts. The type also tells the system and the user why the service holds the phone awake.`,
          evidence: [manifestEv(model, c, '<service')], repro: { steps: ['Open the evidence location.'], command: [] }
        }));
      }
      if (c.kind !== 'provider' && c.filters.some((f) => !f.actions.length)) {
        findings.push(finding('manifest.android14-requirements', {
          key: `noaction|${c.name}`, title: `Intent filter without an action: ${c.name.split('.').pop()}`, severity: 'low', detection: 'exact', conclusion: 'weakness',
          summary: `${c.name} has an intent filter with no action. Android 14 does not match such a filter for implicit intents, so the component may be unreachable for the callers it was written for. A filter that matches nothing also hides what the component is meant to accept.`,
          evidence: [manifestEv(model, c, '<intent-filter')], repro: { steps: ['Open the evidence location.'], command: [] }
        }));
      }
    }
    return { findings };
  }
};

export default [debuggable, exportedComponents, unprotectedProviders, weakPermission, backup, taskAffinity, sdkLevels, grantUri, safeBrowsing, deepLinks, riskyAttributes, sensitiveServices, android14];
