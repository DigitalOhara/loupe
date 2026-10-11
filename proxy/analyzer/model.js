/**
 * The parsed facts the rules reason about: the manifest (components, intent filters, permissions, SDK levels) and the
 * network security config, each with line ranges for evidence. Parsing is strict (see xml.js). Nothing here guesses:
 * a value that is absent stays null, and the rules decide what the platform default means for the target SDK.
 */
import { parseXml, XmlError } from './xml.js';

const A = (el, n) => el?.attrs[`android:${n}`] ?? null;
const int = (v) => (v && /^\d+$/.test(v) ? Number(v) : null);
const KINDS = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider']);

/**
 * Android merges every <data> element of one intent filter: a URI matches when its scheme is in the filter's schemes and its host is in its hosts
 * (a host only counts with a scheme). So the elements are combined here, not read one by one.
 */
function filterOf(el) {
  const names = (tag) => el.children.filter((c) => c.name === tag).map((c) => A(c, 'name')).filter(Boolean);
  const data = el.children.filter((c) => c.name === 'data');
  const uniq = (k) => [...new Set(data.map((d) => A(d, k)).filter(Boolean))];
  const schemes = uniq('scheme'), hosts = uniq('host');
  const path = data.some((d) => ['path', 'pathPrefix', 'pathPattern', 'pathAdvancedPattern', 'pathSuffix'].some((k) => A(d, k)));
  return {
    actions: names('action'), categories: names('category'), autoVerify: A(el, 'autoVerify') === 'true', priority: int(A(el, 'priority')) ?? (A(el, 'priority') ? Number(A(el, 'priority')) : null),
    data: schemes.flatMap((scheme) => (hosts.length ? hosts : [null]).map((host) => ({ scheme, host, path })))
  };
}

/** What the component's `exported` attribute means on the target SDK (a provider is exported by default only up to API 16). */
export function isExported(kind, attr, hasFilter, targetSdk) {
  if (attr === 'true') return true;
  if (attr === 'false') return false;
  return kind === 'provider' ? targetSdk !== null && targetSdk <= 16 : hasFilter;
}

export function parseManifest(text) {
  const root = parseXml(text);
  if (root.name !== 'manifest') throw new XmlError('not an AndroidManifest');
  const pkg = root.attrs.package || '';
  const sdk = root.children.find((c) => c.name === 'uses-sdk') || null;
  const app = root.children.find((c) => c.name === 'application') || null;
  const targetSdk = int(A(sdk, 'targetSdkVersion')) ?? int(A(sdk, 'minSdkVersion'));
  const fq = (n) => (!n ? '' : n.startsWith('.') ? pkg + n : n.includes('.') ? n : `${pkg}.${n}`);
  const appPermission = A(app, 'permission');

  const components = [];
  for (const el of app?.children || []) {
    if (!KINDS.has(el.name)) continue;
    const filters = el.children.filter((c) => c.name === 'intent-filter').map(filterOf);
    const kind = el.name === 'activity-alias' ? 'activity' : el.name;
    components.push({
      kind, name: fq(A(el, 'name')), line: el.line, endLine: el.endLine, filters,
      exported: isExported(kind, A(el, 'exported'), filters.length > 0, targetSdk),
      permission: A(el, 'permission') ?? appPermission,
      authorities: A(el, 'authorities'), readPermission: A(el, 'readPermission'), writePermission: A(el, 'writePermission'),
      grantUriPermissions: A(el, 'grantUriPermissions') === 'true', taskAffinity: A(el, 'taskAffinity'), launchMode: A(el, 'launchMode'),
      launcher: filters.some((f) => f.actions.includes('android.intent.action.MAIN') && f.categories.includes('android.intent.category.LAUNCHER')),
      browsable: filters.some((f) => f.categories.includes('android.intent.category.BROWSABLE')), attrs: el.attrs
    });
  }
  return {
    package: pkg, attrs: root.attrs, line: root.line, endLine: root.endLine, minSdk: int(A(sdk, 'minSdkVersion')), targetSdk,
    sdk: sdk && { line: sdk.line, endLine: sdk.endLine },
    app: app && {
      line: app.line, endLine: app.endLine, debuggable: A(app, 'debuggable'), allowBackup: A(app, 'allowBackup'),
      usesCleartextTraffic: A(app, 'usesCleartextTraffic'), networkSecurityConfig: A(app, 'networkSecurityConfig'),
      fullBackupContent: A(app, 'fullBackupContent'), dataExtractionRules: A(app, 'dataExtractionRules'),
      attrs: app.attrs, safeBrowsingOff: app.children.find((c) => c.name === 'meta-data' && A(c, 'name') === 'android.webkit.WebView.EnableSafeBrowsing' && A(c, 'value') === 'false') || null
    },
    components,
    uses: root.children.filter((c) => /^uses-permission/.test(c.name) && A(c, 'name')).map((u) => ({ name: A(u, 'name'), line: u.line, endLine: u.endLine })),
    permissions: root.children.filter((c) => c.name === 'permission').map((p) => ({ name: A(p, 'name'), protectionLevel: A(p, 'protectionLevel') || 'normal', line: p.line }))
  };
}

/** `<network-security-config>`: base and per-domain cleartext and trust anchors, plus debug-overrides. */
export function parseNsc(text) {
  const root = parseXml(text);
  if (root.name !== 'network-security-config') throw new XmlError('not a network security config');
  const anchors = (el) => (el.children.find((c) => c.name === 'trust-anchors')?.children || []).filter((c) => c.name === 'certificates').map((c) => c.attrs.src || '');
  const cfgOf = (el) => ({
    line: el.line, endLine: el.endLine, cleartext: el.attrs.cleartextTrafficPermitted ?? null, anchors: anchors(el),
    overridePins: (el.children.find((c) => c.name === 'trust-anchors')?.children || []).filter((c) => c.name === 'certificates' && c.attrs.overridePins === 'true').map((c) => c.attrs.src || ''),
    domains: el.children.filter((c) => c.name === 'domain').map((d) => d.text.trim()).filter(Boolean)
  });
  const base = root.children.find((c) => c.name === 'base-config');
  const debug = root.children.find((c) => c.name === 'debug-overrides');
  const domains = [];
  const collect = (el) => { for (const c of el.children) if (c.name === 'domain-config') { domains.push(cfgOf(c)); collect(c); } };
  collect(root);
  const pins = [];                                              // <pin-set expiration="yyyy-mm-dd"> anywhere in the config
  const walk = (el) => { for (const c of el.children) { if (c.name === 'pin-set') pins.push({ expiration: c.attrs.expiration || null, line: c.line, endLine: c.endLine }); walk(c); } };
  walk(root);
  return { base: base ? cfgOf(base) : null, debug: debug ? cfgOf(debug) : null, domains, pins };
}

/** Reads and parses the manifest and the config it references. A parse failure is kept as an error string, not thrown. */
export async function buildModel(input) {
  const out = { manifest: null, manifestLines: [], manifestError: null, nsc: null, nscLines: [], nscPath: null, nscError: null };
  const text = await input.read('resources/AndroidManifest.xml', 4 * 1024 ** 2);
  if (text === null) { out.manifestError = 'AndroidManifest.xml was not found or is too large'; return out; }
  out.manifestLines = text.split('\n');
  try { out.manifest = parseManifest(text); } catch (e) { out.manifestError = e.message; return out; }
  const ref = /^@xml\/([\w.]+)$/.exec(out.manifest.app?.networkSecurityConfig || '');
  if (out.manifest.app?.networkSecurityConfig && !ref) out.nscError = 'the network security config reference is not an @xml resource';
  if (ref) {
    out.nscPath = `resources/res/xml/${ref[1]}.xml`;
    // aapt2 may keep qualified variants (res/xml-v24/...). Which one a device uses depends on its API level, which Loupe does not resolve.
    const variants = [];
    for (const d of (await input.list('resources/res')) || []) if (/^xml-/.test(d) && (await input.exists(`resources/res/${d}/${ref[1]}.xml`))) variants.push(d);
    const nsc = await input.read(out.nscPath);
    if (nsc === null) out.nscError = `${out.nscPath} was not found`;
    else if (variants.length) out.nscError = `the config has resource-qualified variants (${variants.slice(0, 3).join(', ')}) and Loupe does not resolve which one a device uses`;
    else { out.nscLines = nsc.split('\n'); try { out.nsc = parseNsc(nsc); } catch (e) { out.nscError = e.message; } }
  }
  // The backup rules the manifest points at, parsed per format. null: none declared, or one could not be read or understood.
  out.backup = await backupPolicy(input, out.manifest.app);
  return out;
}

/** Include and exclude rules of a backup XML section: [{ domain, path }]. */
const rulesOf = (el) => {
  const get = (tag) => el.children.filter((c) => c.name === tag).map((c) => ({ domain: c.attrs.domain || '', path: c.attrs.path || '' }));
  return { include: get('include'), exclude: get('exclude') };
};

/**
 * What the backup rules leave backed up, per context. `fullBackupContent` (API 30 and lower) is one context; `dataExtractionRules` (API 31+) has
 * cloud-backup and device-transfer, and a missing section means everything is backed up. Domains are independent (`root` does not cover
 * `sharedpref`), a bare exclude covers its whole domain, and any include turns the context into an allowlist.
 */
export async function backupPolicy(input, app) {
  const contexts = {};
  for (const [attr, format] of [[app?.fullBackupContent, 'full'], [app?.dataExtractionRules, 'extraction']]) {
    if (!attr) continue;
    const ref = /^@xml\/([\w.]+)$/.exec(attr);
    const text = ref ? await input.read(`resources/res/xml/${ref[1]}.xml`) : null;
    if (text === null) return null;
    let root;
    try { root = parseXml(text); } catch { return null; }
    if (format === 'full') { if (root.name !== 'full-backup-content') return null; contexts['full-backup-content'] = rulesOf(root); }
    else {
      if (root.name !== 'data-extraction-rules') return null;
      for (const name of ['cloud-backup', 'device-transfer']) { const sec = root.children.find((c) => c.name === name); contexts[name] = sec ? rulesOf(sec) : { include: [], exclude: [] }; }
    }
  }
  return Object.keys(contexts).length ? contexts : null;
}

/** The domains in `check` that this context still backs up, and those it only partly excludes. */
export function backedUp({ include, exclude }, check = ['sharedpref', 'database']) {
  const whole = (r) => !r.path || r.path === '.' || r.path === '/';
  const open = [], partial = [];
  for (const d of check) {
    if (include.length ? !include.some((r) => r.domain === d) : exclude.some((r) => r.domain === d && whole(r))) continue;
    (include.length || !exclude.some((r) => r.domain === d) ? open : partial).push(d);
  }
  return { open, partial };
}
