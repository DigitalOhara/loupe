/** Effective cleartext policy and user-CA trust, resolved from the manifest, the network security config and the target SDK. */
import { finding, sourceEv, manifestEv, nscEv } from '../evidence.js';

const cleartext = {
  id: 'network.cleartext', title: 'Cleartext traffic allowed', category: 'NETWORK', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, nsc = model.nsc;
    if (model.nscError) return { inconclusive: `the network security config could not be read: ${model.nscError}` };
    if (m.targetSdk === null) return { inconclusive: 'the manifest declares no SDK version, so the platform default is unknown' };
    const findings = [];
    let base, ev, how;
    if (nsc?.base?.cleartext) { base = nsc.base.cleartext === 'true'; ev = nscEv(model, nsc.base, `cleartextTrafficPermitted="${nsc.base.cleartext}"`); how = 'the network security config base-config'; }
    else if (!nsc && m.app?.usesCleartextTraffic) { base = m.app.usesCleartextTraffic === 'true'; ev = manifestEv(model, m.app, `android:usesCleartextTraffic="${m.app.usesCleartextTraffic}"`); how = 'android:usesCleartextTraffic'; }
    else { base = m.targetSdk < 28; ev = manifestEv(model, m.sdk || m.app, `targetSdkVersion ${m.targetSdk}: cleartext is ${base ? 'allowed' : 'blocked'} by default`); how = `the platform default for targetSdkVersion ${m.targetSdk}`; }
    if (base) {
      findings.push(finding('network.cleartext', {
        key: 'base', severity: 'medium', detection: 'exact', conclusion: 'exposure',
        summary: `Plain HTTP is permitted for every host (${how}). A network attacker can read or change any traffic the app sends over plain HTTP.`,
        evidence: [ev], repro: { steps: ['Run a dynamic session and check the socket table for connections to port 80, or open the evidence location.'], command: [] }
      }));
    }
    for (const d of nsc?.domains || []) {
      if (d.cleartext !== 'true') continue;
      findings.push(finding('network.cleartext', {
        key: `domain:${d.domains.join(',')}`, title: `Cleartext allowed for ${d.domains.join(', ') || 'some domains'}`, severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `The network security config allows plain HTTP for ${d.domains.join(', ') || 'a domain list'}. A network attacker can read or change traffic the app sends to those hosts over plain HTTP.`,
        evidence: [nscEv(model, d, 'cleartextTrafficPermitted="true"')], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

const userCa = {
  id: 'network.user-ca', title: 'User-installed CAs are trusted', category: 'NETWORK', needs: ['manifest'],
  run({ model }) {
    const m = model.manifest, nsc = model.nsc;
    if (model.nscError) return { inconclusive: `the network security config could not be read: ${model.nscError}` };
    const findings = [];
    // debug-overrides only apply when the app is debuggable, which is when they matter
    for (const cfg of [nsc?.base, ...(nsc?.domains || []), m.app?.debuggable === 'true' ? nsc?.debug : null]) {
      if (!cfg?.anchors.includes('user')) continue;
      const bypass = cfg.overridePins.includes('user');
      findings.push(finding('network.user-ca', {
        key: `nsc:${cfg === nsc.debug ? 'debug' : cfg.domains?.join(',') || 'base'}`, severity: bypass ? 'high' : 'medium', detection: 'exact', conclusion: 'weakness',
        summary: `The network security config trusts certificates the user installs${cfg === nsc.debug ? ' (in debug-overrides, and the app is debuggable)' : ''}. Anyone who can add a CA to the device can intercept this app's TLS.${bypass ? ' overridePins="true" also lets that CA skip certificate pinning.' : ''}`,
        evidence: [nscEv(model, cfg, bypass ? 'overridePins' : '<certificates src="user" />')], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    const explicit = !!(nsc?.base?.anchors.length);
    if (!findings.length && !explicit && m.targetSdk !== null && m.targetSdk < 24) {
      findings.push(finding('network.user-ca', {
        key: 'platform-default', severity: 'low', detection: 'exact', conclusion: 'exposure',
        summary: `targetSdkVersion ${m.targetSdk} is below 24, so Android trusts user-installed CAs for this app by default. Anyone who can add a CA to the device can intercept the app's TLS.`,
        evidence: [manifestEv(model, m.sdk || m.app, `targetSdkVersion ${m.targetSdk}`)], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

const expiredPins = {
  id: 'network.expired-pins', title: 'Certificate pin set has expired', category: 'NETWORK', needs: ['manifest'],
  run({ model }) {
    if (model.nscError) return { inconclusive: `the network security config could not be read: ${model.nscError}` };
    const findings = [], now = Date.now();
    for (const p of model.nsc?.pins || []) {
      const t = p.expiration && /^\d{4}-\d{2}-\d{2}$/.test(p.expiration) ? Date.parse(p.expiration) : NaN;
      if (!(t < now)) continue;
      findings.push(finding('network.expired-pins', {
        key: p.expiration, severity: 'medium', detection: 'exact', conclusion: 'weakness',
        summary: `A pin-set expired on ${p.expiration}. After that date Android stops enforcing the pins, so certificate pinning no longer protects this app.`,
        evidence: [nscEv(model, p, `expiration="${p.expiration}"`)], repro: { steps: ['Open the evidence location.'], command: [] }
      }));
    }
    return { findings };
  }
};

// Cordova and Capacitor apps list the origins their WebView may load in res/xml/config.xml.
const cordova = {
  id: 'network.cordova-allowlist', title: 'Hybrid app WebView allows any origin', category: 'PLATFORM', needs: ['manifest'],
  async run({ input }) {
    const text = await input.read('resources/res/xml/config.xml');
    if (text === null || !/<widget\b/.test(text)) return { notApplicable: 'no Cordova config.xml' };
    const findings = [];
    for (const m of text.matchAll(/<(?:access\s+origin|allow-navigation\s+href|allow-intent\s+href)="\*"/g)) {
      findings.push(finding('network.cordova-allowlist', {
        key: m[0], title: `Wildcard ${m[0].slice(1).split(/\s/)[0]}`, severity: 'medium', detection: 'exact', conclusion: 'weakness',
        summary: `The Cordova config.xml contains ${m[0]}...>, a wildcard origin. The app's WebView, which can call native plugins, will load or talk to any origin. A link or injected script can then bring in attacker content with plugin access.`,
        evidence: [sourceEv('resources/res/xml/config.xml', text, m.index, 'wildcard origin')], repro: { steps: ['Open res/xml/config.xml in the Decompiler.'], command: [] }
      }));
    }
    return { findings };
  }
};

export default [cleartext, userCa, expiredPins, cordova];
