import test from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest, parseNsc, isExported } from './model.js';

const MF = (app, sdk = '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>', extra = '') => `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x.app">
  ${sdk}
  ${extra}
  <application ${app}>
    <activity android:name=".Main"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <activity android:name="Deep"><intent-filter><category android:name="android.intent.category.BROWSABLE"/></intent-filter></activity>
    <provider android:name=".P" android:authorities="a.b;c.d"/>
    <service android:name="com.other.S" android:exported="true" android:permission="com.x.PERM"/>
  </application>
</manifest>`;

test('resolves names, launcher, browsable and effective export', () => {
  const m = parseManifest(MF('android:debuggable="true"'));
  assert.equal(m.package, 'com.x.app');
  assert.deepEqual([m.minSdk, m.targetSdk], [21, 33]);
  const by = Object.fromEntries(m.components.map((c) => [c.name, c]));
  assert.ok(by['com.x.app.Main'].launcher && by['com.x.app.Main'].exported);
  assert.ok(by['com.x.app.Deep'].browsable);
  assert.equal(by['com.x.app.P'].exported, false);          // provider default on targetSdk 33
  assert.equal(by['com.other.S'].permission, 'com.x.PERM');
  assert.equal(m.app.debuggable, 'true');
});

test('isExported follows the platform defaults', () => {
  assert.equal(isExported('provider', null, false, 16), true);
  assert.equal(isExported('provider', null, false, 17), false);
  assert.equal(isExported('service', null, true, 30), true);
  assert.equal(isExported('service', null, false, 30), false);
  assert.equal(isExported('activity', 'false', true, 30), false);
});

test('application-level permission protects components without their own', () => {
  const m = parseManifest(MF('android:permission="com.x.APP"'));
  assert.equal(m.components.find((c) => c.name === 'com.x.app.P').permission, 'com.x.APP');
});

test('falls back to minSdk when targetSdk is absent and reports permissions', () => {
  const m = parseManifest(MF('', '<uses-sdk android:minSdkVersion="19"/>', '<permission android:name="com.x.PERM" android:protectionLevel="signature"/>'));
  assert.equal(m.targetSdk, 19);
  assert.deepEqual(m.permissions.map((p) => [p.name, p.protectionLevel]), [['com.x.PERM', 'signature']]);
});

test('parseNsc reads base, domains and debug overrides', () => {
  const n = parseNsc(`<network-security-config>
    <base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config>
    <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">example.com</domain><pin-set/></domain-config>
    <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
  </network-security-config>`);
  assert.equal(n.base.cleartext, 'false');
  assert.deepEqual(n.base.anchors, ['system', 'user']);
  assert.deepEqual([n.domains[0].domains, n.domains[0].cleartext], [['example.com'], 'true']);
  assert.deepEqual(n.debug.anchors, ['user']);
});
