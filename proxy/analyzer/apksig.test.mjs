import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { certificates, blockCertificates } from './apksig.js';

test('garbage and truncated input yield no certificates and never throw', () => {
  assert.deepEqual(certificates(Buffer.alloc(4096)), []);
  assert.deepEqual(blockCertificates(Buffer.from('x'.repeat(2000))), []);
  const fake = Buffer.alloc(3000); fake.writeUInt32LE(0x06054b50, 2900); fake.writeUInt32LE(2000, 2916);
  assert.deepEqual(blockCertificates(fake), []);
});

test('a real signed APK reports its certificate algorithm and key size', (t) => {
  const dir = path.join(os.homedir(), '.loupe', 'decompiled');
  const apk = fs.existsSync(dir) && fs.readdirSync(dir).map((d) => path.join(dir, d, 'in', 'base.apk')).find((f) => fs.existsSync(f));
  if (!apk) return t.skip('no decompiled APK on this machine');
  const [c] = certificates(fs.readFileSync(apk));
  assert.match(c.sigAlg, /^(?:MD5|SHA\d+)with|RSASSA/);
  assert.ok(c.keyBits >= 512 || c.curve);
});
