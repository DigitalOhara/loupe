import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openInput } from './files.js';
import { entry } from './testkit.mjs';

const collect = async (it) => { const out = []; for await (const f of it) out.push(f.rel); return out.sort(); };

test('walk yields text files and skips other extensions', async () => {
  const input = openInput(entry({ 'sources/A.java': 'a', 'sources/b/B.java': 'b', 'sources/c.bin': 'x' }));
  assert.deepEqual(await collect(input.walk('sources', /\.java$/)), ['sources/A.java', 'sources/b/B.java']);
  assert.equal(input.stats.examined, 2);
});

test('paths that escape out/ are refused', async () => {
  const input = openInput(entry({ 'resources/a.xml': '<a/>' }));
  for (const rel of ['../meta.json', '/etc/passwd', 'a/../../x', 'a\0b']) assert.equal(await input.read(rel), null, rel);
  assert.equal(await input.read('resources/a.xml'), '<a/>');
});

test('symlinks are never followed', async () => {
  const dir = entry({ 'sources/real.java': 'ok' });
  const secret = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'loupe-az-s-')), 'secret.java');
  fs.writeFileSync(secret, 'SECRET');
  fs.symlinkSync(secret, path.join(dir, 'out/sources/link.java'));
  fs.symlinkSync(path.dirname(secret), path.join(dir, 'out/sources/linkdir'));
  const input = openInput(dir);
  assert.deepEqual(await collect(input.walk('sources', /\.java$/)), ['sources/real.java']);
  assert.equal(await input.read('sources/link.java'), null);
  assert.equal(await input.read('sources/linkdir/secret.java'), null);
});

test('oversize files are skipped and counted', async () => {
  const input = openInput(entry({ 'sources/Big.java': 'x'.repeat(100), 'sources/S.java': 'y' }), { maxFileBytes: 50 });
  assert.deepEqual(await collect(input.walk('sources', /\.java$/)), ['sources/S.java']);
  assert.equal(input.stats.skipped, 1);
});

test('a spent budget stops the walk and marks the input truncated', async () => {
  const files = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`sources/F${i}.java`, 'x']));
  const input = openInput(entry(files), { maxFiles: 5 });
  const got = await collect(input.walk('sources', /\.java$/));
  assert.ok(got.length < 20);
  assert.equal(input.stats.truncated, true);
});
