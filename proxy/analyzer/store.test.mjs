import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.LOUPE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'loupe-az-home-'));
const { saveScan, latestScan } = await import('./store.js');
test.after(() => fs.rmSync(process.env.LOUPE_HOME, { recursive: true, force: true }));

const A = 'a'.repeat(64), B = 'b'.repeat(64);
const scan = (n, art = A) => ({ scanId: `s${n}`, artifactId: art, startedAt: 1000 + n, outcomes: [] });
const mode = (p) => fs.statSync(p).mode & 0o777;

test('saves and reads back the latest scan', async () => {
  await saveScan(scan(1)); await saveScan(scan(2));
  assert.equal((await latestScan(A)).scanId, 's2');
  assert.equal(await latestScan(B), null);
});

test('files are private', async () => {
  await saveScan(scan(1, B));
  const dir = path.join(process.env.LOUPE_HOME, 'analyzer', B);
  assert.equal(mode(dir), 0o700);
  assert.equal(mode(path.join(dir, 'latest.json')), 0o600);
});

test('a bad artifact id is refused', async () => {
  await assert.rejects(() => saveScan(scan(1, '../x')), TypeError);
  await assert.rejects(() => latestScan('nope'), TypeError);
});
