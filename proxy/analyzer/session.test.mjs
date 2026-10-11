import test from 'node:test';
import assert from 'node:assert/strict';
import { CONTENT_BUDGET, parseProcNet, parseLogLine, parseSnapshot, snapshotScript, quote, PKG, COMPONENT, DEEPLINK } from '../../src/lib/sessionParse.js';

test('parseProcNet reads the IPv4-mapped rows a real phone prints in tcp6', () => {
  const row = (rem, uid) => `   9: 0000000000000000FFFF0000CA00A8C0:8FD2 ${rem} 01 000000E7:00000000 01:00000015 00000000 ${uid}        0 1102866 2 0000000000000000 22 0 0 10 7`;
  assert.deepEqual(parseProcNet(row('0000000000000000FFFF0000CC00A8C0:1F90', 10293), 10293), [{ remote: '192.168.0.204:8080', state: 'ESTABLISHED' }]);
  assert.deepEqual(parseProcNet(row('0000000000000000FFFF00000100007F:9827', 10293), 10293), [{ remote: '127.0.0.1:38951', state: 'ESTABLISHED' }]);
  assert.deepEqual(parseProcNet(row('00000000000000000000000000000000:0000', 10293), 10293), []);
});

test('parseProcNet reads IPv4, IPv4-mapped IPv6 and IPv6, for one uid, with listeners by their local address', () => {
  const text = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 1 1 0
   1: C900A8C0:D2F4 2900A8C0:0050 01 00000000:00000000 00:00000000 00000000 10123        0 2 1 0
   2: C900A8C0:D2F5 08080808:01BB 06 00000000:00000000 00:00000000 00000000 10123        0 3 1 0
   3: C900A8C0:D2F6 08080808:0050 01 00000000:00000000 00:00000000 00000000 999        0 4 1 0
   4: 0000000000000000FFFF0000C900A8C0:D2F7 0000000000000000FFFF000029 0A 0 0 0 0 10123 0 5`;
  assert.deepEqual(parseProcNet(text, 10123), [{ remote: '127.0.0.1:27042', state: 'LISTEN' }, { remote: '192.168.0.41:80', state: 'ESTABLISHED' }, { remote: '8.8.8.8:443', state: 'TIME_WAIT' }]);
  const v6 = '   0: 00000000000000000000000001000000:D2F4 B80D0120000000000000000001000000:01BB 01 0:0 00:0 0 10123 0 1 1 0';
  assert.deepEqual(parseProcNet(v6, 10123), [{ remote: '[2001:db8:0:0:0:0:0:1]:443', state: 'ESTABLISHED' }]);
  assert.deepEqual(parseProcNet('garbage\n\n', 1), []);
});

test('parseLogLine reads threadtime with epoch and skips banners', () => {
  assert.deepEqual(parseLogLine('         1791602936.539  4372  8930 I android.system.suspend-service: !@SystemSuspend: write mem-'), { t: 1791602936539, pid: 4372, level: 'I', tag: 'android.system.suspend-service', msg: '!@SystemSuspend: write mem-' });
  assert.deepEqual(parseLogLine('1791602936.5  5709  5709 E Tag     : msg: with colon'), { t: 1791602936500, pid: 5709, level: 'E', tag: 'Tag', msg: 'msg: with colon' });
  assert.equal(parseLogLine('--------- beginning of main'), null);
});

const b64 = (s) => Buffer.from(s).toString('base64');

test('parseSnapshot reads files, binaries, folders, matches, totals and errors', () => {
  const text = [`@@F ${b64('./shared_prefs/a b.xml')} 660 12 1700000000 T`, b64('<map>\n  <x/>\n</map>'), `@@F ${b64('./databases/app.db')} 600 4096 1700000001 B`, `@@D 751 ${b64('.')}`, `@@D 771 ${b64('./files')}`, `@@M 0 ${b64('./databases/app.db')}`, '@@N 3 2'].join('\n');
  const s = parseSnapshot(text);
  assert.deepEqual(s.files.map((f) => [f.path, f.mode, f.size, f.text]), [['./shared_prefs/a b.xml', '660', 12, '<map>\n  <x/>\n</map>'], ['./databases/app.db', '600', 4096, null]]);
  assert.deepEqual(s.dirs, [{ path: '.', mode: '751' }, { path: './files', mode: '771' }]);
  assert.deepEqual(s.matches, [{ needle: 0, path: './databases/app.db' }]);
  assert.deepEqual(parseSnapshot(`@@Q ${b64('./databases/app.db')}\n@@N 1 1`).sqlite, ['./databases/app.db']);
  assert.deepEqual([s.total, s.truncated], [3, false]);                                     // the count is only a hint: files appear and vanish while the app runs
  assert.equal(parseSnapshot(text, 2).truncated, true);                                      // a listing that reaches the cap may be cut short
  assert.equal(parseSnapshot('@@ERR cannot enter the folder').error, 'cannot enter the folder');
  assert.equal(parseSnapshot(`@@F ${b64('a')} 600 1 1 T\n${b64('x')}\n@@N 1 1`).truncated, false);               // everything that exists was listed
});

test('a snapshot without exactly one trailer is incomplete, never "no files"', () => {
  for (const text of ['', `@@F ${b64('a')} 600 1 1 T\n${b64('x')}`, '@@N 0 0\n@@N 0 0']) {
    const s = parseSnapshot(text);
    assert.deepEqual([s.complete, s.truncated, s.error !== ''], [false, true, true], JSON.stringify(text));
  }
  const gone = parseSnapshot('@@ERR cannot enter the folder');
  assert.deepEqual([gone.missing, gone.complete, gone.truncated], [true, false, true]);
  assert.deepEqual([parseSnapshot('@@N 0 1').complete, parseSnapshot('@@N 0 1').error], [true, '']);
});

test('an app cannot forge records through file contents or names', () => {
  const evil = '@@F ZmFrZQ== 666 1 1 T\n@@ERR pwned\n@@N 0 0\n@@M 0 ZmFrZQ==';
  const text = [`@@F ${b64('./evil.txt')} 600 9 1 T`, b64(evil), `@@F ${b64('./nl\nname\n@@ERR x')} 600 1 1 B`, '@@N 2 1'].join('\n');
  const s = parseSnapshot(text);
  assert.equal(s.error, '');
  assert.deepEqual([s.files.length, s.matches.length, s.total], [2, 0, 2]);
  assert.equal(s.files[0].text, evil);                                                      // the hostile text is only data
  assert.equal(s.files[1].path, './nl\nname\n@@ERR x');
  // raw (unencoded) hostile lines are ignored, not obeyed
  assert.equal(parseSnapshot('@@ERR from a raw line').error, 'from a raw line');            // only our own script can print this: app bytes are Base64
});

test('snapshotScript encodes app bytes, quotes needles and the directory', () => {
  const s = snapshotScript('/data/data/com.x', ["it's", '$(rm -rf /)']);
  assert.ok(s.includes(`-e 'it'\\''s'`) && s.includes(`-e '$(rm -rf /)'`));
  assert.ok(s.includes("cd '/data/data/com.x'") && s.includes('base64 -w 0'));
  assert.equal(quote("a'b"), `'a'\\''b'`);
});

test('name validators accept real names and refuse anything shell-like', () => {
  assert.ok(PKG.test('com.android.insecurebankv2') && COMPONENT.test('com.x.A$B') && DEEPLINK.test('myapp://open/'));
  for (const bad of ['a b', 'a;b', '$(x)', '']) assert.ok(!PKG.test(bad) && !COMPONENT.test(bad), bad);
  assert.ok(!DEEPLINK.test('myapp://open/?x=1') && !DEEPLINK.test('x://a b/'));
});

test('the snapshot lists every file, and reads content only from small text files', () => {
  const s = snapshotScript('/data/data/com.x');
  assert.ok(!s.includes('-size -64k'), 'big files are listed too, so their modes can be checked');
  assert.ok(s.includes('-lt 65536') && s.includes('grep -Iq'));
});

test('files whose names contain a newline make the snapshot incomplete instead of vanishing', () => {
  const s = snapshotScript('/data/data/com.x');
  assert.ok(s.includes('@@X') && s.includes('-name "*$nl*"'));
  const text = [`@@F ${b64('./a')} 600 1 1 T`, b64('x'), '@@X 2', '@@N 3 1'].join('\n');
  const p = parseSnapshot(text);
  assert.deepEqual([p.unlisted, p.complete, p.truncated], [2, true, true]);
  assert.equal(parseSnapshot(`@@F ${b64('./a')} 600 1 1 T\n${b64('x')}\n@@X 0\n@@N 1 1`).truncated, false);
});

test('the snapshot script has a content byte budget, and a spent budget marks the snapshot truncated', () => {
  assert.ok(snapshotScript('/data/data/x').includes(`-lt ${CONTENT_BUDGET}`));
  assert.ok(CONTENT_BUDGET * 3 < 64 * 1024 ** 2 * 0.75);                                   // before, after and shared storage fit the upload limit with room to spare
  const s = parseSnapshot(`@@F ${b64('a')} 600 1 1 T\n${b64('x')}\n@@F ${b64('b')} 600 1 1 B\n@@B\n@@N 2 1`);
  assert.deepEqual([s.capped, s.truncated, s.complete], [true, true, true]);
});
