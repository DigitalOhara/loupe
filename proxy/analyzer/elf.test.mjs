import test from 'node:test';
import assert from 'node:assert/strict';
import { parseElf } from './elf.js';
import { elf64 } from './testkit.mjs';

test('reads NX, RELRO, BIND_NOW and the canary import', () => {
  const clean = { pie: true, rpath: false, stripped: true, fortify: true, dangerous: [] };
  assert.deepEqual(parseElf(elf64()), { is64: true, nx: true, relro: 'full', canary: true, ...clean });
  assert.deepEqual(parseElf(elf64({ stackFlags: 7, relro: false, bindNow: false, canary: false })), { is64: true, nx: false, relro: 'none', canary: false, ...clean });
  assert.equal(parseElf(elf64({ bindNow: false })).relro, 'partial');
});

test('rejects non-ELF, big-endian and corrupt headers', () => {
  assert.ok(parseElf(Buffer.alloc(100)).error);
  const be = elf64(); be[5] = 2;
  assert.match(parseElf(be).error, /big-endian/);
  const bad = elf64(); bad.writeUInt16LE(60000, 56);
  assert.match(parseElf(bad).error, /corrupt/);
  assert.ok(parseElf(elf64().subarray(0, 40)).error);
});

test('reads PIE, unfortified copies and an unstripped symbol table', () => {
  const exec = elf64(); exec.writeUInt16LE(2, 16);
  assert.equal(parseElf(exec).pie, false);
  const withStr = (s) => Buffer.concat([elf64(), Buffer.from(s, 'latin1')]);
  assert.equal(parseElf(withStr('\0strcpy\0')).fortify, false);
  assert.equal(parseElf(withStr('\0strcpy\0__strcpy_chk\0')).fortify, true);
  assert.equal(parseElf(withStr('\0.symtab\0')).stripped, false);
});
