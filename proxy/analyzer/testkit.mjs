// Test helpers: a fake decompile cache entry on disk. Not a test file (the runner globs *.test.mjs).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** A stored (uncompressed) zip. The analyzer's zip reader checks sizes and offsets but not CRCs. */
export function zipStored(files) {
  const locals = [], central = [];
  let off = 0;
  for (const [name, data] of Object.entries(files)) {
    const n = Buffer.from(name), d = Buffer.from(data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(n.length, 26); lh.writeUInt32LE(d.length, 18); lh.writeUInt32LE(d.length, 22);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt32LE(d.length, 20); ch.writeUInt32LE(d.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, n, d); central.push(ch, n);
    off += 30 + n.length + d.length;
  }
  const cd = Buffer.concat(central), eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(Object.keys(files).length, 8); eocd.writeUInt16LE(Object.keys(files).length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

/** A minimal little-endian ELF64 with GNU_STACK, GNU_RELRO and a DYNAMIC segment. */
export function elf64({ stackFlags = 6, relro = true, bindNow = true, canary = true } = {}) {
  const phoff = 64, phnum = 3, dynOff = phoff + phnum * 56, dynEntries = bindNow ? [[24, 0], [0, 0]] : [[0, 0]];
  const buf = Buffer.alloc(dynOff + dynEntries.length * 16 + 64);
  buf.write('\x7fELF', 0, 'latin1'); buf[4] = 2; buf[5] = 1;
  buf.writeBigUInt64LE(BigInt(phoff), 32); buf.writeUInt16LE(56, 54); buf.writeUInt16LE(phnum, 56);
  const ph = (i, type, flags, off = 0, filesz = 0) => { const o = phoff + i * 56; buf.writeUInt32LE(type, o); buf.writeUInt32LE(flags, o + 4); buf.writeBigUInt64LE(BigInt(off), o + 8); buf.writeBigUInt64LE(BigInt(filesz), o + 32); };
  ph(0, 0x6474e551, stackFlags);
  ph(1, relro ? 0x6474e552 : 1, 4);
  ph(2, 2, 6, dynOff, dynEntries.length * 16);
  dynEntries.forEach(([t, v], i) => { buf.writeBigUInt64LE(BigInt(t), dynOff + i * 16); buf.writeBigUInt64LE(BigInt(v), dynOff + i * 16 + 8); });
  if (canary) buf.write('__stack_chk_fail', buf.length - 20, 'latin1');
  return buf;
}

/** { 'resources/AndroidManifest.xml': '...', 'sources/a/B.java': '...' } becomes <dir>/out/<path>; `apk` becomes <dir>/in/base.apk. */
export function entry(files, apk = null) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'loupe-az-'));
  if (apk) { fs.mkdirSync(path.join(dir, 'in')); fs.writeFileSync(path.join(dir, 'in', 'base.apk'), apk); }
  for (const [rel, text] of Object.entries(files)) {
    const f = path.join(dir, 'out', rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, text);
  }
  return dir;
}

export const manifest = ({ app = '', sdk = '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>', body = '', top = '' } = {}) => `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x.app">
    ${sdk}
    ${top}
    <application ${app}>
        ${body}
    </application>
</manifest>`;
