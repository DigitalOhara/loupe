/** Header-level hardening facts from a native library. Hostile input: every offset is bounds-checked, nothing is executed. */
const PT_DYNAMIC = 2, PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552;
const DT_RPATH = 15, DT_RUNPATH = 29, DT_BIND_NOW = 24, DT_FLAGS = 30, DT_FLAGS_1 = 0x6ffffffb;

export function parseElf(buf) {
  if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7f454c46) return { error: 'not an ELF file' };
  if (buf[5] !== 1) return { error: 'big-endian ELF is not supported' };
  const is64 = buf[4] === 2;
  const u16 = (o) => buf.readUInt16LE(o), u32 = (o) => buf.readUInt32LE(o), u64 = (o) => Number(buf.readBigUInt64LE(o));
  const phoff = is64 ? u64(32) : u32(28), size = is64 ? u16(54) : u16(42), num = is64 ? u16(56) : u16(44);
  if (num > 256 || size < (is64 ? 56 : 32) || phoff + num * size > buf.length) return { error: 'corrupt program headers' };
  let nx = null, relro = false, dyn = null;
  for (let i = 0; i < num; i++) {
    const o = phoff + i * size, type = u32(o);
    if (type === PT_GNU_STACK) nx = ((is64 ? u32(o + 4) : u32(o + 24)) & 1) === 0;
    else if (type === PT_GNU_RELRO) relro = true;
    else if (type === PT_DYNAMIC) dyn = is64 ? { off: u64(o + 8), len: u64(o + 32) } : { off: u32(o + 4), len: u32(o + 16) };
  }
  let bindNow = false, rpath = false;
  if (dyn && dyn.off + dyn.len <= buf.length) {
    const ent = is64 ? 16 : 8;
    for (let o = dyn.off, n = 0; o + ent <= dyn.off + dyn.len && n < 1024; o += ent, n++) {
      const tag = is64 ? u64(o) : u32(o), val = is64 ? u64(o + 8) : u32(o + 4);
      if (tag === 0) break;
      if (tag === DT_RPATH || tag === DT_RUNPATH) rpath = true;
      if (tag === DT_BIND_NOW || (tag === DT_FLAGS && (val & 8)) || (tag === DT_FLAGS_1 && (val & 1))) bindNow = true;
    }
  }
  // ponytail: symbol names are found by substring, not by walking the symbol tables. FORTIFY counts as missing only when an unchecked libc copy is imported and no *_chk variant is.
  const str = buf.toString('latin1'), risky = /\0(?:strcpy|strcat|sprintf|vsprintf|memcpy|gets)\0/.test(str);
  return {
    is64, nx, relro: relro ? (bindNow ? 'full' : 'partial') : 'none', canary: buf.includes('__stack_chk_fail'),
    pie: u16(16) !== 2, rpath, stripped: !buf.includes('\0.symtab\0'), fortify: !risky || /__(?!stack_chk_fail)\w+_chk\0/.test(str),
    dangerous: [...new Set([...str.matchAll(/\0(gets|system|popen)\0/g)].map((m) => m[1]))]
  };
}
