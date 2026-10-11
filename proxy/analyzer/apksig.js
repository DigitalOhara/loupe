/**
 * Reads the signing certificates out of an APK without a Java toolchain: from the APK Signing Block (schemes v2 and v3) and from v1
 * META-INF/*.RSA|DSA|EC files. Hostile input: every offset is bounds-checked and nothing is executed. Returns
 * [{ sigAlg: 'SHA1withRSA', keyAlg: 'RSA', keyBits: 2048 }].
 */
import crypto from 'node:crypto';

const OIDS = { '1.2.840.113549.1.1.4': 'MD5withRSA', '1.2.840.113549.1.1.5': 'SHA1withRSA', '1.2.840.113549.1.1.11': 'SHA256withRSA', '1.2.840.113549.1.1.12': 'SHA384withRSA', '1.2.840.113549.1.1.13': 'SHA512withRSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS', '1.2.840.10045.4.1': 'SHA1withECDSA', '1.2.840.10045.4.3.2': 'SHA256withECDSA', '1.2.840.10045.4.3.3': 'SHA384withECDSA', '1.2.840.10045.4.3.4': 'SHA512withECDSA',
  '1.2.840.10040.4.3': 'SHA1withDSA', '2.16.840.1.101.3.4.3.2': 'SHA256withDSA' };

/** One DER element at `o`: { tag, start (of the value), end }. */
function der(b, o) {
  if (o + 2 > b.length) return null;
  const tag = b[o]; let len = b[o + 1], p = o + 2;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 4 || p + n > b.length) return null; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[p++]; }
  return p + len <= b.length ? { tag, start: p, end: p + len } : null;
}
const oidText = (b) => { const o = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0; for (const x of b.subarray(1)) { v = v * 128 + (x & 0x7f); if (!(x & 0x80)) { o.push(v); v = 0; } } return o.join('.'); };

/** The signature algorithm name of an X.509 certificate (DER), or ''. */
function sigAlgOf(cert) {
  const top = der(cert, 0); if (!top || top.tag !== 0x30) return '';
  const tbs = der(cert, top.start); if (!tbs) return '';
  const alg = der(cert, tbs.end); if (!alg || alg.tag !== 0x30) return '';
  const oid = der(cert, alg.start); if (!oid || oid.tag !== 0x06) return '';
  return OIDS[oidText(cert.subarray(oid.start, oid.end))] || oidText(cert.subarray(oid.start, oid.end));
}

function describe(der0) {
  try {
    const x = new crypto.X509Certificate(der0), d = x.publicKey.asymmetricKeyDetails || {};
    return { sigAlg: sigAlgOf(der0), keyAlg: x.publicKey.asymmetricKeyType?.toUpperCase() || '', keyBits: d.modulusLength || (d.namedCurve ? 0 : 0), curve: d.namedCurve || '' };
  } catch { return null; }
}

const u32 = (b, o) => (o + 4 <= b.length ? b.readUInt32LE(o) : null);
/** Certificates of one signer inside a v2/v3 signing-block value. */
function blockCerts(v) {
  const out = [];
  try {
    let o = 4;                                                       // the signers sequence is length-prefixed
    const sEnd = Math.min(v.length, 4 + u32(v, 0));
    while (o + 4 <= sEnd && out.length < 8) {
      const sl = u32(v, o); o += 4; const sig = v.subarray(o, o + sl); o += sl;
      const dl = u32(sig, 0); const data = sig.subarray(4, 4 + dl);   // signed data
      const dgl = u32(data, 0); let p = 4 + dgl;                       // skip digests
      const cl = u32(data, p); let q = p + 4; const cEnd = q + cl;
      while (q + 4 <= cEnd && out.length < 8) { const l = u32(data, q); q += 4; out.push(data.subarray(q, q + l)); q += l; }
    }
  } catch { /* a malformed block yields what was read so far */ }
  return out;
}

/** The v2 and v3 certificates from a whole APK file buffer. */
export function blockCertificates(apk) {
  const out = [];
  if (apk.length < 1024) return out;
  let eocd = -1;
  for (let i = apk.length - 22; i >= Math.max(0, apk.length - 65_557); i--) if (apk.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return out;
  const cd = apk.readUInt32LE(eocd + 16);
  if (cd < 32 || cd > apk.length || apk.subarray(cd - 16, cd).toString('latin1') !== 'APK Sig Block 42') return out;
  const size = Number(apk.readBigUInt64LE(cd - 24)), start = cd - size - 8;
  if (start < 0 || size < 24) return out;
  for (let o = start + 8; o + 12 <= cd - 24;) {
    const len = Number(apk.readBigUInt64LE(o)); if (len < 4 || o + 8 + len > cd) break;
    const id = apk.readUInt32LE(o + 8);
    if (id === 0x7109871a || id === 0xf05368c0) out.push(...blockCerts(apk.subarray(o + 12, o + 8 + len)));
    o += 8 + len;
  }
  return out;
}

/** Describes every distinct certificate found. `v1Blocks` are the bytes of META-INF/*.RSA|DSA|EC files. */
export function certificates(apk, v1Blocks = []) {
  const ders = blockCertificates(apk);
  for (const blk of v1Blocks) for (let i = 0; i + 4 < blk.length; i++) if (blk[i] === 0x30 && blk[i + 1] === 0x82) { const d = der(blk, i); if (d && d.end - i > 200 && describe(blk.subarray(i, d.end))) { ders.push(blk.subarray(i, d.end)); i = d.end - 1; } }
  const seen = new Set(), out = [];
  for (const d of ders) { const k = crypto.createHash('sha256').update(d).digest('hex'); if (seen.has(k)) continue; seen.add(k); const c = describe(d); if (c) out.push(c); }
  return out;
}
