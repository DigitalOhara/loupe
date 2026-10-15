/**
 * Turns an uploaded proxy CA (DER or PEM) into the PEM text and the Android
 * trust-store filename (`<subject_hash_old>.0`) the browser then installs on the
 * device. Uses the host's openssl, which the Wi-Fi bridge already assumes is
 * present; this never touches the device, so it works over USB and Wi-Fi alike.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OPENSSL_PATHS = ['openssl', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe', 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'];
let _openssl;
function openssl() {
  if (_openssl) return _openssl;
  for (const p of OPENSSL_PATHS) {
    try { execFileSync(p, ['version'], { stdio: 'ignore' }); return (_openssl = p); }
    catch { /* next */ }
  }
  throw new Error('openssl not found — install Git for Windows or add openssl to PATH');
}

/** Handles /__loupe/cert/*. Returns true if it took the request. */
export async function handleCertApi(req, res, path) {
  if (path !== '/__loupe/cert/prepare') return false;
  if (req.method !== 'POST') { res.writeHead(405).end(); return true; }

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);

  const dir = mkdtempSync(join(tmpdir(), 'loupe-cert-'));
  const inFile = join(dir, 'in');
  const pemFile = join(dir, 'cert.pem');
  try {
    writeFileSync(inFile, raw);
    // Accept PEM or DER; normalise to PEM either way.
    const ssl = openssl();
    let form = 'PEM';
    try { execFileSync(ssl, ['x509', '-inform', 'PEM', '-in', inFile, '-noout']); }
    catch { form = 'DER'; }
    execFileSync(ssl, ['x509', '-inform', form, '-in', inFile, '-outform', 'PEM', '-out', pemFile]);

    const hash = execFileSync(ssl, ['x509', '-in', pemFile, '-subject_hash_old', '-noout'])
      .toString().trim().split('\n')[0];
    const subject = execFileSync(ssl, ['x509', '-in', pemFile, '-subject', '-noout'])
      .toString().trim();
    if (!/^[0-9a-f]{8}$/.test(hash)) throw new Error('could not compute the certificate hash');

    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ ok: true, pem: readFileSync(pemFile, 'utf8'), hash, subject }));
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'not a valid certificate (need a DER or PEM CA)' }));
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  return true;
}
