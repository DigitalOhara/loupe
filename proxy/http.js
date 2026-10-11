/** JSON replies and request bodies for the bridge's /__loupe/* handlers. */
export const NOSNIFF = { 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' };

/** An error that carries its HTTP status (and optional extra fields for the JSON body). */
export class HttpErr extends Error { constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; } }

export const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', ...NOSNIFF }); res.end(JSON.stringify(body)); };

export const readJson = (req, max = 65536) => new Promise((resolve, reject) => {
  let b = '';
  req.on('data', (c) => { b += c; if (b.length > max) { req.destroy(); reject(new HttpErr(413, 'body too large')); } });
  req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { reject(new HttpErr(400, 'bad json')); } });
});
