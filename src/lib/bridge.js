/**
 * Authenticated access to the Node bridge (/__loupe/*). The bridge issues a
 * per-launch token at /__loupe/session; it is held in memory only and sent as a
 * Bearer header (fetch) or `loupe.<token>` subprotocol (WebSocket).
 */
let tokenP = null;

const getToken = () => (tokenP ||= fetch('/__loupe/session', { cache: 'no-store' })
  .then((r) => { if (!r.ok) throw new Error('bridge refused a session'); return r.json(); })
  .then((j) => j.token)
  .catch((e) => { tokenP = null; throw e; }));

export async function bridgeFetch(url, init = {}) {
  const run = async () => fetch(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${await getToken()}` } });
  const r = await run();
  if (r.status !== 401) return r;
  tokenP = null;                // the bridge restarted and rotated its token
  return run();
}

export async function bridgeWS(url) {
  return new WebSocket(url, [`loupe.${await getToken()}`]);
}

/** A query string from an object, leaving out empty values. */
export const qs = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== '')).toString();

/** The JSON body of a bridge response, or an Error carrying the bridge's message, status and code. */
export async function ok(res) {
  const j = await res.json().catch(() => ({}));
  if (!res.ok || j.ok === false) throw Object.assign(new Error(j.error || `bridge said ${res.status}`), { code: j.code, status: res.status });
  return j;
}
