/**
 * Analyzer API (/__loupe/analyzer/*), behind the bridge's loopback, Origin, Host and token checks. A scan targets a
 * decompile cache entry by the same `id` the Decompiler uses; results are stored under the APK's artifactId, so they
 * outlive the cache entry. One scan per entry at a time. The page polls `GET scan` for progress.
 */
import { entryForAnalysis, entrySignature, entrySplitSignatures } from '../jadx.js';
import { RULES } from './rules/index.js';
import { SNAPSHOT } from './standards.js';
import { runScan, artifactId } from './run.js';
import { recommendationFor } from './recommendations.js';
import { json, readJson } from '../http.js';
import { openInput } from './files.js';
import { buildModel } from './model.js';
import { cleanRecording, sessionRecord, DYN_RULES } from './dynamic.js';
import * as store from './store.js';

// Session uploads and result deletes run one at a time, so a delete can never be undone by an upload that was already saving.
let chain = Promise.resolve();
const ordered = (fn) => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };

const deleting = new Set();                   // artifact ids whose result is being deleted: no scan may start until it is gone
const jobs = new Map();                        // decompile id -> { scanId, status, progress, startedAt, ac }
/** The job for a decompile id, or the running scan of the same artifact started from another decompile of it. */
const jobFor = async (id) => {
  const own = jobs.get(id);
  if (own?.status === 'running') return own;
  const aid = artifactId((await entryForAnalysis(id)).meta);
  return [...jobs.values()].find((j) => j.aid === aid && j.status === 'running') || own;
};
const view = (j) => j && { scanId: j.scanId, status: j.status, progress: j.progress, startedAt: j.startedAt, error: j.error };

async function start(id) {
  const { dir, meta } = await entryForAnalysis(id);
  const aid = artifactId(meta);
  // Results are stored per artifact, so a second decompile of the same APK must not scan at the same time and race for latest.json.
  // Nothing below the next line awaits before the job is registered, so two requests cannot both pass this check.
  if (deleting.has(aid)) throw Object.assign(new Error('The result is being deleted. Try again in a moment.'), { status: 409 });
  const running = [...jobs.values()].find((j) => j.aid === aid && j.status === 'running');
  if (running) return running;
  const ac = new AbortController();
  const job = { aid, scanId: null, status: 'running', progress: { done: 0, total: RULES.length, rule: '' }, startedAt: Date.now(), ac, error: null };
  jobs.set(id, job);
  job.done = (async () => {
    const sig = { ...(await entrySignature(dir)), splits: await entrySplitSignatures(dir) };
    const rec = await runScan({ dir, meta: { ...meta, id }, sig, signal: ac.signal, onProgress: (p) => { job.progress = p; } });
    // A cancelled, failed or partial scan must not replace a complete one: keep the last good result, and report the attempt through the job.
    const prev = rec.status === 'complete' ? null : await store.latestScan(aid);
    job.scanId = rec.scanId; if (!prev || prev.status !== 'complete') await store.saveScan(rec); job.status = rec.status;
  })().catch((e) => { job.status = 'failed'; job.error = String(e.message).slice(0, 200); });
  return job;
}

export async function handleAnalyzerApi(req, res, route) {
  try {
    const p = new URL(req.url, 'http://x').searchParams, id = p.get('id') || '';
    const is = (m, r) => req.method === m && route === `/__loupe/analyzer/${r}`;

    if (is('GET', 'status')) return json(res, 200, { ok: true, standards: SNAPSHOT, rules: RULES.map((r) => ({ id: r.id, title: r.title, category: r.category, needs: r.needs || [], code: !!r.code })), dynamicRules: DYN_RULES.map((r) => ({ id: r.id, title: r.title, category: r.category, group: r.group })) });
    if (is('POST', 'scan')) return json(res, 200, { ok: true, job: view(await start((await readJson(req)).id)) });
    if (is('GET', 'scan')) return json(res, 200, { ok: true, job: view(await jobFor(id)) || null });
    if (is('DELETE', 'results')) {
      const aid = artifactId((await entryForAnalysis(id)).meta);
      const dyn = p.get('mode') === 'dynamic';
      if (!dyn) deleting.add(aid);
      try {
        if (!dyn) for (const j of [...jobs.values()]) if (j.aid === aid && j.status === 'running') { j.ac.abort(); await j.done; }      // every scan of this artifact, and wait for its own save, so it cannot bring the result back
        await ordered(() => store.deleteScan(aid, dyn ? 'dynamic' : 'static'));
      } finally { deleting.delete(aid); }
      return json(res, 200, { ok: true });
    }
    if (is('DELETE', 'scan')) { (await jobFor(id))?.ac.abort(); return json(res, 200, { ok: true }); }

    if (is('GET', 'results')) {
      const aid = artifactId((await entryForAnalysis(id)).meta);
      const [scan, dynamic] = await Promise.all([store.latestScan(aid), store.latestScan(aid, 'dynamic')]);
      // The recommendation is looked up when results are read, so scans stored before it existed show it too.
      const apply = (r) => r && { ...r, outcomes: r.outcomes.map((o) => (o.state === 'finding' ? { ...o, recommendation: recommendationFor(o.ruleId, o.title) } : o)) };
      return json(res, 200, { ok: true, artifactId: aid, scan: apply(scan), dynamic: apply(dynamic) });
    }
    // What a dynamic session should probe: the exported components the manifest declares, and the APK hash to compare with the installed one.
    // Which of these decompiled apps already have a stored scan, for the Decompiler's list and the Analyzer dashboard: { id: { artifactId, static: { findings, at, status, scanId, severity }, dynamic: { ... } } }.
    if (is('GET', 'summary')) {
      const out = {};
      for (const one of (p.get('ids') || '').split(',').filter(Boolean).slice(0, 100)) {
        try {
          const aid = artifactId((await entryForAnalysis(one)).meta), row = {};
          for (const mode of ['static', 'dynamic']) {
            const r = await store.latestScan(aid, mode);
            if (!r) continue;
            const found = r.outcomes.filter((o) => o.state === 'finding'), n = (sev) => found.filter((o) => o.severity === sev).length;
            row[mode] = { findings: found.length, at: r.finishedAt || r.startedAt, status: r.status, scanId: r.scanId, severity: { high: n('high'), medium: n('medium'), low: n('low') } };
          }
          if (row.static || row.dynamic) out[one] = { ...row, artifactId: aid };
        } catch { /* a cache entry that cannot be read has no scan to show */ }
      }
      return json(res, 200, { ok: true, scans: out });
    }
    if (is('GET', 'plan')) {
      const { dir, meta } = await entryForAnalysis(id);
      const m = (await buildModel(openInput(dir))).manifest;
      if (!m) throw Object.assign(new Error('the manifest could not be read'), { status: 422 });
      // Providers are probed on reads only, so the permission that guards reads decides: readPermission, else the component's own or the application's.
      const readable = (c) => c.exported && !c.launcher && !(c.kind === 'provider' ? (c.readPermission ?? c.permission) : c.permission);
      // Writes have their own permission: a provider whose reads are open but whose writes are guarded must not get write probes, and the reverse is a write surface of its own.
      const writable = (c) => c.exported && c.kind === 'provider' && !(c.writePermission ?? c.permission);
      const open = m.components.filter((c) => readable(c) || writable(c));
      // A provider answers only to the paths its UriMatcher knows, so read the plain ones (no wildcards) from its class. The bare authority usually returns nothing.
      const input = openInput(dir);
      for (const c of open) {
        if (c.kind !== 'provider') continue;
        const src = /^[\w.$]+$/.test(c.name) ? await input.read(`sources/${c.name.replace(/\./g, '/')}.java`).catch(() => null) : null;
        c.paths = [...new Set([...(src || '').matchAll(/addURI\([^,]+,\s*"([\w\-./]+)"/g)].map((x) => x[1]))].slice(0, 4);
      }
      return json(res, 200, {
        ok: true, package: m.package, apkSha256s: (meta.parts || []).map((p) => p.sha256),
        activities: open.filter((c) => c.kind === 'activity' && readable(c)).map((c) => c.name),
        services: open.filter((c) => c.kind === 'service' && readable(c)).map((c) => c.name),
        receivers: open.filter((c) => c.kind === 'receiver' && readable(c)).map((c) => c.name),
        providers: open.filter((c) => c.kind === 'provider' && c.authorities).map((c) => ({ name: c.name, authority: c.authorities.split(';')[0], paths: c.paths || [], readable: readable(c), writable: writable(c) })),
        deeplinks: m.components.filter((c) => c.kind === 'activity' && c.exported).flatMap((c) => c.filters.filter((f) => f.categories.includes('android.intent.category.BROWSABLE')).flatMap((f) => f.data.filter((d) => d.scheme && d.host && !/[*]/.test(d.host)).map((d) => `${d.scheme}://${d.host}/`)))
      });
    }
    // The page uploads a finished recording. It is rebuilt from whitelisted fields, analyzed and stored next to the static scan.
    if (is('POST', 'session')) {
      const body = await readJson(req, 64 * 1024 ** 2);
      const { meta } = await entryForAnalysis(body.id);
      const aid = artifactId(meta);
      const record = sessionRecord(cleanRecording(body.recording), { artifactId: aid, decompileId: body.id });
      await ordered(() => store.saveScan(record));
      return json(res, 200, { ok: true, scanId: record.scanId });
    }
    return json(res, 404, { ok: false, error: 'unknown route' });
  } catch (e) {
    if (!res.headersSent) json(res, e.status || (e instanceof TypeError ? 400 : 500), { ok: false, error: e.message });
    else res.end();
  }
}
