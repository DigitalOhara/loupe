/**
 * Read access to one decompile cache entry for the rules. Everything under it came from a hostile APK: paths are
 * checked segment by segment with lstat (no `..`, no absolute paths, no symlinks), reads are size-capped, and a shared
 * budget (files, bytes, wall clock) stops a pathological APK from running the scan forever. When the budget runs out
 * `stats.truncated` is set, and a file or folder that could not be read counts in `stats.skipped`. Either way a rule
 * that found nothing reports `inconclusive`, not `checked`.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';

export const TEXT = /\.(java|kt|xml|json|properties|txt|html?|js|yml|yaml|cfg|conf|gradle|pem|key|crt|env)$/i;

/** What jadx writes where it could not decompile a method or class. */
const DAMAGE = /Method dump skipped|Method not decompiled|Code restructure failed|Failed to decompile|Can't load method|JADX ERROR/;

export function openInput(dir, { maxFileBytes = 2 * 1024 ** 2, maxFiles = 150_000, maxBytes = 768 * 1024 ** 2, budgetMs = 60_000 } = {}) {
  const out = path.join(dir, 'out');
  const stats = { examined: 0, skipped: 0, damaged: 0, libraryDamaged: 0, damagedFiles: [], truncated: false };
  let ownRoots = null;                                  // set by the engine from the manifest: where the app's own code lives
  let t0 = Date.now(), bytes = 0, base = 0;
  const spent = () => {
    if (Date.now() - t0 > budgetMs || stats.examined - base > maxFiles || bytes > maxBytes) stats.truncated = true;
    return stats.truncated;
  };
  /** Each rule gets the whole budget: it is a limit on one pass, not on the scan, so a late rule is not starved by the earlier ones. */
  const resetBudget = () => { t0 = Date.now(); bytes = 0; base = stats.examined; stats.truncated = false; };

  /** Absolute path of `rel` under out/, or null when it escapes, is missing, or passes through a symlink. */
  async function resolve(rel) {
    if (rel.includes('\0') || path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) return null;
    let cur = out;
    for (const seg of rel.split('/').filter(Boolean)) {
      cur = path.join(cur, seg);
      const st = await fsp.lstat(cur).catch(() => null);
      if (!st || st.isSymbolicLink()) return null;
    }
    return cur;
  }

  /** The file as text, or null when it is missing, a directory, a symlink, or over the size cap. */
  async function read(rel, max = maxFileBytes) {
    const abs = await resolve(rel);
    if (!abs) return null;
    const st = await fsp.lstat(abs).catch(() => null);
    if (!st?.isFile() || st.size > max) { if (st?.isFile()) stats.skipped++; return null; }
    bytes += st.size;
    const text = await fsp.readFile(abs, 'utf8').catch(() => null);
    if (text === null) stats.skipped++;                      // eligible but unreadable
    return text;
  }

  /** Every file under `sub` whose relative path passes `test`, yielded as { rel, text }. Stops when the budget is spent. `skipDir(rel)` prunes a directory without reading it. */
  async function* walk(sub, test = TEXT, { skipDir = null } = {}) {
    const root = await resolve(sub);
    if (!root) return;
    const stack = [[root, sub]];
    while (stack.length) {
      const [abs, rel] = stack.pop();
      const list = await fsp.readdir(abs, { withFileTypes: true }).catch(() => { stats.skipped++; return []; });
      for (const e of list) {
        if (spent()) return;
        if (e.isSymbolicLink()) continue;
        const r = `${rel}/${e.name}`;
        if (e.isDirectory()) { if (!skipDir?.(r)) stack.push([path.join(abs, e.name), r]); continue; }
        if (!e.isFile() || !test.test(e.name)) continue;
        const text = await read(r);
        if (text === null) continue;
        stats.examined++;
        // jadx left a marker: part of this class is missing. Only the app's own code can make a rule inconclusive: a library that is partly missing is reported, but does not downgrade the rules.
        if (DAMAGE.test(text)) {
          if (!ownRoots || ownRoots.some((p) => r.startsWith(p))) { stats.damaged++; if (stats.damagedFiles.length < 50) stats.damagedFiles.push(r); } else stats.libraryDamaged++;
        }
        yield { rel: r, text };
      }
    }
  }

  /** Entry names of a directory under out/, or null when it is missing or not a plain directory. */
  const list = async (rel) => { const abs = await resolve(rel); return abs ? fsp.readdir(abs).catch(() => null) : null; };
  /** Every APK part that was decompiled: the base and any splits. */
  const apkPaths = () => (fs.readdirSync(path.join(dir, 'in'), { withFileTypes: true }).filter((d) => d.isFile() && /\.apk$/.test(d.name)).map((d) => path.join(dir, 'in', d.name)).sort());
  return { read, walk, list, resetBudget, stats, setOwnRoots: (r) => { ownRoots = r; }, apkPath: path.join(dir, 'in', 'base.apk'), apkPaths, exists: async (rel) => !!(await resolve(rel)) };
}
