/**
 * Runs rules and turns what they return into outcomes. Pure of any threading: the worker (worker.js) calls it, and
 * the tests call it directly. A rule never decides its own state. It returns findings, or says it is inconclusive or
 * not applicable. "checked" is only the answer when the rule ran over its whole input.
 */
import fs from 'node:fs';
import { RULES } from './rules/index.js';
import { standardsFor } from './standards.js';
import { buildModel } from './model.js';

const NEEDS = {
  manifest: ['manifest-unreadable', (c) => !!c.model.manifest],
  signature: ['tool-unavailable', (c) => !!c.sig && !c.sig.error],
  apk: ['apk-missing', (c) => fs.existsSync(c.input.apkPath)],
  sources: ['no-sources', (c) => c.hasSources]
};

const header = (rule) => ({ ruleId: rule.id, title: rule.title, category: rule.category, standards: standardsFor(rule) });
const delta = (a, b) => ({ examined: b.examined - a.examined, skipped: b.skipped - a.skipped, damaged: b.damaged - a.damaged, libraryDamaged: b.libraryDamaged - a.libraryDamaged, eligible: b.examined - a.examined + b.skipped - a.skipped });

export async function runRule(rule, ctx) {
  const head = header(rule);
  for (const n of rule.needs || []) {
    const [reason, ok] = NEEDS[n];
    if (!ok(ctx)) return [{ ...head, state: 'not_tested', reason }];
  }
  ctx.input.resetBudget?.();
  const before = { ...ctx.input.stats };
  let res;
  try { res = await rule.run(ctx); } catch (e) { return [{ ...head, state: 'error', reason: String(e?.message || e).slice(0, 200) }]; }
  let coverage = delta(before, ctx.input.stats);
  if (!coverage.eligible && rule.needs?.includes('manifest')) coverage = { examined: 1, skipped: 0, eligible: 1 };   // the manifest itself
  if (res.notApplicable) return [{ ...head, state: 'not_applicable', reason: res.notApplicable, coverage }];
  const gap = (ctx.input.stats.truncated && 'the scan budget ran out before every file was read') || (coverage.skipped && `${coverage.skipped} eligible file${coverage.skipped === 1 ? ' was' : 's were'} too large or unreadable, so nothing can be said about them`) || (rule.code && coverage.damaged > 0 && `the decompiler could not fully decompile ${coverage.damaged} of the files this rule read (${ctx.input.stats.damagedFiles.slice(-Math.min(coverage.damaged, 2)).map((f) => f.split('/').slice(-3).join('/')).join(', ')}${coverage.damaged > 2 ? ', …' : ''}), so some code is missing`);
  // Findings do not make a rule complete: say so when it did not read everything.
  const said = gap || res.inconclusive;
  if (res.findings?.length) return [...res.findings.map((f) => ({ ...head, state: 'finding', coverage, ...f })), ...(said ? [{ ...head, state: 'inconclusive', reason: `${said}. The findings above stand, but this rule may have missed others`, coverage }] : [])];
  const why = res.inconclusive || gap;
  if (why) return [{ ...head, state: 'inconclusive', reason: why, coverage }];
  return [{ ...head, state: 'checked', coverage }];
}

/** Builds the model once, then runs every rule in order, calling onRule(rule, outcomes) after each. */
export async function runAll({ input, sig, partial }, onRule = () => {}) {
  const model = await buildModel(input);
  // The app's own code is under the packages the manifest names for the app itself: its package, its launcher activity and its Application class, two levels deep.
  // Other components in a merged manifest belong to libraries, so they do not count. With nothing to go by, all code counts.
  const roots = new Set(), mf = model.manifest, appCls = mf?.app?.attrs?.['android:name'];
  const fq = (n) => (!n ? '' : n.startsWith('.') ? `${mf.package}${n}` : n.includes('.') ? n : `${mf.package}.${n}`);
  for (const n of [mf?.package, ...(mf?.components || []).filter((c) => c.launcher).map((c) => c.name), fq(appCls)]) {
    const p = String(n || '').split('.').filter(Boolean);
    if (p.length > 1) roots.add(`sources/${p.slice(0, Math.min(2, p.length - 1)).join('/')}/`);
    else if (p.length === 1 && n === mf?.package) roots.add(`sources/${p[0]}/`);
  }
  input.setOwnRoots?.(roots.size ? [...roots] : null);
  const ctx = { input, model, sig, partial: !!partial, hasSources: await input.exists('sources') };
  const all = [];
  for (const rule of RULES) {
    const out = await runRule(rule, ctx);
    all.push(...out);
    onRule(rule, out);
  }
  return all;
}
