/**
 * Runs one scan: the rules execute in a worker thread (worker.js) with memory limits, a wall-clock timeout and
 * cancellation. Every rule that did not report, because of a timeout, crash or cancel, gets an `error` outcome with the
 * reason, so a partial scan can never read as a clean one. The worker's messages are untrusted and sanitized.
 */
import crypto from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { RULES } from './rules/index.js';
import { cleanOutcome } from './outcome.js';
import { SNAPSHOT, standardsFor } from './standards.js';

const WORKER = new URL('./worker.js', import.meta.url);

/** One id for the APK set (base plus splits), independent of decompiler options, so rescans share a history. */
export const artifactId = (meta) => crypto.createHash('sha256').update((meta.parts || []).map((p) => p.sha256).sort().join('\n')).digest('hex');

export function runScan({ dir, meta, sig, signal, onProgress = () => {}, timeoutMs = 120_000, worker = WORKER }) {
  return new Promise((resolve) => {
    const partial = !!(meta.partial || meta.errors);
    const rec = {
      scanId: crypto.randomBytes(8).toString('hex'), artifactId: artifactId(meta), decompileId: meta.id, startedAt: Date.now(), finishedAt: null, status: 'complete',
      provenance: { analyzer: 1, standards: SNAPSHOT, jadx: meta.tool || null, decompilePartial: partial }, outcomes: []
    };
    const seen = new Set();
    const w = new Worker(worker, { workerData: { dir, sig, partial }, resourceLimits: { maxOldGenerationSizeMb: 768, maxYoungGenerationSizeMb: 64, stackSizeMb: 4 } });
    let settled = false, timer, onAbort;

    const finish = (status, reason) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort);
      w.terminate();
      for (const r of RULES) if (!seen.has(r.id)) rec.outcomes.push(cleanOutcome({ ruleId: r.id, title: r.title, category: r.category, standards: standardsFor(r), state: 'error', reason }));
      rec.status = status; rec.finishedAt = Date.now();
      resolve(rec);
    };

    w.on('message', (m) => {
      if (settled || !m || typeof m !== 'object') return;
      if (m.type === 'rule' && typeof m.ruleId === 'string' && RULES.some((r) => r.id === m.ruleId) && Array.isArray(m.outcomes) && !seen.has(m.ruleId)) {
        const clean = [];
        for (const o of m.outcomes.slice(0, 200)) { try { clean.push(cleanOutcome({ ...o, ruleId: m.ruleId })); } catch { /* drop a malformed outcome */ } }
        if (!clean.length) return;
        seen.add(m.ruleId); rec.outcomes.push(...clean);
        onProgress({ done: seen.size, total: RULES.length, rule: m.ruleId });
      } else if (m.type === 'done') finish(seen.size === RULES.length ? 'complete' : 'partial', 'the rule worker finished without reporting this rule');
      else if (m.type === 'failed') finish('failed', String(m.message || 'the rule worker failed').slice(0, 200));
    });
    w.on('error', (e) => finish('partial', `the rule worker stopped: ${String(e.message).slice(0, 120)}`));
    w.on('exit', () => finish('partial', 'the rule worker stopped unexpectedly'));
    timer = setTimeout(() => finish('partial', 'the scan timed out'), timeoutMs);
    onAbort = () => finish('cancelled', 'the scan was cancelled');
    if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort);
  });
}
