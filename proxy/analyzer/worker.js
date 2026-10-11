/** Rule worker: runs in a worker thread with memory limits (see run.js). Posts each rule's outcomes as soon as it finishes. */
import { parentPort, workerData } from 'node:worker_threads';
import { openInput } from './files.js';
import { runAll } from './engine.js';

const input = openInput(workerData.dir);
try {
  await runAll({ input, sig: workerData.sig, partial: workerData.partial }, (rule, outcomes) => parentPort.postMessage({ type: 'rule', ruleId: rule.id, outcomes }));
  parentPort.postMessage({ type: 'done' });
} catch (e) {
  parentPort.postMessage({ type: 'failed', message: String(e?.message || e).slice(0, 200) });
}
