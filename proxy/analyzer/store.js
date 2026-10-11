/**
 * What the analyzer keeps on disk under ~/.loupe/analyzer: scan results, keyed by artifactId so they
 * survive the decompile cache being evicted. Directories are 0700 and files 0600 (results can hold secrets and PII),
 * and every write is atomic (temp file, then rename).
 */
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const root = () => path.join(process.env.LOUPE_HOME || path.join(os.homedir(), '.loupe'), 'analyzer');
const ID = /^[a-f0-9]{64}$/;

function dirFor(artifactId) {
  if (!ID.test(artifactId || '')) throw new TypeError('bad artifact id');
  return path.join(root(), artifactId);
}

async function writeAtomic(file, data) {
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  await fsp.writeFile(tmp, data, { mode: 0o600 });
  await fsp.rename(tmp, file);
}
const readJson = (file, fallback) => fsp.readFile(file, 'utf8').then(JSON.parse, () => fallback);

// ponytail: only the latest scan of each kind is kept. Keep a history when scan diffs need one.
const scanFile = (artifactId, mode) => path.join(dirFor(artifactId), mode === 'dynamic' ? 'dynamic.json' : 'latest.json');
export const saveScan = async (rec) => writeAtomic(scanFile(rec.artifactId, rec.mode), JSON.stringify(rec));
/** Removes the stored result of one kind. */
export const deleteScan = (artifactId, mode) => fsp.rm(scanFile(artifactId, mode), { force: true });
export const latestScan = async (artifactId, mode = 'static') => readJson(scanFile(artifactId, mode), null);
