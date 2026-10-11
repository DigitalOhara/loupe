/**
 * One row per app that has a stored result in this mode. `apps` are the decompiled apps (newest first) and `sums` the summary by decompile id.
 * The same APK decompiled twice shares one stored result, so rows are deduplicated by artifact, keeping the newest decompile.
 */
export function rowsFor(apps, sums, mode) {
  const seen = new Set();
  return apps.filter((a) => {
    const r = sums[a.id]?.[mode];
    if (!r || seen.has(sums[a.id].artifactId)) return false;
    seen.add(sums[a.id].artifactId);
    return true;
  });
}
