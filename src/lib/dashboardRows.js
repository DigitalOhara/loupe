/**
 * One row per app that has a stored result in either mode. `apps` are the decompiled apps (newest first) and `sums` the summary by decompile id.
 * The same APK decompiled twice shares one stored result, so rows are deduplicated by artifact, keeping the newest decompile.
 */
export function rowsFor(apps, sums) {
  const seen = new Set();
  return apps.filter((a) => {
    const r = sums[a.id];
    if (!r || !(r.static || r.dynamic) || seen.has(r.artifactId)) return false;
    seen.add(r.artifactId);
    return true;
  });
}
