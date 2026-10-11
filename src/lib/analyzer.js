/** Client for the bridge's analyzer API (/__loupe/analyzer/*). See proxy/analyzer/api.js. Targets are decompile cache ids, the same ones the Decompiler uses. */
import { bridgeFetch, qs, ok } from './bridge.js';

const B = '/__loupe/analyzer';

/** What a dynamic session may probe: exported activities, providers and deep links from the manifest, and the APK hash. */
export const plan = (id) => bridgeFetch(`${B}/plan?${qs({ id })}`).then(ok);
/** Uploads a finished recording. The bridge analyzes it and stores the result next to the static scan. */
export const uploadSession = (id, recording) => bridgeFetch(`${B}/session`, { method: 'POST', body: JSON.stringify({ id, recording }) }).then(ok);
/** { id: { static, dynamic } } for the decompiled apps that already have a stored scan. */
export const summary = (ids) => bridgeFetch(`${B}/summary?${qs({ ids: ids.join(',') })}`).then(ok).then((j) => j.scans);
/** Deletes the stored result of one mode ('static' or 'dynamic') for an app. */
export const deleteResults = (id, mode) => bridgeFetch(`${B}/results?${qs({ id, mode })}`, { method: 'DELETE' }).then(ok);
export const status = () => bridgeFetch(`${B}/status`).then(ok);
export const startScan = (id) => bridgeFetch(`${B}/scan`, { method: 'POST', body: JSON.stringify({ id }) }).then(ok).then((j) => j.job);
/** The scan job for `id` while the bridge remembers it, else null. `status` is running | complete | partial | cancelled | failed. */
export const scanState = (id) => bridgeFetch(`${B}/scan?${qs({ id })}`).then(ok).then((j) => j.job);
export const cancelScan = (id) => bridgeFetch(`${B}/scan?${qs({ id })}`, { method: 'DELETE' }).then(ok);
/** { artifactId, scan, dynamic }: the latest stored scans (each is null before the first one). */
export const results = (id) => bridgeFetch(`${B}/results?${qs({ id })}`).then(ok);
