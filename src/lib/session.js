/** The page's handle on dynamic sessions: the recorder (recorder.js) bound to the real ADB connection, plus a React hook for its state. */
import { useSyncExternalStore } from 'react';
import * as webadb from './webadb.js';
import * as recorder from './recorder.js';

export const probe = (pkg, analyzedShas) => recorder.probe(webadb, pkg, analyzedShas);
export const startSession = (o) => recorder.startSession(webadb, o);
export const { stopSession, getSession, subscribe } = recorder;
export const useSession = () => useSyncExternalStore(recorder.subscribe, recorder.getSession);
