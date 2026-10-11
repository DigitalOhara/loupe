import manifest from './manifest.js';
import network from './network.js';
import signature from './signature.js';
import code from './code.js';
import native from './native.js';
import appcode from './appcode.js';
import secretvalues from './secretvalues.js';
import hybrid from './hybrid.js';

/** Registry order is display order. Each rule: { id, title, category, needs, code?, run(ctx) }. */
export const RULES = [...manifest, ...network, ...signature, ...code, ...native, ...appcode, ...secretvalues, ...hybrid];
