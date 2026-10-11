/**
 * What counts as sensitive: typed values (and their Base64 form), key=value credentials, JWTs, provider tokens, session cookies, card and Social Security numbers, and private keys. Results show these
 * values as they are; `scrub` exists only so a fingerprint never depends on one.
 */
import { SECRETS } from './evidence.js';
import { needlesOf } from '../../src/lib/sessionParse.js';

const KV = /\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization|bearer)\b["']?\s*[:=]\s*["']?([^\s"'&,;]{4,})/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const CARD = /\b(?:\d[ -]?){13,19}\b/g;
const COOKIE = /\b(?:Set-Cookie|Cookie)\s*:\s*[^\n]*?\b(?:[\w-]*(?:session|sess|sid|auth|token|jwt)[\w-]*)=([^;\s]{6,})/gi;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g;
const PLACEHOLDER = /^(null|true|false|none|undefined|\*+|x+|<.*>|\{.*\})$/i;

const luhn = (digits) => {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) { let d = +digits[digits.length - 1 - i]; if (i % 2) { d *= 2; if (d > 9) d -= 9; } sum += d; }
  return sum % 10 === 0;
};


/** What looks sensitive in a piece of text: [{ label, value, exact }]. `exact` is true for values the user typed. */
export function sensitive(text, typed = []) {
  const out = [];
  for (const n of needlesOf(typed)) if (n.value && text.includes(n.value)) out.push({ label: n.label, value: n.value, exact: true });
  for (const m of text.matchAll(KV)) if (!PLACEHOLDER.test(m[2])) out.push({ label: `A ${m[1].toLowerCase()} value`, value: m[2], exact: false });
  for (const m of text.matchAll(JWT)) out.push({ label: 'A JWT', value: m[0], exact: false });
  for (const [label, re, hide] of SECRETS) if (hide) for (const m of text.matchAll(re)) out.push({ label, value: m[0], exact: false });
  for (const m of text.matchAll(COOKIE)) out.push({ label: 'A session cookie', value: m[1], exact: false });
  for (const m of text.matchAll(SSN)) out.push({ label: 'A Social Security number', value: m[0], exact: false });
  for (const m of text.matchAll(PRIVATE_KEY)) out.push({ label: 'A private key', value: m[0], exact: false });
  for (const m of text.matchAll(CARD)) { const d = m[0].replace(/\D/g, ''); if (d.length >= 13 && d.length <= 19 && luhn(d)) out.push({ label: 'A card number', value: m[0], exact: false }); }
  return out;
}

/** `text` with every sensitive value replaced by a fixed placeholder. For identity keys: a fingerprint must not depend on a secret. */
export const scrub = (text) => sensitive(String(text ?? '')).reduce((t, h) => t.split(h.value).join('***'), String(text ?? ''));
