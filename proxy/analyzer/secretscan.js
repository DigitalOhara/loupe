/**
 * Detecting secret values by what they are named and what they look like, for the cases where no provider has a fixed token format: a password, key or
 * secret assigned a literal, and key-shaped constants (Base64 or hex of an AES-sized key) standing alone in dex and native strings.
 */
const NAME = '[\\w-]*?(?:pass(?:word|wd|phrase|code)?|pwd|secret|api[_-]?key|apikey|access[_-]?(?:key|token)|auth[_-]?(?:key|token)|private[_-]?key|client[_-]?secret|credential|aes[_-]?key|des[_-]?key|encrypt\\w*key|enc[_-]?key|crypt\\w*key|signing[_-]?key|master[_-]?key|shared[_-]?key|secret[_-]?key|salt|token)[\\w-]*';
/** A name that is about UI text or a path rather than a secret. */
const NOISE_NAME = /(?:hint|label|title|desc|description|toggle|prompt|error|message|msg|text|format|regex|pattern|path|icon|mask|eye|strike|type|name|length|policy|rule|enabled|visible|required|expired|missing|invalid|field|button|view|style|theme|color|key_?(?:code|event|board)|tag|url|uri|endpoint|header|param|action|extra|field|count|size|max|min)(?:[_.-]|$)|(?:_|^)(?:is|has|use|show|hide|can)_/i;

export const KV = new RegExp(`(?<![\\w.])(${NAME})["']?\\s*(?:=>|=|:)\\s*["']([^"'\\r\\n]{8,200})["']`, 'gi');
export const XML_STRING = new RegExp(`<string\\s+name="(${NAME})"[^>]*>([^<]{8,200})<`, 'gi');
export const PROP = new RegExp(`^[ \\t]*(${NAME})[ \\t]*[=:][ \\t]*([^\\s"'#<][^\\r\\n]{7,200})$`, 'gim');

export function entropy(s) {
  const n = {};
  for (const c of s) n[c] = (n[c] || 0) + 1;
  return -Object.values(n).reduce((t, k) => t + (k / s.length) * Math.log2(k / s.length), 0);
}

const WORD = new Set(['pass', 'password', 'passwd', 'pwd', 'passphrase', 'passcode', 'secret', 'secrets', 'token', 'credential', 'credentials', 'salt', 'apikey', 'passkey', 'privatekey']);
const KEYWORD = new Set(['api', 'aes', 'des', 'private', 'secret', 'access', 'auth', 'encrypt', 'encryption', 'enc', 'signing', 'master', 'shared', 'client', 'crypto', 'crypt', 'hmac', 'license']);
/** Whether the name has a secret-like word as a whole word (`aesKey`, `API_KEY`, `client_secret`), not inside another word (`tokenizer`, `passthru`). */
export function secretName(name) {
  const w = name.split(/[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])/).filter(Boolean).map((x) => x.toLowerCase());
  return w.some((x, i) => WORD.has(x) || (x === 'key' && KEYWORD.has(w[i - 1] || '')));
}

export const EMBEDDED = /<([A-Za-z]*(?:Username|Password|Passwd|Pwd|Secret|ApiKey|AccessKey|Token)[A-Za-z]*)\b[^>]*>([^<\r\n]{3,80})</g;
/** A value between XML tags inside a string (a SOAP or XML payload): anything that is not an empty or placeholder value. */
export const embeddedValue = (v) => !/^(?:null|true|false|none|undefined|\?|\*+|x+|\$\{.*|%[sd@].*|\{\{.*|<.*)$/i.test(v.trim()) && /[A-Za-z0-9]/.test(v);

/** Whether `value`, assigned to `name`, is plausibly a real secret and not UI text, an identifier, a placeholder or a plain URL. */
export function plausible(name, value) {
  const v = value.trim();
  if (!secretName(name) || NOISE_NAME.test(name)) return false;
  if (/^(?:null|true|false|none|undefined|changeme|your[_ -]|example|sample|test|dummy|placeholder|<|\$\{|%[sd@]|\{\{|@|\?|\*+$|x{4,}$)/i.test(v)) return false;
  if (/^[a-z][a-z0-9]*(?:[_.:-][a-z0-9]+)+$/.test(v)) return false;                 // password_hint, com.example.key: identifiers
  if (/^[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+$/.test(v) || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return false;   // CamelCase and CONSTANT_NAMES
  if (/^https?:\/\/[^\s:@]*$/i.test(v) || /^[\w./-]+\.(?:xml|png|json|html|js|css|java|kt)$/i.test(v) || /^(?:android|java|javax|com|org)\.[\w.]+$/.test(v)) return false;
  const digit = /\d/.test(v), special = /[^A-Za-z0-9\s]/.test(v), mixed = /[a-z]/.test(v) && /[A-Z]/.test(v);
  if (/^[A-Z]?[a-z]+[:.!?]*$/.test(v)) return false;                                  // one ordinary word, such as a field label
  if (/\s/.test(v)) return digit && !/[.!?]$/.test(v) && v.split(/\s+/).length <= 8;       // a sentence of UI text has no digit; "This is the key 123" does
  if (!(digit || special || (mixed && v.length >= 10))) return false;
  return entropy(v) >= 2.5;
}

/** Standalone key-shaped constants: Base64 or hex long enough for an AES key, random-looking rather than a word or a Java name. */
export function keyShaped(s) {
  if (s.length < 16 || s.length > 128) return null;
  if (/^[0-9a-fA-F]+$/.test(s) && [32, 48, 64].includes(s.length) && /\d/.test(s) && /[a-fA-F]/.test(s) && entropy(s) >= 3.0) return 'hex key-sized value';
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && [16, 20, 22, 24, 32, 43, 44, 64, 88].includes(s.length) || /^[A-Za-z0-9+/]{22,}={0,2}$/.test(s)) {
    const digits = (s.match(/\d/g) || []).length, sym = (s.match(/[+/=]/g) || []).length;
    if (/[a-z]/.test(s) && /[A-Z]/.test(s) && (digits + sym) / s.length >= 0.15 && entropy(s) >= 4.0 && (s.match(/[A-Z][a-z]{2,}/g) || []).length < 2 && !/[a-z]{7,}/.test(s) && !(s.includes('/') && /[a-z]{5,}/.test(s))) return 'Base64 key-sized value';
  }
  return null;
}
