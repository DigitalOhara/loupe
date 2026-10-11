/** Builders for the evidence attached to findings. Excerpts are plain text, capped, and never rendered as HTML. */
import { fingerprint } from './outcome.js';
import { PKG } from '../../src/lib/sessionParse.js';

const MANIFEST = 'resources/AndroidManifest.xml';

/**
 * An excerpt of an XML element with its most important line marked (`hitLine`): the line of the attribute or tag the note is about, so the reader
 * does not have to find it. The window moves to include that line when the element is long.
 */
function xmlEv(kind, path, lines, el, note, max = 12) {
  const needle = (/android:\w+/.exec(note) || /\w+(?=\s*=\s*")/.exec(note) || /\w+SdkVersion/.exec(note) || (/intent filter/.test(note) && ['<intent-filter']) || /<[\w-]+/.exec(note) || /BROWSABLE|uses-permission|EnableSafeBrowsing/.exec(note) || [''])[0];
  let hit = el.line;
  if (needle) for (let l = el.line; l <= Math.min(el.endLine, lines.length); l++) if (lines[l - 1].includes(needle)) { hit = l; break; }
  const start = hit - el.line >= max ? Math.max(el.line, hit - 3) : el.line;
  const end = Math.min(el.endLine, start + max - 1);
  return { kind, ref: { path, startLine: start, endLine: end, hitLine: hit }, excerpt: lines.slice(start - 1, end).join('\n'), note };
}

export const manifestEv = (model, el, note = '') => xmlEv('manifest', MANIFEST, model.manifestLines, el, note);

export const nscEv = (model, el, note = '') => xmlEv('resource', model.nscPath, model.nscLines, el, note);

/** [label, pattern, a secret value (not just a marker line), severity (default high)]. Used by the secrets rule and by `sensitive()`. */
export const SECRETS = [
  // the header plus Base64 key material after it, so code that only mentions the marker (to strip it from a key it reads) is not a key
  ['Private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:[\s"'+]|\\[nrt])*[A-Za-z0-9+/=]{40,}/g, false],
  ['AWS secret access key', /\bAKIA[0-9A-Z]{16}\b[\s\S]{0,120}?['"][0-9A-Za-z/+]{40}['"]/g, true],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, true],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, true],
  ['Stripe live secret key', /\bsk_live_[0-9a-zA-Z]{24,}\b/g, true],
  ['Stripe restricted key', /\brk_live_[0-9a-zA-Z]{24,}\b/g, true],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g, true, 'medium'],             // usually restricted by app or referrer, so a lower severity
  ['Google OAuth access token', /\bya29\.[0-9A-Za-z_-]{20,}/g, true],
  ['Twilio API key', /\bSK[0-9a-f]{32}\b/g, true],
  ['Mailgun API key', /\bkey-[0-9a-zA-Z]{32}\b/g, true],
  ['Mailchimp API key', /\b[0-9a-f]{32}-us\d{1,2}\b/g, true],
  ['Slack webhook', /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9A-Za-z]{20,}/g, true],
  ['Square token', /\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,}/g, true],
  ['Braintree production token', /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, true],
  ['Discord bot token', /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g, true],
  ['Credentials in a URL', /\b[a-z][a-z0-9+.-]*:\/\/[^\/\s:@"'<>]{1,64}:[^\/\s@"'<>]{1,64}@[\w.-]+/gi, true],
  ['Hardcoded Authorization header value', /["']\s*(?:Basic [A-Za-z0-9+\/=]{12,}|Bearer [A-Za-z0-9._~+\/-]{20,}=*)\s*["']/g, true],
  ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, true, 'medium'],
  ['Azure storage key', /DefaultEndpointsProtocol=https?;[^"'\n]*?(?:AccountKey|SharedAccessSignature)=[^;"'\s]+/g, true],
  ['SendGrid API key', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, true],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, true],
  ['Firebase database URL', /https:\/\/[a-z0-9-]+(?:-default-rtdb)?(?:\.[a-z0-9-]+)?\.firebaseio\.com/g, false, 'low'],       // not a secret, but its security rules decide who can read the data
  ['Google service account key', /"type"\s*:\s*"service_account"/g, false],
  ['PGP private key', /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, false],
  ['Firebase Cloud Messaging server key', /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}/g, true],
  ['Telegram bot token', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, true],
  ['Mapbox secret token', /\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g, true],
  ['OpenAI API key', /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g, true],
  ['Anthropic API key', /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, true],
  ['Sentry DSN', /https:\/\/[0-9a-f]{32}@[\w.-]*sentry\.io\/\d+/g, true, 'low'],             // a DSN only lets someone send events, so low
  ['Database connection string', /\b(?:jdbc:[a-z]+|mongodb(?:\+srv)?|redis|postgres(?:ql)?|mysql|amqp):\/\/[^\s"'<>]{4,}/g, true, 'low']
];
/** A matched line in a text file plus one line of context on each side, as it appears in the file. */
export function sourceEv(path, text, index, note = '') {
  const lines = text.split('\n');
  const line = text.slice(0, index).split('\n').length;
  const start = Math.max(1, line - 1), end = Math.min(lines.length, line + 1);
  return { kind: path.startsWith('sources/') ? 'source' : 'resource', ref: { path, startLine: start, endLine: end, hitLine: line }, excerpt: lines.slice(start - 1, end).map((l) => l.slice(0, 240)).join('\n'), note };
}

/** A finding from a rule, with its fingerprint filled in. `repro.command` is an argv array, and only built from a valid package name. */
export const finding = (ruleId, f) => ({ ...f, fingerprint: fingerprint(ruleId, f.key) });
export const validPackage = (pkg) => PKG.test(pkg);
