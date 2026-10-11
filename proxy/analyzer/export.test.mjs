import test from 'node:test';
import assert from 'node:assert/strict';
import { toMarkdown, findingMarkdown, findingIds, reportCode, cmdLine } from '../../src/lib/exportScan.js';

const std = { masvs: ['MASVS-PLATFORM'], maswe: ['MASWE-0018'], mastg: [], cwe: ['CWE-926'] };
const base = { ruleId: 'manifest.exported-components', title: 'Exported activity', category: 'PLATFORM', standards: std, coverage: {}, reason: '' };
const scan = {
  scanId: 's', artifactId: 'a', startedAt: 1_700_000_000_000, finishedAt: 1_700_000_001_000, status: 'complete', mode: 'static', provenance: {},
  outcomes: [
    { ...base, state: 'finding', severity: 'high', detection: 'exact', conclusion: 'exposure', summary: 'Any app can start it.', fingerprint: 'f'.repeat(16), evidence: [{ kind: 'manifest', excerpt: '<activity/>', note: '', ref: { path: 'resources/AndroidManifest.xml', startLine: 40, endLine: 41, hitLine: null } }], repro: { steps: ['Run it.'], command: ['adb', 'shell', 'am', 'start', '-n', 'a/b c'] } },
    { ...base, ruleId: 'code.x', title: 'Hidden', state: 'finding', severity: 'low', detection: 'probable', conclusion: 'weakness', summary: 's', fingerprint: 'e'.repeat(16), evidence: [], repro: null },
    { ...base, ruleId: 'network.cleartext', title: 'Cleartext', state: 'checked' },
    { ...base, ruleId: 'signature.verdict', title: 'Signature', state: 'not_tested', reason: 'tool-unavailable' },
    { ...base, ruleId: 'x.y', title: 'Pipe', state: 'inconclusive', reason: 'a | b' }
  ]
};

test('cmdLine quotes arguments with spaces', () => assert.equal(cmdLine(['adb', 'a b', "it's"]), `adb 'a b' 'it'\\''s'`));

test('the Markdown report has a summary, findings and a table of the rest', () => {
  const md = toMarkdown(scan, { app: 'My App' });
  assert.match(md, /^# My App: Static analysis/);
  assert.match(md, /2 findings, 1 rules checked clean, 1 inconclusive, 1 not tested, 0 errors/);
  assert.match(md, /## Findings[\s\S]*### MYAP-01|## Findings[\s\S]*### [A-Z]{4}-01: Exported activity/);
  assert.match(md, /adb shell am start -n 'a\/b c'/);
  assert.match(md, /\| signature\.verdict \| not tested \| tool-unavailable \|/);
  assert.match(md, /\| x\.y \| inconclusive \| a \\\| b \|/);
  assert.match(md, /No findings does not mean the app is secure/);
  assert.match(findingMarkdown({ ...scan.outcomes[0], recommendation: 'Remove the export. Add a permission.' }, scan), /\nRecommendation:\nRemove the export\. Add a permission\.\n\nRelated standards/);
  assert.match(findingMarkdown({ ...scan.outcomes[0], summary: 'Set android:debuggable to false in sources/a/B.java.' }, scan), /Set `android:debuggable` to `false` in `sources\/a\/B\.java`\./);
  assert.equal(findingMarkdown(scan.outcomes[0], scan).includes('Related standards: MASVS-PLATFORM, MASWE-0018, CWE-926'), true);
});

test('report codes: four letters from the app name, stable for any name', () => {
  const cases = { InsecureShop: 'INSH', 'InsecureBankv2.apk': 'INBA', OVAA: 'OVAA', Allsafe: 'ALLS', GDS_Smart: 'GDSM', 'My Great Bank': 'MGBY', 'A B C D E': 'ABCD', Go: 'GOXX', '1234': 'APPX', '': 'APPX' };
  for (const [name, code] of Object.entries(cases)) assert.equal(reportCode(name), code, name);
  assert.ok(Object.values(cases).every((c) => /^[A-Z]{4}$/.test(c)));
});

test('findings get IDs in severity order, and the report shows them', () => {
  const ids = findingIds(scan.outcomes, 'MYAP');
  assert.deepEqual([...ids.values()], ['MYAP-01', 'MYAP-02']);
  assert.equal(ids.get(scan.outcomes[0]), 'MYAP-01');                       // the high finding, before the low one
  const md = toMarkdown(scan, { app: 'My App' });
  assert.match(md, /\| MYAP-01 \| High \| Exported Activity \|/);
  assert.match(md, /### MYAP-01: Exported Activity/);
  assert.match(md, /\| MYAP-02 \| Low \| Hidden \|/);
  const many = findingIds(Array.from({ length: 120 }, () => ({ ...scan.outcomes[0] })), 'X');
  assert.ok([...many.values()].every((v) => /^X-\d{3}$/.test(v)));        // three digits once there are more than 99
});

test('hostile text cannot forge report structure', () => {
  const evil = '```\n## Forged finding\n![x](http://evil.example/p.png) [click](http://evil.example)\n```\nmore';
  const o = { ...scan.outcomes[0], title: '# Fake\n## heading', summary: '[a](http://evil.example)\n\n### Fake 2', evidence: [{ ...scan.outcomes[0].evidence[0], excerpt: evil, ref: { path: 'a\n## b', startLine: 1, endLine: 1, hitLine: 1 } }], repro: { steps: ['1. **bold**'], command: ['echo', '```'] } };
  const md = toMarkdown({ ...scan, outcomes: [o, ...scan.outcomes.slice(2)] });
  const outside = md.replace(/(`{3,})\n[\s\S]*?\n\1/g, '');                    // text outside any fenced block
  const lines = outside.split('\n');
  assert.ok(!lines.some((l) => /^#{1,6} (Fake|Forged|heading)/.test(l)), 'no forged heading');
  assert.ok(md.split('\n').some((l) => /^`{4,}$/.test(l)), 'the evidence fence is longer than the backticks it holds');
  assert.ok(!/(^|[^\\])!\[x\]\(/m.test(outside) && !/(^|[^\\])\[a\]\(http/.test(outside), 'no live links or images outside a code block');
  assert.equal(lines.filter((l) => /^### /.test(l)).length, 1);             // only the real finding heading
});

test('finding names are Title Case in the report, with code names left alone', () => {
  const o = { ...scan.outcomes[0], title: 'WebView can read files through file URLs: WebViewActivity.java' };
  const md = toMarkdown({ ...scan, outcomes: [o, ...scan.outcomes.slice(1)] }, { app: 'My App' });
  assert.match(md, /### [A-Z]{4}-01: WebView Can Read Files Through File URLs: WebViewActivity\.java/);
});
