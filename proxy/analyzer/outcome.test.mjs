import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanOutcome, fingerprint, mask } from './outcome.js';

test('fingerprint ignores everything but rule and key', () => {
  assert.equal(fingerprint('r', 'activity:A'), fingerprint('r', 'activity:A'));
  assert.notEqual(fingerprint('r', 'activity:A'), fingerprint('r', 'activity:B'));
  assert.match(fingerprint('r', 'k'), /^[a-f0-9]{16}$/);
});

test('mask keeps the ends only', () => {
  assert.equal(mask('abcd'), '****');
  assert.equal(mask('AKIA' + 'ABCDEFGHIJKLMNOP'), 'AK************OP');
});

test('cleanOutcome whitelists fields, caps sizes and drops bad evidence', () => {
  const o = cleanOutcome({
    ruleId: 'a.b', state: 'finding', severity: 'high', title: 'x'.repeat(5000), evil: '<script>', category: 'NOPE',
    evidence: [{ kind: 'source', excerpt: 'y'.repeat(9000), ref: { path: 'p', startLine: 1.5, endLine: 3 } }, { kind: 'bogus' }, null],
    repro: { steps: ['s'], command: ['adb', 5, 'x'] }
  });
  assert.equal(o.evil, undefined);
  assert.equal(o.title.length, 600);
  assert.equal(o.category, null);
  assert.equal(o.evidence.length, 1);
  assert.equal(o.evidence[0].excerpt.length, 4096);
  assert.deepEqual([o.evidence[0].ref.startLine, o.evidence[0].ref.endLine], [null, 3]);
  assert.deepEqual(o.repro.command, ['adb', 'x']);
});

test('cleanOutcome rejects unusable shapes', () => {
  for (const bad of [null, 'x', {}, { ruleId: 'a', state: 'nope' }, { state: 'checked' }]) assert.throws(() => cleanOutcome(bad), TypeError);
});
