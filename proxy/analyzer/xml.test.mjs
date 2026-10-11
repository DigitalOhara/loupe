import test from 'node:test';
import assert from 'node:assert/strict';
import { parseXml, XmlError, walk } from './xml.js';

test('parses elements, attributes, text and line ranges', () => {
  const r = parseXml('<?xml version="1.0"?>\n<a x="1" y=\'2\'>\n  <b\n    z="&amp;&lt;"/>\n  <c>hi &#65;</c>\n</a>');
  assert.equal(r.name, 'a');
  assert.deepEqual(r.attrs, { x: '1', y: '2' });
  const [b, c] = r.children;
  assert.deepEqual([b.line, b.endLine, b.attrs.z], [3, 4, '&<']);
  assert.equal(c.text, 'hi A');
  assert.equal([...walk(r)].length, 3);
});

test('refuses DTDs and entities', () => {
  assert.throws(() => parseXml('<!DOCTYPE a [<!ENTITY x "y">]><a/>'), XmlError);
  assert.throws(() => parseXml('<!doctype a><a/>'), XmlError);
});

test('refuses malformed, unbalanced and multi-root input', () => {
  for (const bad of ['<a><b></a>', '<a', '<a/><b/>', '', '<a>', '</a>']) assert.throws(() => parseXml(bad), XmlError, bad);
});

test('enforces size, depth and node limits', () => {
  assert.throws(() => parseXml('<a/>', { maxBytes: 3 }), XmlError);
  assert.throws(() => parseXml('<a>'.repeat(5) + '</a>'.repeat(5), { maxDepth: 4 }), XmlError);
  assert.throws(() => parseXml('<a>' + '<b/>'.repeat(10) + '</a>', { maxNodes: 5 }), XmlError);
});

test('an unterminated attribute value is rejected quickly', () => {
  const t = Date.now();
  assert.throws(() => parseXml('<a x="' + 'y'.repeat(200_000)), XmlError);
  assert.ok(Date.now() - t < 1000);
});
