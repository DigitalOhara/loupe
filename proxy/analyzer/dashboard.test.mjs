import test from 'node:test';
import assert from 'node:assert/strict';
import { rowsFor } from '../../src/lib/dashboardRows.js';

test('the dashboard lists an app with either result, once per artifact', () => {
  const apps = [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }, { id: 'e' }];
  const sums = {
    a: { artifactId: 'x', static: {} },
    b: { artifactId: 'y', dynamic: {} },
    c: { artifactId: 'z', static: {}, dynamic: {} },
    d: { artifactId: 'z', static: {} },   // the same APK decompiled again: newest (c) wins
  };
  assert.deepEqual(rowsFor(apps, sums).map((r) => r.id), ['a', 'b', 'c']);
});
