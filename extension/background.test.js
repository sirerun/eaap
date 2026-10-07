import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isDynamicSeg, normalizeURL } from './normalize.js';
import { redactHeaders } from './redact.js';

test('recognizes numeric and UUID path identifiers', () => {
  assert.equal(isDynamicSeg('12345'), true);
  assert.equal(isDynamicSeg('550e8400-e29b-41d4-a716-446655440000'), true);
  assert.equal(isDynamicSeg('orders'), false);
});

test('normalizes a Sanifu-style API path and removes volatile query values', () => {
  const [template, params] = normalizeURL('https://sanifu.run/api/users/12345?ts=1&include=profile');
  assert.equal(template, '/api/users/{param1}?include=profile');
  assert.deepEqual(params, ['12345']);
});

test('redacts credentials from captured request and response headers', () => {
  assert.deepEqual(redactHeaders([
    { name: 'Authorization', value: 'Bearer fixture-secret' },
    { name: 'set-cookie', value: 'session=fixture-secret' },
    { name: 'content-type', value: 'application/json' },
  ]), {
    authorization: '[REDACTED]',
    'set-cookie': '[REDACTED]',
    'content-type': 'application/json',
  });
});
