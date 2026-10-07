import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isDynamicSeg, normalizeURL } from './normalize.js';
import { redactHeaders } from './redact.js';
import { bodyShape, headerShape, isApproved } from './capture.js';

test('recognizes numeric and UUID path identifiers', () => {
  assert.equal(isDynamicSeg('12345'), true);
  assert.equal(isDynamicSeg('550e8400-e29b-41d4-a716-446655440000'), true);
  assert.equal(isDynamicSeg('orders'), false);
});

test('normalizes path identifiers and never retains query values', () => {
  const [template, params] = normalizeURL('https://sanifu.run/api/users/12345?ts=1&include=profile');
  assert.equal(template, '/api/users/{param1}?<query-schema>');
  assert.deepEqual(params, []);
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

test('capture allows only configured tab and request origins and drops values', () => {
  const allowed = new Set(['https://approved.example']);
  assert.equal(isApproved({url:'https://approved.example/api',initiator:'https://approved.example/'},allowed),true);
  assert.equal(isApproved({url:'https://other.example/api',initiator:'https://approved.example/'},allowed),false);
  assert.equal(isApproved({url:'https://approved.example/api',initiator:'https://other.example/'},allowed),false);
  const payload=JSON.stringify({password:'BODY_SECRET_123456789012345',message:'private text',items:[{note:'nested secret'}]});
  const body=bodyShape({raw:[{bytes:new TextEncoder().encode(payload)}]});
  assert.equal(body.includes('BODY_SECRET_'),false);
  assert.equal(body.includes('private text'),false);
  assert.equal(body.includes('string'),true);
  const headers=JSON.stringify(headerShape([{name:'Authorization',value:'Bearer HEADER_SECRET_1234567890'},{name:'content-type',value:'application/json; boundary=SECRET'}]));
  assert.equal(headers.includes('HEADER_SECRET_'),false);
  assert.equal(headers.includes('SECRET'),false);
});
