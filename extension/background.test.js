import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isDynamicSeg, normalizeURL } from './normalize.js';
import { redactHeaders } from './redact.js';
import { bodyShape, headerShape, isApproved, PendingSamples } from './capture.js';

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
  const body=bodyShape({raw:[{bytes:new TextEncoder().encode(payload).buffer}]});
  assert.equal(body.includes('BODY_SECRET_'),false);
  assert.equal(body.includes('private text'),false);
  assert.equal(body.includes('string'),true);
  const headers=JSON.stringify(headerShape([{name:'Authorization',value:'Bearer HEADER_SECRET_1234567890'},{name:'content-type',value:'application/json; boundary=SECRET'}]));
  assert.equal(headers.includes('HEADER_SECRET_'),false);
  assert.equal(headers.includes('SECRET'),false);
});


test('raw body shaping rejects oversized parts before reading or copying the remainder', () => {
 let touched=false;
 const raw=[{bytes:new ArrayBuffer(65537)},{get bytes(){touched=true;throw Error('must not read remainder')}}];
 assert.deepEqual(JSON.parse(bodyShape({raw})),{'$raw':'oversize'});
 assert.equal(touched,false);
 assert.deepEqual(JSON.parse(bodyShape({raw:[{bytes:new ArrayBuffer(40000)},{bytes:new ArrayBuffer(40000)}]})),{'$raw':'oversize'});
});


test('aborted captures are removed before completion and discovery flush', async () => {
 const prior={chrome:globalThis.chrome,WebSocket:globalThis.WebSocket,fetch:globalThis.fetch,setInterval:globalThis.setInterval};
 const listeners={},requests=[];let flush;
 const event=name=>({addListener:fn=>{listeners[name]=fn}});
 globalThis.chrome={webRequest:{onBeforeRequest:event('start'),onBeforeSendHeaders:event('headers'),onCompleted:event('done'),onErrorOccurred:event('error')}};
 globalThis.WebSocket=class {static OPEN=1;readyState=0;close(){}};
 globalThis.fetch=async(_url,options)=>{requests.push(JSON.parse(options.body));return {ok:true}};
 globalThis.setInterval=fn=>{flush=fn;return 1};
 try {
  await import('./background.js?abort-regression');
  assert.equal(typeof listeners.error,'function');
  const request={url:'http://127.0.0.1:18132/api/opaque',initiator:'http://127.0.0.1:18132',method:'POST',type:'xmlhttprequest',requestId:'aborted'};
  listeners.start(request);
  listeners.error(request);
  listeners.done({...request,statusCode:200});
  await flush();
  assert.equal(requests.length,0);
  const complete={...request,requestId:'complete'};
  listeners.start(complete);
  listeners.done({...complete,statusCode:200});
  await flush();
  assert.equal(requests.length,1);
  assert.equal(requests[0].samples.length,1);
  assert.equal(requests[0].samples[0].request_id,'complete');
 } finally {
  for(const [key,value] of Object.entries(prior)){if(value===undefined)delete globalThis[key];else globalThis[key]=value}
 }
});


test('pending capture entries have hard count and age limits', () => {
 let now=1000;
 const pending=new PendingSamples({maxEntries:3,maxAgeMs:100,now:()=>now});
 for(let i=0;i<20;i++)pending.set(String(i),{method:'GET'});
 assert.equal(pending.size,3);
 assert.equal(pending.get('0'),undefined);
 assert.deepEqual(pending.get('19'),{method:'GET'});
 pending.delete('19');
 assert.equal(pending.size,2);
 now+=100;
 assert.equal(pending.size,0);
 assert.equal(pending.get('18'),undefined);
 assert.throws(()=>new PendingSamples({maxEntries:201}));
});

test('deep raw metadata is truncated without retaining values', () => {
 let value='private fixture value';
 for(let i=0;i<100;i++)value={child:value};
 const shape=bodyShape({raw:[{bytes:new TextEncoder().encode(JSON.stringify(value)).buffer}]});
 assert.equal(shape.includes('private fixture value'),false);
 assert.equal(shape.includes('truncated'),true);
});
