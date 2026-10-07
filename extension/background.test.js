import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizeURL } from './normalize.js';
import { redactHeaders } from './redact.js';
import { bodyShape, headerShape, isApproved, PendingSamples } from './capture.js';

test('normalization retains only explicitly configured route literals', () => {
 const raw='https://approved.example/api/users/alice?token=private';
 assert.deepEqual(normalizeURL(raw),['/{param1}/{param2}/{param3}?<query-schema>',[]]);
 assert.deepEqual(normalizeURL(raw,['/api/users/{identifier}']),['/api/users/{param1}?<query-schema>',[]]);
 assert.deepEqual(normalizeURL(raw,['/api/orders/{identifier}']),normalizeURL(raw));
 for(const bad of [null,'/api/users/alice',{},['/api//users/{id}'],['/api/users/{bad-name}'],['/api/users/{id}/']]){
  assert.equal(JSON.stringify(normalizeURL(raw,bad)).includes('alice'),false);
 }
 assert.deepEqual(normalizeURL('not-a-url'),['',[]]);
 assert.equal(normalizeURL('https://approved.example/'+Array(65).fill('alice').join('/'))[0],'/{path}');
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

test('discovery splits aggregate UTF-8 bytes and retries an owned batch without loss', async () => {
 const prior={chrome:globalThis.chrome,WebSocket:globalThis.WebSocket,fetch:globalThis.fetch,setInterval:globalThis.setInterval};
 const listeners={},accepted=[];let flush,failed=false;
 const event=name=>({addListener:fn=>{listeners[name]=fn}});
 globalThis.chrome={webRequest:{onBeforeRequest:event('start'),onBeforeSendHeaders:event('headers'),onCompleted:event('done'),onErrorOccurred:event('error')}};
 globalThis.WebSocket=class {static OPEN=1;readyState=0;close(){}};
 globalThis.fetch=async(_url,options)=>{
  assert.ok(new TextEncoder().encode(options.body).byteLength<=1<<20,'gateway request exceeds 1 MiB');
  if(!failed){failed=true;throw Error('controlled transient failure')}
  accepted.push(...JSON.parse(options.body).samples.map(s=>s.request_id));
  return {ok:true};
 };
 globalThis.setInterval=fn=>{flush=fn;return 1};
 try {
  await import('./background.js?flush-byte-regression');
  const payload=Object.fromEntries(Array.from({length:64},(_,i)=>['field'+i+'x'.repeat(55),'synthetic']));
  const raw=new TextEncoder().encode(JSON.stringify(payload)).buffer;
  for(let i=0;i<200;i++){
   const request={url:'http://127.0.0.1:18132/api/opaque',initiator:'http://127.0.0.1:18132',method:'POST',type:'xmlhttprequest',requestId:String(i)};
   listeners.start({...request,requestBody:{raw:[{bytes:raw}]}});
   listeners.headers({...request,requestHeaders:Array.from({length:64},(_,j)=>({name:'x-fixture-'+j+'z'.repeat(40),value:'private'}))});
   listeners.done({...request,statusCode:200});
  }
  for(let i=0;i<10;i++)await flush();
  assert.equal(failed,true);
  assert.deepEqual(accepted,Array.from({length:200},(_,i)=>String(i)));
 } finally {
  for(const [key,value] of Object.entries(prior)){if(value===undefined)delete globalThis[key];else globalThis[key]=value}
 }
});

test('in-flight and stalled capture never buffers a raw URL path', async () => {
 const prior={chrome:globalThis.chrome,WebSocket:globalThis.WebSocket,fetch:globalThis.fetch,setInterval:globalThis.setInterval};
 const originalSet=PendingSamples.prototype.set, originalNow=Date.now;
 let pending, now=1000, flush; const listeners={}, requests=[];
 const event=name=>({addListener:fn=>{listeners[name]=fn}});
 PendingSamples.prototype.set=function(key,sample){pending=this;return originalSet.call(this,key,sample)};
 Date.now=()=>now;
 globalThis.chrome={webRequest:{onBeforeRequest:event('start'),onBeforeSendHeaders:event('headers'),onCompleted:event('done'),onErrorOccurred:event('error')}};
 globalThis.WebSocket=class {static OPEN=1;readyState=0;close(){}};
 globalThis.fetch=async(_url,options)=>{requests.push(options.body);return {ok:true}};
 globalThis.setInterval=fn=>{flush=fn;return 1};
 try {
  await import('./background.js?pending-path-regression');
  for(const [index,path] of ['/api/users/alice@example.com','/api/users/alice','/api/users/123456','/api/users/alice%40example.com'].entries()){
   const request={url:'http://127.0.0.1:18132'+path+'?token=private-query',initiator:'http://127.0.0.1:18132',method:'GET',type:'xmlhttprequest',requestId:String(index)};
   listeners.start(request);
   const sample=pending.get(request.requestId);
   assert.ok(sample);
   assert.equal(sample.url_template,'','path must be deferred until completion');
   assert.equal(JSON.stringify(sample).includes('alice'),false);
   assert.equal(JSON.stringify(sample).includes('private-query'),false);
  }
  now+=29999;
  assert.equal(pending.size,4);
  for(let i=0;i<4;i++)assert.equal(pending.get(String(i)).url_template,'');
  await flush(); assert.equal(requests.length,0);
  now++;
  await flush(); assert.equal(pending.size,0); assert.equal(requests.length,0);
 } finally {
  PendingSamples.prototype.set=originalSet; Date.now=originalNow;
  for(const [key,value] of Object.entries(prior)){if(value===undefined)delete globalThis[key];else globalThis[key]=value}
 }
});

test('completed captures never transmit ordinary-name path identifiers', async () => {
 const prior={chrome:globalThis.chrome,WebSocket:globalThis.WebSocket,fetch:globalThis.fetch,setInterval:globalThis.setInterval};
 const listeners={},requests=[];let flush;
 const event=name=>({addListener:fn=>{listeners[name]=fn}});
 globalThis.chrome={webRequest:{onBeforeRequest:event('start'),onBeforeSendHeaders:event('headers'),onCompleted:event('done'),onErrorOccurred:event('error')}};
 globalThis.WebSocket=class {static OPEN=1;readyState=0;close(){}};
 globalThis.fetch=async(_url,options)=>{requests.push(options.body);return {ok:true}};
 globalThis.setInterval=fn=>{flush=fn;return 1};
 try {
  await import('./background.js?completed-path-regression');
  for(const [index,name] of ['alice','private-customer','secret%40example.com'].entries()){
   const request={url:'http://127.0.0.1:18132/api/users/'+name,initiator:'http://127.0.0.1:18132',method:'GET',type:'xmlhttprequest',requestId:String(index)};
   listeners.start(request);listeners.done({...request,statusCode:200});
  }
  await flush();
  assert.equal(requests.length,1);assert.equal(JSON.parse(requests[0]).samples.length,3);
  for(const marker of ['alice','private-customer','secret%40example.com'])assert.equal(requests[0].includes(marker),false,marker+' leaked');
 } finally {
  for(const [key,value] of Object.entries(prior)){if(value===undefined)delete globalThis[key];else globalThis[key]=value}
 }
});
