import {spawn} from 'node:child_process';
import {mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import http from 'node:http';

const root=resolve(new URL('..',import.meta.url).pathname);
const chrome=process.env.CHROME_BIN||'/usr/bin/google-chrome';
const owned=await mkdtemp(join(root,'../cache/eaap-browser-fixture-'));
// Chrome singleton sockets require a short path; this directory is owned by this run.
const socketTmp=await mkdtemp('/tmp/eaap-fixture-');
const samples=[],appRequests=[]; const app=http.createServer(async(req,res)=>{
 appRequests.push(req.url);
 if(req.url==='/'){res.writeHead(200,{'content-type':'text/html'});res.end(`<script>fetch('/api/users/alice?token=URL_SECRET_12345678901234567890',{method:'POST',headers:{authorization:'Bearer HEADER_SECRET_12345678901234567890','content-type':'application/json'},body:JSON.stringify({password:'BODY_SECRET_12345678901234567890',note:'private'})})</script>`);return}
 res.writeHead(200,{'content-type':'application/json'});res.end('{}');
});
const gateway=http.createServer(async(req,res)=>{let b='';for await(const c of req)b+=c;if(req.url==='/internal/discovery'){samples.push(b);res.writeHead(202);res.end();}else{res.writeHead(404);res.end();}});
function listen(server,port){return new Promise((ok,no)=>server.once('error',no).listen(port,'127.0.0.1',ok));}
await Promise.all([listen(gateway,18131),listen(app,18132)]);
const health=await fetch('http://127.0.0.1:18132/health');if(!health.ok)throw Error('owned fixture health failed');
let browser;
async function session(index){
 const sampleStart=samples.length;
 const ext=join(owned,`extension-${index}`);await mkdir(ext,{recursive:true});
 for(const f of ['background.js','capture.js','normalize.js','redact.js','executor.js','manifest.json']) await writeFile(join(ext,f),await readFile(join(root,'extension',f)));
 const allow=JSON.parse(await readFile(join(root,'extension/allowlist.json'),'utf8'));allow.gateway_ws_url='ws://127.0.0.1:18131/internal/extension';allow.discovery_url='http://127.0.0.1:18131/internal/discovery';allow.allowed_origins=['http://127.0.0.1:18132'];allow.capture_path_templates={'http://127.0.0.1:18132':['/api/users/{identifier}']};allow.flush_interval_ms=750;await writeFile(join(ext,'allowlist.json'),JSON.stringify(allow));
 // Synthetic, disposable profiles only: avoid host keyring prompts on headless Linux.
 browser=spawn(chrome,['--password-store=basic','--headless=new','--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run','--no-default-browser-check','--no-proxy-server','--disable-gpu','--disable-features=Vulkan','--disable-software-rasterizer','--use-gl=disabled','--remote-debugging-pipe','--enable-unsafe-extension-debugging',`--user-data-dir=${join(owned,`profile-${index}`)}`,'about:blank'],{stdio:['ignore','ignore','pipe','pipe','pipe'],env:{...process.env,TMPDIR:socketTmp},detached:true});
 let sequence=0,buffer='';const pending=new Map(),workerEvents=[];let stderr='';browser.stderr.on('data',c=>stderr+=c.toString());
 browser.stdio[4].on('error',()=>{});browser.stdio[3].on('error',()=>{});browser.stdio[4].on('data',chunk=>{buffer+=chunk;let at;while((at=buffer.indexOf('\0'))>=0){const line=buffer.slice(0,at);buffer=buffer.slice(at+1);if(!line)continue;const e=JSON.parse(line),p=pending.get(e.id);if(p){pending.delete(e.id);clearTimeout(p.timer);e.error?p.reject(Error(JSON.stringify(e.error))):p.resolve(e.result);}else if(e.sessionId)workerEvents.push(e)}});
 const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(Error(`timeout ${method}; stderr=${stderr.slice(-1500)}`));},15000);pending.set(id,{resolve,reject,timer});browser.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0');});
 try{
   await send('Browser.getVersion');const loaded=await send('Extensions.loadUnpacked',{path:ext});let worker;
   const until=Date.now()+12000;while(Date.now()<until){const targets=await send('Target.getTargets');worker=targets.targetInfos.find(t=>t.type==='service_worker'&&t.url===`chrome-extension://${loaded.id}/background.js`);if(worker)break;await new Promise(r=>setTimeout(r,200));}
   if(!worker)throw Error(`EAAP worker missing (extension ${loaded.id}): ${stderr.slice(-2500)}`);
   const {sessionId}=await send('Target.attachToTarget',{targetId:worker.targetId,flatten:true});
   await send('Runtime.enable',{},sessionId);
   let info; const readyDeadline=Date.now()+15000;
   do {
   info=await send('Runtime.evaluate',{expression:'(globalThis.chrome?.runtime?.id ? {id:chrome.runtime.id,manifest:chrome.runtime.getManifest().name,permissions:chrome.runtime.getManifest().permissions,webRequest:!!chrome.webRequest,beforeRequest:chrome.webRequest.onBeforeRequest.hasListeners(),beforeHeaders:chrome.webRequest.onBeforeSendHeaders.hasListeners(),completed:chrome.webRequest.onCompleted.hasListeners(),errors:chrome.webRequest.onErrorOccurred.hasListeners()} : null)',returnByValue:true,awaitPromise:true},sessionId);
   if(info.result?.value?.id===loaded.id && info.result.value.beforeRequest && info.result.value.beforeHeaders && info.result.value.completed && info.result.value.errors)break;
   await new Promise(r=>setTimeout(r,100));
   } while(Date.now()<readyDeadline);
   if(info.result?.value?.id!==loaded.id || !info.result.value.beforeRequest || !info.result.value.beforeHeaders || !info.result.value.completed || !info.result.value.errors)throw Error(`unexpected worker ${JSON.stringify(info)}`);
   const page=await send('Target.createTarget',{url:'about:blank'});
   const attached=await send('Target.attachToTarget',{targetId:page.targetId,flatten:true});
   await send('Network.enable',{},attached.sessionId);
   await send('Page.enable',{},attached.sessionId);
   await send('Runtime.enable',{},attached.sessionId);
   await send('Runtime.runIfWaitingForDebugger',{},attached.sessionId);
   await send('Page.navigate',{url:'http://127.0.0.1:18132/'},attached.sessionId);
   const captureDeadline=Date.now()+10000;
   while(samples.length===sampleStart && Date.now()<captureDeadline) await new Promise(r=>setTimeout(r,100));
   const captured=samples.slice(sampleStart).flatMap(body=>JSON.parse(body).samples);
   const post=captured.find(sample=>sample.method==='POST' && sample.template==='/api/users/{param1}?<query-schema>');
   if(!post || JSON.parse(post.request_body || '{}').note!=='string' || post.request_headers.authorization!=='present' || post.request_headers['content-type']!=='application/json') throw Error(`profile ${index} did not capture sanitized body and header metadata: ${JSON.stringify(captured)}`);
   const opened=await send('Runtime.evaluate',{expression:'({url:location.href,state:document.readyState,body:document.body?.textContent})',returnByValue:true},attached.sessionId);
   if(opened.result?.value?.state!=='complete')throw Error(`profile ${index} page incomplete`);
   await send('Browser.close');return {index,capturedSamples:captured.length,id:loaded.id,worker:worker.url,tab:opened.result?.value,manifest:info.result.value,workerEvents:workerEvents.map(e=>({method:e.method,detail:e.params?.exceptionDetails?.text||e.params?.args?.map(a=>a.value||a.description).join(' ')})),stderr:stderr.slice(-2500)};
 } catch(error) { console.error(JSON.stringify({appRequests,events:workerEvents.filter(e=>e.method.startsWith('Network.')||e.method.startsWith('Page.')),stderr}));throw error; } finally {try{process.kill(-browser.pid,'SIGTERM')}catch{};await new Promise(r=>setTimeout(r,300));try{process.kill(-browser.pid,'SIGKILL')}catch{};await new Promise(r=>{if(browser.exitCode!==null)r();else{browser.once('exit',r);setTimeout(r,1000).unref();}});}
}
try{
 const sessions=[await session(1),await session(2)];
 const captured=samples.join('\n');
 for(const secret of ['URL_SECRET_','HEADER_SECRET_','BODY_SECRET_','private','alice'])if(captured.includes(secret))throw Error(`fixture leaked ${secret}`);
 if(samples.length<2)throw Error(`expected discovery from two isolated profiles, got ${samples.length}; appRequests=${JSON.stringify(appRequests)}; sessions=${JSON.stringify(sessions)}`);
 console.log(JSON.stringify({sessions,sampleCount:samples.length,redacted:true,owned},null,2));
} finally {gateway.close();app.close();await rm(socketTmp,{recursive:true,force:true});await rm(owned,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
