import test from 'node:test';
import assert from 'node:assert/strict';
import {uploadFile,uploadChunkSize,waitJob} from '../src/maintenance.js';
import {setLanguage} from '../src/i18n.js';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';
const dashboard={user:{role:'administrator'},csrf:'synthetic-proof'};
const response=body=>({ok:true,json:async()=>body});
test('uploads read bounded slices, retry the same offset and use refreshed session proofs',async()=>{
 let token=0;const bytes=new Uint8Array(uploadChunkSize*2+13);bytes.fill(123);
 const original=new Blob([bytes]),slices=[],operations=[];let failed=false;
 const file={size:original.size,slice:(start,end)=>{slices.push([start,end]);return original.slice(start,end);},arrayBuffer:()=>assert.fail('whole-file buffering')};
 let accepted=0;
 const request=async(url,options)=>{
  if(url==='/webman/login.cgi')return response({success:true,SynoToken:'fresh-dsm-proof'});
  const body=JSON.parse(options.body);operations.push(body);
  assert.equal(body.csrf,'proof-'+token++);
  const op=body.operation,part=Uint8Array.from(atob(op.data),c=>c.charCodeAt(0));
  assert.ok(part.length<=uploadChunkSize);assert.ok(part.every(b=>b===123));
  if(op.offset===0&&!failed){failed=true;accepted=part.length;throw new Error('response lost after accepting bytes');}
  accepted=Math.max(accepted,op.offset+part.length);return response({ok:true,bytes:accepted});
 };
 await uploadFile(()=>({...dashboard,csrf:'proof-'+token}),'job',file,{request});
 assert.equal(slices.length,3);assert.equal(operations.length,4);assert.deepEqual(operations[0].operation,operations[1].operation);
 assert.equal(accepted,file.size);
});
test('job failures, invalid upload acknowledgement and cancellation remain failures',async()=>{
 for(const state of ['failed','cancelled'])await assert.rejects(waitJob(dashboard,'job',{request:async url=>url==='/webman/login.cgi'?response({success:true}):response({ok:true,status:{state,code:'synthetic-error'}})}),/synthetic-error/);
 await assert.rejects(uploadFile(dashboard,'job',new Blob(['a']),{request:async url=>url==='/webman/login.cgi'?response({success:true}):response({ok:true,bytes:2})}));
 const controller=new AbortController();
 await assert.rejects(waitJob(dashboard,'job',{signal:controller.signal,onProgress:()=>controller.abort(),request:async url=>url==='/webman/login.cgi'?response({success:true}):response({ok:true,status:{state:'running'}})}),e=>e.name==='AbortError');
});
test('history and backup panels expose independent retention, audit bounds and streaming workflow',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  const locale=await server.ssrLoadModule('/src/i18n.js');locale.setLanguage('en');
  const {default:History}=await server.ssrLoadModule('/src/HistorySettings.vue');
  const history=await renderToString(createSSRApp(History,{dashboard:{...dashboard,history:{settings:{events_days:90,hardware_logs_days:30},revision:4}}}));
  assert.match(history,/Retain event history/);assert.match(history,/Retain hardware logs/);assert.match(history,/10&#39;000|10,000/);assert.match(history,/Preview cleanup/);assert.match(history,/value="30"/);assert.match(history,/value="90"/);
  const {default:Backup}=await server.ssrLoadModule('/src/BackupSettings.vue');
  const backup=await renderToString(createSSRApp(Backup,{dashboard}));
  assert.match(backup,/background|chunks/);assert.doesNotMatch(backup,/128 MiB|192 MiB/);
 }finally{setLanguage('de');await server.close();}
});
