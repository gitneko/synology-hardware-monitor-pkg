import test from 'node:test';
import assert from 'node:assert/strict';
import {downloadBackup,backupFilename} from '../src/backup-download.js';
const id='a'.repeat(32),token='synthetic-token+/=';
const login=()=>({ok:true,json:async()=>({success:true,SynoToken:token})});
function attachment(overrides={}){
 return {ok:true,headers:new Headers({'Content-Type':'application/octet-stream','Content-Disposition':'attachment; filename="HardwareMonitor-backup.hmbackup"','Content-Length':String(8*1024**3)}),
  blob:()=>assert.fail('must not buffer a backup'),arrayBuffer:()=>assert.fail('must not buffer a backup'),text:()=>assert.fail('must not read a HEAD body'),...overrides};
}
test('checks a large attachment using fresh DSM headers, then navigates with encoded query token and explicit filename',async()=>{
 const calls=[],saved=[],controller=new AbortController();
 await downloadBackup(id,{signal:controller.signal,save:(...args)=>saved.push(args),request:async(url,options)=>{
  calls.push(url);assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');assert.equal(options.signal,controller.signal);
  if(url==='/webman/login.cgi')return login();
  assert.equal(options.method,'HEAD');assert.equal(options.headers['X-SYNO-TOKEN'],token);assert.ok(!url.includes('SynoToken'));return attachment();
 }});
 assert.deepEqual(calls,['/webman/login.cgi','./api.cgi?download='+id]);
 assert.deepEqual(saved,[['./api.cgi?download='+id+'&SynoToken='+encodeURIComponent(token),backupFilename]]);
});
test('HTML login/error pages, JSON denials, expired jobs, missing attachment and zero length never initiate downloads',async()=>{
 for(const response of [attachment({ok:false}),attachment({headers:new Headers({'Content-Type':'text/html'})}),attachment({headers:new Headers({'Content-Type':'application/json'})}),attachment({headers:new Headers({'Content-Type':'application/octet-stream'})}),attachment({headers:new Headers({'Content-Type':'application/octet-stream','Content-Disposition':'attachment','Content-Length':'0'})})]){
  await assert.rejects(downloadBackup(id,{request:async url=>url==='/webman/login.cgi'?login():response,save:()=>assert.fail('must not download an error page')}));
 }
});
test('expired DSM sessions and redirects fail safely without exposing the token or creating a download',async()=>{
 for(const request of [async()=>({ok:true,json:async()=>({success:false})}),async url=>{if(url==='/webman/login.cgi')return login();throw new Error('private-server-details-'+token);}]){
  await assert.rejects(downloadBackup(id,{request,save:()=>assert.fail()}),e=>!e.message.includes(token)&&!e.message.includes('private-server-details'));
 }
 await assert.rejects(downloadBackup('../monitor.db',{request:()=>assert.fail(),save:()=>assert.fail()}));
});
test('cookie-only local mode still validates the file and native navigation has no token',async()=>{
 globalThis.HARDWARE_MONITOR_LOCAL=true;
 try{await downloadBackup(id,{request:async(url,options)=>{assert.equal(url,'./api.cgi?download='+id);assert.equal(options.headers['X-SYNO-TOKEN'],undefined);return attachment();},save:(url,name)=>{assert.equal(url,'./api.cgi?download='+id);assert.equal(name,backupFilename);}});}
 finally{delete globalThis.HARDWARE_MONITOR_LOCAL;}
});
test('native attachment uses a .hmbackup filename, suppresses referrers and removes its temporary link',async()=>{
 const previous=Object.getOwnPropertyDescriptor(globalThis,'document');let link,clicked=false,removed=false;
 try{
  Object.defineProperty(globalThis,'document',{configurable:true,value:{createElement:tag=>{assert.equal(tag,'a');return link={click:()=>clicked=true,remove:()=>removed=true};},body:{append:value=>assert.equal(value,link)}}});
  await downloadBackup(id,{request:async url=>url==='/webman/login.cgi'?login():attachment()});
  assert.ok(clicked&&removed);assert.equal(link.download,backupFilename);assert.equal(link.referrerPolicy,'no-referrer');assert.equal(link.rel,'noreferrer');
 }finally{if(previous)Object.defineProperty(globalThis,'document',previous);else delete globalThis.document;}
});
