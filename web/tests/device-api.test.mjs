import test from 'node:test';
import assert from 'node:assert/strict';
import {administer} from '../src/device-api.js';
const dashboard={user:{role:'administrator'},csrf:'package-proof'};
const response=(body,status=200)=>({ok:status>=200&&status<300,json:async()=>body});
const login=()=>response({success:true,SynoToken:'dsm-proof'});
test('writes use fresh DSM token and separate package CSRF proof with no credentials in URL',async()=>{
  const operation={action:'save',device:{password:'private-password-marker'}};
  const controller=new AbortController(),calls=[];
  const request=async(url,options)=>{
    calls.push(url);assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');assert.equal(options.signal,controller.signal);
    if(url==='/webman/login.cgi')return login();
    assert.equal(url,'./api.cgi');assert.equal(options.method,'POST');
    assert.equal(options.headers['X-SYNO-TOKEN'],'dsm-proof');assert.equal(options.headers['Content-Type'],'application/json');
    assert.deepEqual(JSON.parse(options.body),{csrf:'package-proof',operation});return response({ok:true,id:'new-device'});
  };
  assert.equal((await administer(dashboard,operation,request,controller.signal)).id,'new-device');
  assert.deepEqual(calls,['/webman/login.cgi','./api.cgi']);
  assert.ok(!calls.join(' ').includes('private-password-marker'));
});
test('viewer or absent package token prevents writes before any request',async()=>{
  for(const state of [null,{user:{role:'viewer'},csrf:'proof'},{user:{role:'administrator'}}]){
    await assert.rejects(administer(state,{action:'delete'},async()=>{assert.fail('must not request');}),/Administrator/);
  }
});
test('HTTP 200 application denial, HTTP failure, invalid JSON and expired DSM session stay failures',async()=>{
  for(const api of [response({ok:false,error:'Abgewiesen'}),response({ok:true},403),{ok:true,json:async()=>{throw new Error('HTML');}}]){
    await assert.rejects(administer(dashboard,{action:'test'},async(url)=>url==='/webman/login.cgi'?login():api));
  }
  let calls=0;
  await assert.rejects(administer(dashboard,{action:'save'},async()=>{calls++;return response({success:false});}));
  assert.equal(calls,1);
});
