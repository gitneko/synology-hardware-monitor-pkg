import test from 'node:test';
import assert from 'node:assert/strict';
import {updateSession} from '../src/session.js';
const data={user:{name:'test-admin',role:'administrator'},devices:[{id:'private-device'}]};
const state=()=>({dashboard:data,error:'',authRequired:false});
const response=(body,status=200)=>({status,ok:status>=200&&status<300,json:async()=>body});
const login=()=>response({success:true,SynoToken:'test-token-marker'});
const authenticated=()=>response({ok:true,data});
function withSession(api){return async(url,options)=>url==='/webman/login.cgi'?login():api(url,options);}

test('existing DSM token reaches API header and never visible state or URLs',async()=>{
  const s=state(),calls=[];
  await updateSession(s,async(url,options)=>{
    calls.push(url);assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');
    if(url==='/webman/login.cgi')return login();
    assert.equal(url,'./api.cgi');assert.equal(options.headers['X-SYNO-TOKEN'],'test-token-marker');return authenticated();
  });
  assert.deepEqual(calls,['/webman/login.cgi','./api.cgi']);assert.deepEqual(s.dashboard,data);
  assert.ok(!JSON.stringify(s).includes('test-token-marker'));assert.ok(!calls.join(' ').includes('test-token-marker'));
});
test('session expiration removes previous hardware data and diagnoses with same header',async()=>{
  const s=state();
  await updateSession(s,withSession(async(url,options)=>{
    assert.equal(options.headers['X-SYNO-TOKEN'],'test-token-marker');
    if(url==='./api.cgi')return {status:403,ok:false,json:()=>{throw new Error('HTML denial page');}};
    assert.equal(url,'./api.cgi?diagnose=1');return response({ok:false,code:'dsm_helper_failed',source:'hardware-monitor'});
  }));
  assert.equal(s.dashboard,null);assert.equal(s.authRequired,true);assert.match(s.error,/dsm_helper_failed/);
});
test('logged-out DSM response prevents any device API call',async()=>{
  const s=state();let calls=0;
  await updateSession(s,async(url)=>{calls++;assert.equal(url,'/webman/login.cgi');return response({success:false});});
  assert.equal(calls,1);assert.equal(s.dashboard,null);assert.equal(s.authRequired,true);
});
test('network errors and HTML responses cannot retain a previous dashboard',async()=>{
  for(const api of [async()=>{throw new Error('offline');},async()=>({status:404,ok:false,json:async()=>{throw new Error('HTML');}})]){
    const s=state();await updateSession(s,withSession(api));assert.equal(s.dashboard,null);assert.ok(s.error);
  }
});
test('authenticated response unlocks view; identity-less response cannot',async()=>{
  const s={dashboard:null,error:'old error',authRequired:true};
  await updateSession(s,withSession(async()=>authenticated()));
  assert.deepEqual(s.dashboard,data);assert.equal(s.error,'');assert.equal(s.authRequired,false);
  await updateSession(s,withSession(async()=>response({ok:true,data:{devices:[]}})));assert.equal(s.dashboard,null);
});
test('each refresh reads current session instead of retaining an old token',async()=>{
  const s=state();let counter=0;
  const request=async(url,options)=>{
    if(url==='/webman/login.cgi')return response({success:true,SynoToken:`token-${++counter}`});
    assert.equal(options.headers['X-SYNO-TOKEN'],`token-${counter}`);return authenticated();
  };
  await updateSession(s,request);await updateSession(s,request);assert.equal(counter,2);
});
test('invalid token or HTML session response is neither forwarded nor displayed',async()=>{
  for(const session of [{success:true,SynoToken:'private-marker\r\nInjected: value'},{success:true,SynoToken:12},null]){
    const s=state();let calls=0;
    await updateSession(s,async()=>{calls++;return session?response(session):{ok:false,json:async()=>{throw new Error('private-marker');}};});
    assert.equal(calls,1);assert.equal(s.dashboard,null);assert.ok(!s.error.includes('private-marker'));
  }
});
test('cookie-only DSM configuration still requires native API confirmation',async()=>{
  const s=state();let calls=0;
  await updateSession(s,async(url,options)=>{
    calls++;if(url==='/webman/login.cgi')return response({success:true});
    assert.equal(options.headers['X-SYNO-TOKEN'],undefined);assert.equal(options.headers['X-HardwareMonitor-Language'],'de');return authenticated();
  });
  assert.equal(calls,2);assert.deepEqual(s.dashboard,data);
});
