import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';
import {replayPreviewOperation,replaySendOperation,replayStatus,replayError} from '../src/mail-replay.js';
import {setLanguage} from '../src/i18n.js';

test('replay selection targets an original event and exactly one saved recipient',()=>{
 const e={id:12,created:100,kind:'recovery'},recipient='alarm@example.invalid';
 assert.deepEqual(replayPreviewOperation(e,recipient,[recipient,'other@example.invalid']),{action:'mail_replay_preview',event_id:12,recipient});
 for(const event of [{id:0},{id:1.5},{id:'12'},null])assert.throws(()=>replayPreviewOperation(event,recipient,[recipient]));
 assert.throws(()=>replayPreviewOperation(e,'external@example.invalid',[recipient]));
});
test('submission sends only the immutable preview id and reuses it after an uncertain response',()=>{
 const event={id:12},recipient='alarm@example.invalid',preview={id:'a'.repeat(32),event_id:12,recipient,subject:'Real subject',body:'Real message'};
 const expected={action:'mail_replay_send',id:preview.id};
 assert.deepEqual(replaySendOperation(preview,event,recipient),expected);
 assert.deepEqual(replaySendOperation(preview,event,recipient),expected);
 assert.throws(()=>replaySendOperation(preview,{id:13},recipient));
 assert.throws(()=>replaySendOperation(preview,event,'other@example.invalid'));
 assert.throws(()=>replaySendOperation(null,event,recipient));
});
test('manual states distinguish queued, retry, permanent failure, cancellation and SMTP acceptance',()=>{
 setLanguage('en');
 try{
  assert.equal(replayStatus({state:'submitted'}),'Accepted by the SMTP server');
  assert.equal(replayStatus({state:'failed'}),'Submission failed');
  assert.equal(replayStatus({state:'cancelled'}),'Submission cancelled');
  assert.equal(replayStatus({state:'queued'}),'Queued for submission');
  assert.equal(replayStatus({state:'queued',error:'mail_timeout'}),'Retry queued');
  assert.match(replayError('mail_timeout'),/may already have been accepted/);
  assert.equal(replayError('unknown private response'),'Submission failed');
 }finally{setLanguage('de');}
});
test('actual replay dialog offers one saved recipient and explicit preview/send with escaped original content',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true,hmr:false,ws:false},appType:'custom'});
 try{
  const {default:Dialog}=await server.ssrLoadModule('/src/MailReplay.vue');
  const props={event:{id:12,created:100,device_name:'Server',message:'<script>unsafe</script>'},dashboard:{user:{role:'administrator'},mail:{revision:1,settings:{enabled:false,recipients:['alarm@example.invalid','other@example.invalid']}}}};
  let html=await renderToString(createSSRApp(Dialog,props));
  assert.match(html,/role="dialog"/);assert.match(html,/Versandvorschau erstellen/);assert.match(html,/Manueller Versandverlauf/);
  assert.match(html,/&lt;script&gt;unsafe&lt;\/script&gt;/);assert.doesNotMatch(html,/<script>unsafe/);
  assert.match(html,/alarm@example.invalid/);assert.match(html,/other@example.invalid/);
  assert.doesNotMatch(html,/Einmalig an ausgewählten Empfänger senden/);
  assert.doesNotMatch(html,/type="email"|multiple/);
  props.dashboard.user.role='viewer';html=await renderToString(createSSRApp(Dialog,props));assert.doesNotMatch(html,/role="dialog"/);
 }finally{await server.close();}
});
