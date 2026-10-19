import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';
import {acknowledgementOperation} from '../src/alarm-actions.js';
import {overall,observationStatus,observationLabel} from '../src/health.js';
import {deliveryText} from '../src/events.js';

const device=()=>({device:{id:'server'},revision:7,stale:false,overall_status:'acknowledged',snapshot:{observations:[{key:'fan',health:'critical'}],capabilities:[]},alarms:[],alarm_statuses:{fan:{status:'acknowledged'}}});
const alarm=()=>({key:'fan',label:'System fan',health:'critical',current_health:'critical',observed:100,covered_by:[],assessment:{token:'synthetic-incident-version',status:'critical',derived:false}});
test('operator actions target the displayed incident and require a bounded reason',()=>{
 const d=device(),a=alarm();
 assert.deepEqual(acknowledgementOperation(d,a,true,'  Verified input failure  '),{action:'alarm_acknowledge',id:'server',revision:7,key:'fan',token:a.assessment.token,acknowledged:true,reason:'Verified input failure'});
 for(const reason of ['', ' ', 'x\ny','ä'.repeat(501)])assert.throws(()=>acknowledgementOperation(d,a,true,reason));
 for(const key of ['collector','coverage:/redfish/v1/','log:fan'])assert.throws(()=>acknowledgementOperation(d,{...a,key},true,'reason'));
 assert.throws(()=>acknowledgementOperation(d,{...a,assessment:{...a.assessment,derived:true}},true,'reason'));
 assert.throws(()=>acknowledgementOperation(d,{...a,assessment:{}},true,'reason'));
 assert.equal(acknowledgementOperation(d,a,false).acknowledged,false);
});
test('server assessment drives rows and overall state while raw severity and uncertainty survive',()=>{
 const d=device(),o=d.snapshot.observations[0];
 assert.equal(overall(d),'acknowledged');assert.equal(observationStatus(o,d.snapshot,d),'acknowledged');assert.equal(observationLabel(o,d.snapshot,d),'Bestätigt');
 assert.equal(o.health,'critical');
 d.overall_status='warning';assert.equal(overall(d),'warning');
 d.overall_status='unknown';assert.equal(overall(d),'unknown');
 d.overall_status='acknowledged';d.stale=true;assert.equal(overall(d),'unknown');
});
test('suppression is explained independently for email and desktop without hiding submitted progress',()=>{
 assert.match(deliveryText({mail_reason:'acknowledged',desktop_reason:'acknowledged'}),/Bestätigung unterdrückt/);
 const submitted=deliveryText({transport:'smtp',delivered:100,total_recipients:2,submitted_recipients:2,desktop_reason:'acknowledged'});
 assert.match(submitted,/SMTP-Server angenommen/);assert.match(submitted,/DSM-Desktop: durch Bestätigung/);
});
test('alarm controls expose reasons and review state, and keep viewers and derived parents read-only',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true,hmr:false,ws:false},appType:'custom'});
 try{
  const {default:Row}=await server.ssrLoadModule('/src/AlarmRow.vue');
  const a=alarm(),d=device(),dashboard={user:{role:'administrator'}};
  let html=await renderToString(createSSRApp(Row,{alarm:a,device:d,dashboard}));
  assert.match(html,/Bestätigen …/);assert.match(html,/textarea[^>]*required/);assert.match(html,/Neue Hardwarelog-Einträge bleiben separat aktiv/);
  a.assessment.status='acknowledged';a.assessment.acknowledgement={actor:'operator',created:100,reason:'<script>unsafe</script>',needs_review:false};
  html=await renderToString(createSSRApp(Row,{alarm:a,device:d,dashboard}));
  assert.match(html,/Bestätigung aufheben …/);assert.match(html,/Hardwarezustand:/);assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>unsafe/);
  a.assessment.status='warning';a.assessment.acknowledged=true;
  html=await renderToString(createSSRApp(Row,{alarm:a,device:d,dashboard}));assert.match(html,/Bestätigung aufheben …/);assert.match(html,/Warnung/);
  a.assessment.acknowledged=false;
  a.assessment.acknowledgement.needs_review=true;a.assessment.status='critical';
  html=await renderToString(createSSRApp(Row,{alarm:a,device:d,dashboard}));assert.match(html,/Importierte Bestätigung prüfen/);
  for(const props of [{alarm:a,device:d,dashboard:{user:{role:'viewer'}}},{alarm:{...a,assessment:{...a.assessment,derived:true}},device:d,dashboard}]){
   html=await renderToString(createSSRApp(Row,props));assert.doesNotMatch(html,/class="refresh alarm-action"/);
  }
 }finally{await server.close();}
});
