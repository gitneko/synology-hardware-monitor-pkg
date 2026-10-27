import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';

test('saved SNMPv3 sender without approval has a prominent, actionable notice',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  const {default:Notice}=await server.ssrLoadModule('/src/SnmpIdentityNotice.vue');
  const {setLanguage}=await server.ssrLoadModule('/src/i18n.js');
  const entry={revision:2,device:{id:'sender',name:'<Dell server>',enabled:true,snmp_poll:{host:'192.0.2.1'},snmp_traps:{enabled:true,security:{version:'v3'},engine_ids:[]}}};
  let html=await renderToString(createSSRApp(Notice,{entry}));
  assert.match(html,/role="alert"/);assert.match(html,/Gespeichert – SNMPv3-Trap-Empfang noch gesperrt/);assert.match(html,/&lt;Dell server&gt;/);assert.match(html,/class="primary"/);assert.match(html,/Senderidentität prüfen/);
  setLanguage('en');html=await renderToString(createSSRApp(Notice,{entry}));assert.match(html,/Saved – SNMPv3 trap reception is still blocked/);assert.match(html,/Verify sender identity/);setLanguage('de');
  for(const change of [
   value=>{value.device.snmp_traps.engine_ids=['8000000001'];},
   value=>{value.device.snmp_traps.security.version='v2c';},
   value=>{value.device.snmp_traps.enabled=false;},
   value=>{value.device.enabled=false;},
   value=>{delete value.device.snmp_traps;},
  ]){
   const saved=structuredClone(entry);change(saved);
   html=await renderToString(createSSRApp(Notice,{entry:saved}));assert.doesNotMatch(html,/role="alert"|noch gesperrt|<button/);
  }
  html=await renderToString(createSSRApp(Notice,{}));assert.doesNotMatch(html,/<button/);
  const missingTarget=structuredClone(entry);delete missingTarget.device.snmp_poll;
  html=await renderToString(createSSRApp(Notice,{entry:missingTarget}));assert.match(html,/SNMP-Abfrageziel/);assert.match(html,/Senderprüfung einrichten/);

 }finally{await server.close();}
});
