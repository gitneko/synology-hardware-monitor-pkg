import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';

test('device editor defaults to Standard and renders pinned devices with their fingerprint',async()=>{
 const previous=Object.getOwnPropertyDescriptor(globalThis,'document');
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  Object.defineProperty(globalThis,'document',{configurable:true,value:{activeElement:null,cookie:'lang=ger'}});
  const {default:Editor}=await server.ssrLoadModule('/src/DeviceEditor.vue');
  const standard=await renderToString(createSSRApp(Editor,{entry:null,dashboard:{}}));
  assert.match(standard,/value="standard" selected/);
  assert.match(standard,/Öffentlich vertrauenswürdiges Zertifikat/);
  assert.doesNotMatch(standard,/Genau diesem Serverzertifikat vertrauen/);
  const pinned=await renderToString(createSSRApp(Editor,{entry:{device:{id:'synthetic',tls_profile:'idrac7',custom_trust:true,certificate_fingerprint:'AA:BB:CC'}},dashboard:{}}));
  assert.match(pinned,/value="idrac7" selected/);
  assert.match(pinned,/Genau diesem Serverzertifikat vertrauen/);
  assert.match(pinned,/AA:BB:CC/);
  assert.match(pinned,/value="keep" selected/);
  assert.doesNotMatch(pinned,/Öffentlich vertrauenswürdiges Zertifikat/);
  for(const protocol of ['redfish','snmp'])for(const traps of [false,true]){
   const entry={device:{id:'synthetic',primary_protocol:protocol,hardware_log:{mode:'latest',limit:123},snmp_poll:{host:'192.0.2.10',security:{version:'v2c'},profile:'generic'},snmp_traps:traps?{enabled:true,security:{version:'v2c'},profile:'generic',allowed_sources:['192.0.2.10']}:null}};
   const html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));
   if(protocol==='redfish'){
    assert.match(html,/Hardwarelog lesen/);assert.match(html,/Anzahl Hardwarelog-Einträge/);
    assert.match(html,/value="123"/);assert.match(html,/Die Aufbewahrungsfrist gilt unabhängig/);
   }else{
    assert.doesNotMatch(html,/Hardwarelog lesen|Anzahl Hardwarelog-Einträge|Die Aufbewahrungsfrist gilt unabhängig/);
    assert.match(html,/SNMP-Traps empfangen/);
   }
  }
 }finally{
  await server.close();
  if(previous)Object.defineProperty(globalThis,'document',previous);else delete globalThis.document;
 }
});
