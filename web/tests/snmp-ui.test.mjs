import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';

test('SNMP editor and receiver UI enforce protocol separation and the viewer boundary',async()=>{
 const previous=Object.getOwnPropertyDescriptor(globalThis,'document');
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  Object.defineProperty(globalThis,'document',{configurable:true,value:{activeElement:null,cookie:'lang=ger'}});
  const {default:Editor}=await server.ssrLoadModule('/src/DeviceEditor.vue');const {default:Settings}=await server.ssrLoadModule('/src/SnmpSettings.vue');
  const entry={revision:1,has_snmp_poll_secret:true,device:{id:'synthetic',name:'Synthetic',primary_protocol:'snmp',snmp_poll:{host:'192.0.2.10',security:{version:'v1'},profile:'dell_idrac'},enabled:true}};
  let html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.match(html,/SNMPv1/);assert.match(html,/Klartext/);assert.match(html,/value="keep" selected/);assert.doesNotMatch(html,/HTTPS-Adresse|Gerätepasswort|Zertifikatsvertrauen|Authentifizierungs-Passphrase/);
  entry.device.snmp_poll.security={version:'v3',username:'reader',auth:'sha256'};html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.match(html,/SNMPv3-Benutzer/);assert.match(html,/SHA-256/);assert.doesNotMatch(html,/Community-Zugriff|type="password"/);
  entry.device.snmp_poll.profile='synology_dsm';html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.match(html,/value="synology_dsm" selected/);assert.match(html,/DSM unterstützt keine SNMP-Traps/);
  entry.device.snmp_poll.profile='network_generic';html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.match(html,/value="network_generic" selected/);assert.match(html,/Nur zuvor aktive Ports/);
  for(const profile of ['ups_generic','apc_ups','eaton_ups']){entry.device.snmp_poll.profile=profile;html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.ok(html.includes(`value="${profile}" selected`));assert.match(html,/schaltet die USV nicht/);}
  const {default:Interfaces}=await server.ssrLoadModule('/src/NetworkInterfaces.vue');
  const networkSnapshot={snmp:{network:{interfaces:[{key:'snmp:interface:test',index:7,name:'<unsafe>',alias:'WAN',present:true,seen_up:true,admin:1,oper:2}]}},observations:[{key:'snmp:interface:test',label:'Link',health:'warning',reading:null}]};
  html=await renderToString(createSSRApp(Interfaces,{snapshot:networkSnapshot,device:{}}));assert.match(html,/&lt;unsafe&gt;/);assert.match(html,/WAN/);assert.match(html,/Kein Link/);assert.match(html,/Warnung/);
  const dashboard={user:{role:'viewer'},devices:[],snmp_receiver:{settings:{enabled:true,listen_port:2162,listen_addresses:['::']},revision:2,state:'listening',listening:['[::]:2162']}};
  html=await renderToString(createSSRApp(Settings,{dashboard}));assert.doesNotMatch(html,/Trap-Empfänger speichern|Lokale NAS-Adressen/);
  dashboard.user.role='administrator';html=await renderToString(createSSRApp(Settings,{dashboard}));assert.match(html,/min="1"/);assert.match(html,/value="2162"/);assert.match(html,/\[::\]:2162/);assert.match(html,/1162/);assert.match(html,/Loopback-Test/);assert.match(html,/Empfangsstatus und Belege aktualisieren/);
  dashboard.snmp_receiver.state='permission_denied';dashboard.snmp_receiver.settings.listen_port=162;
  html=await renderToString(createSSRApp(Settings,{dashboard}));assert.match(html,/value="162"/);assert.match(html,/setup-trap-port\.sh enable/);assert.match(html,/Paketupdates/);assert.match(html,/Paketbenutzer/);
  dashboard.snmp_receiver.state='bind_failed';html=await renderToString(createSSRApp(Settings,{dashboard}));assert.doesNotMatch(html,/setup-trap-port\.sh enable/);
  entry.device.snmp_traps={enabled:true,security:{version:'v3',username:'reader',auth:'sha256'},allowed_sources:['192.0.2.10'],engine_ids:['8000000001']};entry.has_snmp_traps_secret=true;
  html=await renderToString(createSSRApp(Editor,{entry,dashboard:{}}));assert.match(html,/Leer: alle Kontextnamen/);assert.match(html,/keine zusätzliche Kontext-Engine-ID/);assert.match(html,/Sender-Engine-ID wird unabhängig/);
  assert.match(html,/Kompatibilität bei abweichendem Boots-Zähler/);assert.match(html,/keinen direkten Trap-Alarm/);
  entry.device.snmp_traps.timeliness_poll_only=true;
  dashboard.devices=[entry];dashboard.snmp_receiver.devices={synthetic:{revision:1,last_poll_hint:1792790000}};
  html=await renderToString(createSSRApp(Settings,{dashboard}));assert.match(html,/Zeit-Kompatibilität aktiv/);assert.match(html,/SNMPv3-Trap empfangen · Kompatibilitätsmodus/);assert.match(html,/signierte Traps nur als Abfragehinweis/);
  const {default:App}=await server.ssrLoadModule('/src/App.vue');assert.ok(App);
 }finally{await server.close();if(previous)Object.defineProperty(globalThis,'document',previous);else delete globalThis.document;}
});
