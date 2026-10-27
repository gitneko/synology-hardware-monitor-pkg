import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';

test('query notifications have an independent checkbox, saved choices and legacy settings load',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  const {default:Settings}=await server.ssrLoadModule('/src/NotificationSettings.vue');
  for(const [selection,checked] of [
   [{critical:false,warning:false,monitoring:true},true],
   [{critical:true,warning:true,monitoring:false},false],
   [{critical:true,warning:false},true],
   [{critical:false,warning:false},false],
   [{critical:true,warning:true,snmp_trap:true},true],
  ]){
   const original=structuredClone(selection);
   const dashboard={user:{name:'synthetic-admin'},notification_settings:{revision:1,settings:{desktop_enabled:true,desktop_recipient:'synthetic-admin',selection}}};
   const html=await renderToString(createSSRApp(Settings,{dashboard}));
   const checkbox=html.match(/<input\b[^>]*>\s*Abfragewarnungen/);
   assert.ok(checkbox,'query filter rendered');
   assert.equal(/\bchecked\b/.test(checkbox[0]),checked);
   assert.match(html,/Abfragewarnungen und -fehler werden unabhängig/);
   const trap=html.match(/<input\b[^>]*>\s*Verifizierte SNMP-Trap-Ereignisse ohne Komponentenzuordnung/);assert.ok(trap);assert.equal(/\bchecked\b/.test(trap[0]),selection.snmp_trap===true);
   assert.deepEqual(selection,original); // Rendering must not add a choice to old settings.
  }
 }finally{await server.close();}
});
