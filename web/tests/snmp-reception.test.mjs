import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';

test('compatibility reception is visible without implying fresh evidence or hiding newer normal reception',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try{
  const {default:Reception}=await server.ssrLoadModule('/src/SnmpReception.vue');
  const {setLanguage}=await server.ssrLoadModule('/src/i18n.js');
  const {timestamp}=await server.ssrLoadModule('/src/health.js');
  const entry={revision:3,last_trap_received:null};
  const sender={revision:3,last_poll_hint:1792790000};
  let html=await renderToString(createSSRApp(Reception,{entry,sender,compact:true}));
  assert.match(html,/notice-warning/);assert.match(html,/SNMPv3-Trap empfangen · Kompatibilitätsmodus/);
  assert.ok(html.includes(timestamp(sender.last_poll_hint)));assert.match(html,/Signatur und Entschlüsselung geprüft/);assert.match(html,/Aktualität unbestätigt/);assert.match(html,/Geräteabfrage angefordert/);
  assert.doesNotMatch(html,/Noch kein Trap-Eingang nachgewiesen|Kryptografisch verifiziert/);
  entry.last_trap_received=sender.last_poll_hint-100;
  html=await renderToString(createSSRApp(Reception,{entry,sender}));assert.match(html,/Kompatibilitätsmodus/);assert.match(html,/Letzter regulär akzeptierter Trap:/);assert.ok(html.includes(timestamp(entry.last_trap_received)));
  entry.last_trap_received=sender.last_poll_hint+100;
  html=await renderToString(createSSRApp(Reception,{entry,sender}));assert.doesNotMatch(html,/notice-warning/);assert.ok(html.includes(timestamp(entry.last_trap_received)));assert.match(html,/Letzter Kompatibilitätseingang · nur Abfrage:/);
  entry.last_trap_received=null;sender.revision=2;
  html=await renderToString(createSSRApp(Reception,{entry,sender}));assert.match(html,/Noch kein Trap-Eingang nachgewiesen/);assert.doesNotMatch(html,/Kompatibilitätsmodus|Geräteabfrage angefordert/);
  sender.revision=3;setLanguage('en');
  html=await renderToString(createSSRApp(Reception,{entry,sender}));assert.match(html,/SNMPv3 trap received · compatibility mode/);assert.match(html,/freshness unconfirmed/);assert.match(html,/Device poll requested/);
  setLanguage('de');
 }finally{await server.close();}
});
