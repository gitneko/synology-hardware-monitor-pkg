import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {resolveLanguage,setLanguage,t,dateLocale,translations,currentLanguage,preference} from '../src/i18n.js';
import {labels} from '../src/health.js';
import {deliveryText,eventType} from '../src/events.js';

test('automatic language resolution honors supported DSM language, then browser, then English',()=>{
 assert.equal(resolveLanguage('auto',{dsmLanguage:'ger',browserLanguage:'en-US'}),'de');
 assert.equal(resolveLanguage('auto',{dsmLanguage:'en-GB',browserLanguage:'de-CH'}),'en');
 assert.equal(resolveLanguage('auto',{dsmLanguage:'',browserLanguage:'de-CH'}),'de');
 assert.equal(resolveLanguage('auto',{dsmLanguage:'fre',browserLanguage:'fr-FR'}),'en');
 assert.equal(resolveLanguage('en',{dsmLanguage:'ger',browserLanguage:'de'}),'en');
});
test('changing language updates status labels, event delivery descriptions and dates without rewriting vendor text',()=>{
 try{setLanguage('en');assert.equal(labels.critical,'Critical');assert.equal(labels.unknown,'Not fully assessable');assert.equal(dateLocale(),'en-GB');assert.equal(eventType({kind:'recovery',key:'ps1'}),'Hardware recovery');assert.match(deliveryText({desktop:{cancelled:true}}),/cancelled/);assert.equal(t('{0} Ereignisse exportiert.',5),'5 events exported.');assert.equal(t('Unmodified vendor text'),'Unmodified vendor text');}
 finally{setLanguage('de');}assert.equal(labels.critical,'Kritisch');
});
test('all literal translation calls exist and preserve placeholder indices',()=>{
 const source=new URL('../src/',import.meta.url);for(const file of readdirSync(source).filter(n=>/\.(?:vue|js)$/.test(n)&&n!=='i18n.js')){
  const text=readFileSync(new URL(file,source),'utf8');assert.doesNotMatch(text,/<[^>]*v-pre[^>]*>\s*\{\{t\(/,file);for(const match of text.matchAll(/\bt\(("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g)){
   const value=match[1].startsWith('"')?JSON.parse(match[1]):match[1].slice(1,-1);assert.ok(Object.hasOwn(translations,value),`${file}: missing ${value}`);
  }
 }
 for(const [de,en]of Object.entries(translations)){assert.ok(en.length>0);const tokens=s=>[...s.matchAll(/\{\d+\}/g)].map(m=>m[0]).sort();assert.deepEqual(tokens(de),tokens(en),de);}
});

test('Automatic uses a supported DSM cookie before a parent marker, and safely falls back',()=>{
 const previous={document:Object.getOwnPropertyDescriptor(globalThis,'document'),window:Object.getOwnPropertyDescriptor(globalThis,'window'),navigator:Object.getOwnPropertyDescriptor(globalThis,'navigator')},choice=preference.value;
 try{
  Object.defineProperty(globalThis,'document',{configurable:true,value:{cookie:'lang=enu; id=synthetic-cookie',documentElement:{lang:'en'}}});
  Object.defineProperty(globalThis,'window',{configurable:true,value:{parent:{document:{documentElement:{lang:'de'}}}}});
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{language:'de-CH'}});
  preference.value='auto';assert.equal(currentLanguage(),'en');document.cookie='';assert.equal(currentLanguage(),'de');
  window.parent={get document(){throw new Error('cross-origin')}};assert.equal(currentLanguage(),'de');
 }finally{preference.value=choice;for(const [name,descriptor]of Object.entries(previous)){if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name];}}
});
