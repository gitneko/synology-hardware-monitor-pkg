import {ref} from 'vue';
import catalog from './en.json' with {type:'json'};
const storageKey='hardware-monitor.language';
export const preference=ref('auto');
export function normalizeLanguage(value){const tag=String(value??'').toLowerCase();if(tag==='ger'||/^de(?:-|$)/.test(tag))return 'de';if(tag==='enu'||/^en(?:-|$)/.test(tag))return 'en';return null;}
export function resolveLanguage(choice,{dsmLanguage='',browserLanguage='en'}={}){return choice==='de'||choice==='en'?choice:normalizeLanguage(dsmLanguage)??normalizeLanguage(browserLanguage)??'en';}
function environment(){
 let dsmLanguage='';
 try{const cookie=document.cookie.split(';').map(v=>v.trim()).find(v=>v.startsWith('lang='));if(cookie)dsmLanguage=decodeURIComponent(cookie.slice(5));}catch{}
 try{if(!normalizeLanguage(dsmLanguage)&&window.parent!==window)dsmLanguage=window.parent.document.documentElement.lang;}catch{}
 return {dsmLanguage,browserLanguage:typeof navigator==='undefined'?'en':navigator.language};
}
export function currentLanguage(){if(typeof document==='undefined'&&preference.value==='auto')return 'de';return resolveLanguage(preference.value,environment());}
export function dateLocale(){return currentLanguage()==='de'?'de-CH':'en-GB';}
export function setLanguage(value){preference.value=['auto','de','en'].includes(value)?value:'auto';try{if(typeof window!=='undefined')localStorage.setItem(storageKey,preference.value);}catch{}if(typeof document!=='undefined')document.documentElement.lang=currentLanguage();}
export function initLanguage(){try{const saved=typeof window!=='undefined'?localStorage.getItem(storageKey):null;if(saved)setLanguage(saved);}catch{}if(typeof document!=='undefined')document.documentElement.lang=currentLanguage();}
const reverse=new Map(Object.entries(catalog).map(([de,en])=>[en,de]));
export function t(key,...values){const source=Object.hasOwn(catalog,key)?key:reverse.get(key)??key;const text=currentLanguage()==='en'?(catalog[source]??source):source;return text.replace(/\{(\d+)\}/g,(whole,index)=>index<values.length?String(values[index]):whole);}
export const translations=catalog;
