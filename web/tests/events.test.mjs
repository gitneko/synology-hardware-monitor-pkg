import test from 'node:test';import assert from 'node:assert/strict';
import {eventType,eventCategory,deliveryText,filterEvents,sourceTimestamp,capabilityText,groupEvents} from '../src/events.js';
const events=[{device:'a',kind:'alarm',key:'power',health:'critical'},{device:'a',kind:'hardware_log',key:'log:hash',health:'warning'},{device:'b',kind:'recovery',key:'coverage:/Logs',health:'ok'}];
test('historical logs, current hardware and monitoring recovery remain distinct',()=>{
 assert.deepEqual(events.map(eventCategory),['hardware','log','monitoring']);
 assert.deepEqual(events.map(eventType),['Hardwarealarm','Hardwarelog','Abfrage wieder erfolgreich']);
 assert.equal(eventType({kind:'recovery',key:'ps1'}),'Hardware-Entwarnung');
});
test('combined filters apply only to the loaded events and retain input',()=>{
 const copy=JSON.stringify(events);
 assert.deepEqual(filterEvents(events,{category:'all',health:'all',device:'all'}),events);
 assert.deepEqual(filterEvents(events,{category:'hardware',health:'critical',device:'a'}),[events[0]]);
 assert.deepEqual(filterEvents(events,{category:'log',health:'critical',device:'a'}),[]);
 assert.equal(JSON.stringify(events),copy);
});
test('recorded, queued, cancelled and submitted are not confused with delivery',()=>{
 assert.equal(deliveryText({}),'Lokal gespeichert');assert.equal(deliveryText({queued:true}),'Lokal vorgemerkt · kein Versand aktiv');
 assert.equal(deliveryText({queued:true,cancelled:true}),'Vormerkung storniert');assert.equal(deliveryText({delivered:123}),'An DSM übergeben');
});
test('HTTP diagnostics show actual status and retries; old snapshots remain readable',()=>{
 assert.equal(capabilityText({outcome:'http_error',http_status:500,attempts:2}),'HTTP 500 · 2 Versuche');
 assert.equal(capabilityText({outcome:'available',attempts:2}),'Erfolgreich nach Wiederholung');
 assert.match(capabilityText({outcome:'http_error'}),/alten Datensatz/);
 assert.equal(sourceTimestamp('invalid'),'');assert.equal(sourceTimestamp(null),'');assert.ok(sourceTimestamp('2026-10-17T12:00:00Z'));
});

test('incomplete polls distinguish deadlines, invalid replies and quantity limits',()=>{
 assert.match(capabilityText({outcome:'deadline'}),/vollständigen Abfrage/);
 assert.match(capabilityText({outcome:'invalid_response'}),/Ungültige Redfish/);
 assert.match(capabilityText({outcome:'resource_limit'}),/Ressourcenlimit/);
 assert.match(capabilityText({outcome:'item_limit'}),/Hardwareloglimit/);
});

test('only positively correlated identical transitions from different sources group; original history survives',()=>{
 const modern={id:2,device:'a',key:'modern',canonical_key:'modern',created:100,kind:'alarm',health:'critical',message:'PS1'};
 const legacy={...modern,id:1,key:'legacy'};
 const input=[modern,legacy],copy=JSON.stringify(input);const grouped=groupEvents(input);
 assert.equal(grouped.length,1);assert.equal(grouped[0].merged_count,2);assert.deepEqual(grouped[0].source_keys,['modern','legacy']);assert.equal(JSON.stringify(input),copy);
 const delivery=groupEvents([{...modern,queued:true,cancelled:true},{...legacy,queued:true,cancelled:false}])[0];assert.equal(delivery.cancelled,false);assert.equal(delivery.queued,true);
 for(const change of [{device:'b'},{created:101},{message:'Other PSU'},{health:'warning'},{canonical_key:'another'},{key:'modern'},{kind:'hardware_log'}])assert.equal(groupEvents([modern,{...legacy,...change}]).length,2);
 assert.equal(groupEvents([{...modern,kind:'hardware_log'},{...legacy,kind:'hardware_log'}]).length,2);
});

test('grouped summaries are distinct from cancellation or delivery',()=>{
 assert.match(deliveryText({mail_reason:'aggregate',desktop_reason:'aggregate',transport:'smtp',cancelled:true}),/Sammelmeldung gebündelt.*keine zusätzliche E-Mail/);
 assert.match(deliveryText({mail_reason:'aggregate',submitted_recipients:1}),/1 bereits per SMTP angenommen/);
});
