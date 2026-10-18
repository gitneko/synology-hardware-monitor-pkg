import test from 'node:test';import assert from 'node:assert/strict';import {overall,primaryAlarms,summaryAlarms,alarmConfirmation,coveredLabels} from '../src/health.js';
const device=()=>({stale:false,alarms:[],snapshot:{observations:[{key:'fan',health:'ok'}],capabilities:[{outcome:'available'}]}});
test('partial and stale coverage is never green',()=>{let d=device();assert.equal(overall(d),'ok');d.stale=true;assert.equal(overall(d),'unknown');d=device();d.snapshot.capabilities[0].outcome='forbidden_permission_or_license';assert.equal(overall(d),'unknown');d=device();d.snapshot.observations=[];assert.equal(overall(d),'unknown')});
test('persisted faults retain severity until stale',()=>{let d=device();d.alarms=[{health:'critical'}];assert.equal(overall(d),'critical');d.stale=true;assert.equal(overall(d),'unknown')});

test('retained component fault stays visible while linked summary states remain inspectable',()=>{
 const d={alarms:[{key:'ps1',label:'PS1',health:'critical',current_health:'unknown',covered_by:[]},{key:'system',label:'System',health:'critical',covered_by:['ps1']}]};
 assert.deepEqual(primaryAlarms(d).map(a=>a.key),['ps1']);assert.deepEqual(summaryAlarms(d).map(a=>a.key),['system']);assert.equal(coveredLabels(d.alarms[1],d),'PS1');assert.match(alarmConfirmation(d.alarms[0]),/aktuell nicht bewertbar/);assert.equal(alarmConfirmation({current_health:'critical'}),'Aktuell bestätigt');
});
