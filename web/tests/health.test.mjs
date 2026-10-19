import test from 'node:test';import assert from 'node:assert/strict';import {overall,measurementSnapshot,primaryAlarms,summaryAlarms,alarmConfirmation,coveredLabels,assessmentReason,observationStatus,observationLabel} from '../src/health.js';
const device=()=>({stale:false,alarms:[],snapshot:{observations:[{key:'fan',health:'ok'}],capabilities:[{outcome:'available'}]}});

test('devices without usable measurements stay unknown and have no detail snapshot',()=>{
 for(const snapshot of [undefined,null,{}, {observations:null}, {observations:null,capabilities:[]}, {observations:[]}, {observations:[],capabilities:null}]){
  const d={...device(),snapshot};
  assert.equal(measurementSnapshot(d),null);
  assert.equal(overall(d),'unknown');
 }
 const d=device();assert.equal(measurementSnapshot(d),d.snapshot);assert.equal(overall(d),'ok');
 d.snapshot.observations=[];assert.equal(measurementSnapshot(d),d.snapshot);assert.equal(overall(d),'unknown');
});
test('partial and stale coverage is never green',()=>{let d=device();assert.equal(overall(d),'ok');d.stale=true;assert.equal(overall(d),'unknown');d=device();d.snapshot.capabilities[0].outcome='forbidden_permission_or_license';assert.equal(overall(d),'unknown');d=device();d.snapshot.observations=[];assert.equal(overall(d),'unknown')});
test('persisted faults retain severity until stale',()=>{let d=device();d.alarms=[{health:'critical'}];assert.equal(overall(d),'critical');d.stale=true;assert.equal(overall(d),'unknown')});

test('disabled functions, proven empty controllers and pure power measurements are neutral',()=>{
 const d=device();
 d.snapshot.assessment_exclusions={redundancy:'disabled',storage:'empty_controller',controller:'empty_controller',power:'informational'};
 for(const key of Object.keys(d.snapshot.assessment_exclusions))d.snapshot.observations.push({key,health:'unknown'});
 assert.equal(overall(d),'ok');
 for(const o of d.snapshot.observations.slice(1)){
  assert.equal(observationStatus(o,d.snapshot),'not_applicable');
  assert.equal(observationLabel(o,d.snapshot),'Nicht relevant');
  assert.ok(assessmentReason(o,d.snapshot));
 }
 d.snapshot.observations.push({key:'unassessed-disk',health:'unknown'});assert.equal(overall(d),'unknown');
});
test('neutral rows cannot suppress faults, stale readings or missing coverage',()=>{
 const d=device();const o={key:'controller',health:'unknown'};
 d.snapshot.observations.push(o);d.snapshot.assessment_exclusions={controller:'empty_controller'};
 assert.equal(overall(d),'ok');
 d.alarms=[{key:o.key,health:'critical',current_health:'unknown'}];assert.equal(overall(d),'critical');
 d.alarms=[];
 for(const health of ['warning','critical']){o.health=health;assert.equal(assessmentReason(o,d.snapshot),'');assert.equal(observationStatus(o,d.snapshot),health);assert.equal(overall(d),health);}
 o.health='unknown';d.stale=true;assert.equal(overall(d),'unknown');
 d.stale=false;d.snapshot.capabilities[0].outcome='timeout';assert.equal(overall(d),'unknown');
});
test('old snapshots, unknown exemption codes and exclusively informational data stay unknown',()=>{
 const d=device();d.snapshot.observations=[{key:'power',health:'unknown'}];assert.equal(overall(d),'unknown');
 d.snapshot.assessment_exclusions={power:'new_unrecognized_reason'};assert.equal(overall(d),'unknown');
 d.snapshot.assessment_exclusions.power='informational';assert.equal(overall(d),'unknown');
});

test('retained component fault stays visible while linked summary states remain inspectable',()=>{
 const d={alarms:[{key:'ps1',label:'PS1',health:'critical',current_health:'unknown',covered_by:[]},{key:'system',label:'System',health:'critical',covered_by:['ps1']}]};
 assert.deepEqual(primaryAlarms(d).map(a=>a.key),['ps1']);assert.deepEqual(summaryAlarms(d).map(a=>a.key),['system']);assert.equal(coveredLabels(d.alarms[1],d),'PS1');assert.match(alarmConfirmation(d.alarms[0]),/aktuell nicht bewertbar/);assert.equal(alarmConfirmation({current_health:'critical'}),'Aktuell gemessen');
});
