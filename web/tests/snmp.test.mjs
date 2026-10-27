import test from 'node:test';
import assert from 'node:assert/strict';
import {deviceForm,deviceInput,clearPasswords,enrollmentMatches,approveEngine,receiverState,handlingLabel,securityLabel,profileLabel} from '../src/snmp.js';
import {eventProvenance} from '../src/events.js';
import {setLanguage} from '../src/i18n.js';
const community={kind:'community',community:'synthetic-community'};
const poll={host:'bmc.example.invalid',port:161,security:{version:'v3',username:'reader',auth:'sha256',privacy:'aes128'},profile:'dell_idrac',context_name:'',context_engine_id:null,timeout_ms:2000,retries:1};
const entry={revision:7,has_snmp_poll_secret:true,has_snmp_traps_secret:true,device:{id:'device',name:'Synthetic',primary_protocol:'snmp',enabled:true,snmp_poll:poll,snmp_traps:{enabled:true,security:poll.security,profile:'dell_idrac',allowed_sources:['192.0.2.10'],engine_ids:['8000000001'],context_name:'',context_engine_ids:[],timeliness_poll_only:false}}};
test('DSM polling profile round trips with its display label',()=>{
 const source=structuredClone(entry);source.device.snmp_poll.profile='synology_dsm';
 const draft=deviceForm(source);assert.equal(deviceInput(draft,source).snmp_poll.profile,'synology_dsm');assert.equal(profileLabel(draft.poll.profile),'Synology DSM');
});
test('time compatibility is opt-in, round trips without secret changes, and is cleared for community traps',()=>{
 const original=structuredClone(entry);delete original.device.snmp_traps.timeliness_poll_only;
 const draft=deviceForm(original);assert.equal(draft.traps.timeliness_poll_only,false);
 draft.traps.timeliness_poll_only=true;
 let input=deviceInput(draft,original);assert.equal(input.snmp_traps.timeliness_poll_only,true);assert.equal(input.snmp_secrets.snmp_traps.action,'keep');
 assert.equal(deviceForm({device:input}).traps.timeliness_poll_only,true);
 draft.traps.security.version='v2c';input=deviceInput(draft,original);assert.equal(input.snmp_traps.timeliness_poll_only,false);
});
test('saved SNMP configuration round trips without recovering or resubmitting secret values',()=>{
 const original=structuredClone(entry),draft=deviceForm(entry),input=deviceInput(draft,entry);
 assert.deepEqual(input.snmp_poll,poll);assert.deepEqual(input.snmp_traps,entry.device.snmp_traps);
 assert.deepEqual(input.snmp_secrets,{snmp_poll:{action:'keep'},snmp_traps:{action:'keep'}});
 assert.equal(input.revision,7);assert.equal(input.password,null);assert.equal(input.certificate_pem,null);assert.equal(input.trust_mode,'system');assert.equal(input.endpoint,'');assert.deepEqual(entry,original);
});
test('v1 and v2c polling submit community credentials and exclude hidden v3 context/Redfish fields',()=>{
 for(const version of ['v1','v2c']){
  const draft=deviceForm(null);draft.primary_protocol='snmp';draft.poll.security.version=version;draft.poll.host='192.0.2.10';draft.poll.context_name='hidden';draft.poll.context_engine_id='8000000001';draft.poll_secret.community=community.community;draft.password='hidden-redfish';draft.tls_profile='idrac7';draft.certificate_pem='hidden-cert';
  const input=deviceInput(draft,null);assert.deepEqual(input.snmp_poll.security,{version});assert.equal(input.snmp_poll.context_name,'');assert.equal(input.snmp_poll.context_engine_id,null);assert.deepEqual(input.snmp_secrets.snmp_poll,{action:'replace',credentials:community});assert.equal(input.password,null);assert.equal(input.tls_profile,'standard');assert.equal(input.certificate_pem,null);assert.equal(input.snmp_traps,null);
 }
});
test('v3 auth and privacy passphrases remain independent and use UTF-8 byte limits',()=>{
 const draft=deviceForm(entry);draft.poll_secret.action='replace';draft.poll_secret.auth_password='synthetic-auth';draft.poll_secret.priv_password='synthetic-priv';draft.poll.security.auth='sha1';
 const input=deviceInput(draft,entry);assert.equal(input.snmp_poll.security.auth,'sha1');assert.deepEqual(input.snmp_secrets.snmp_poll.credentials,{kind:'usm',auth_password:'synthetic-auth',priv_password:'synthetic-priv'});
 draft.poll_secret.priv_password='é'.repeat(513);assert.throws(()=>deviceInput(draft,entry),/1024/);
 draft.poll_secret.priv_password='short';assert.throws(()=>deviceInput(draft,entry),/8/);
 clearPasswords(draft);assert.equal(draft.poll_secret.auth_password,'');assert.equal(draft.poll_secret.priv_password,'');
});
test('switching back to Redfish clears retired polling credentials and retains independent trap credentials',()=>{
 const draft=deviceForm(entry);draft.primary_protocol='redfish';draft.responder=false;draft.endpoint='https://bmc.example.invalid/';draft.username='reader';draft.password='synthetic-redfish';
 const input=deviceInput(draft,entry);assert.equal(input.snmp_poll,null);assert.deepEqual(input.snmp_secrets.snmp_poll,{action:'clear'});assert.deepEqual(input.snmp_secrets.snmp_traps,{action:'keep'});assert.equal(input.password,'synthetic-redfish');
});
test('Redfish sender responder uses trap security without an additional polling credential',()=>{
 const draft=deviceForm(null);draft.traps_enabled=true;draft.traps.allowed_sources='192.0.2.10, 2001:db8::10';draft.traps.security.username='trapreader';draft.trap_secret.auth_password='synthetic-auth';draft.trap_secret.priv_password='synthetic-priv';draft.responder=true;draft.poll.host='192.0.2.10';
 const input=deviceInput(draft,null);assert.equal(input.primary_protocol,'redfish');assert.deepEqual(input.snmp_poll.security,input.snmp_traps.security);assert.deepEqual(input.snmp_secrets.snmp_poll,{action:'clear'});assert.deepEqual(input.snmp_traps.allowed_sources,['192.0.2.10','2001:db8::10']);assert.equal(input.snmp_traps.engine_ids.length,0);
});
test('sender probe never grants approval and explicit approval requires unchanged saved target and revision',()=>{
 const draft=deviceForm(entry),observed={verified:true,revision:7,engine_id:'8000000002'};
 assert.equal(enrollmentMatches(draft,entry),true);assert.equal(draft.traps.engine_ids,'8000000001');
 assert.throws(()=>approveEngine(draft,{...observed,revision:6},entry));assert.throws(()=>approveEngine(draft,{...observed,verified:false},entry));assert.throws(()=>approveEngine(draft,{...observed,engine_id:null},entry));
 draft.poll.host='changed.invalid';assert.equal(enrollmentMatches(draft,entry),false);assert.throws(()=>approveEngine(draft,observed,entry));draft.poll.host=poll.host;
 approveEngine(draft,observed,entry);assert.equal(draft.traps.engine_ids,'8000000002');assert.equal(draft.trap_secret.action,'replace');assert.equal(draft.trap_secret.auth_password,'');assert.equal(entry.device.snmp_traps.engine_ids[0],'8000000001');assert.throws(()=>deviceInput(draft,entry));
});
test('paused inputs can explicitly clear secrets; community traps discard hidden USM fields',()=>{
 const draft=deviceForm(entry);draft.enabled=false;draft.poll_secret.action='clear';draft.trap_secret.action='clear';draft.traps.security.version='v1';const input=deviceInput(draft,entry);
 assert.deepEqual(input.snmp_secrets.snmp_poll,{action:'clear'});assert.deepEqual(input.snmp_secrets.snmp_traps,{action:'clear'});assert.deepEqual(input.snmp_traps.security,{version:'v1'});assert.deepEqual(input.snmp_traps.engine_ids,[]);assert.deepEqual(input.snmp_traps.context_engine_ids,[]);
});
test('receiver and evidence labels distinguish trust, lifecycle, unsupported and pending states in both languages',()=>{
 try{for(const language of ['de','en']){setLanguage(language);assert.notEqual(receiverState('verified'),receiverState('verification_pending'));assert.notEqual(receiverState('identity_review_required'),receiverState('snmp_engine_mismatch'));assert.notEqual(receiverState('listening'),receiverState('bind_failed'));assert.notEqual(handlingLabel('test'),handlingLabel('provisional_fault'));assert.notEqual(securityLabel('v1'),securityLabel('v3'));assert.ok(eventProvenance({message_context:{source:'snmp_trap',verified:false,provisional:true,receipt_id:42}}).includes('42'));}setLanguage('en');assert.match(receiverState('snmp_engine_mismatch'),/review required/);assert.match(eventProvenance({message_context:{source:'snmp_poll',verified:false}}),/Not cryptographically verified/);}finally{setLanguage('de');}
});

test('network profile round trips and typed rates/port states remain separate from assessment',async()=>{
 const {networkReading,interfaceState}=await import('../src/snmp.js');
 const source=structuredClone(entry);source.device.snmp_poll.profile='network_generic';
 const draft=deviceForm(source);assert.equal(deviceInput(draft,source).snmp_poll.profile,'network_generic');
 assert.equal(profileLabel(draft.poll.profile),'Netzwerk · Generisch');
 assert.match(networkReading({key:'if:in',reading:1e9,unit:'bit/s'}),/1 Gbit\/s/);
 assert.equal(networkReading({key:'if:in',reading:null,unit:'bit/s'}),'—');
 assert.equal(networkReading({key:'if:duplex',reading:2}),'Halbduplex');
 assert.equal(interfaceState({present:true,admin:1,oper:2}),'Kein Link');assert.equal(interfaceState({present:false}),'Nicht mehr gefunden');
});

test('UPS profiles preserve explicit selection and translate labels',()=>{
 for(const [profile,label] of [['ups_generic','USV · Generisch (RFC 1628)'],['apc_ups','APC USV'],['eaton_ups','Eaton USV']]){const source=structuredClone(entry);source.device.snmp_poll.profile=profile;const draft=deviceForm(source);assert.equal(deviceInput(draft,source).snmp_poll.profile,profile);setLanguage('de');assert.equal(profileLabel(profile),label);setLanguage('en');assert.match(profileLabel(profile),/UPS/);}setLanguage('auto');
});

test('HPE profile retains its saved identifier and explains power and storage limits',async()=>{
 const {hpeNotes}=await import('../src/snmp.js');
 setLanguage('de');
 const source=structuredClone(entry);source.device.snmp_poll.profile='hpe_ilo5';
 const draft=deviceForm(source);assert.equal(deviceInput(draft,source).snmp_poll.profile,'hpe_ilo5');assert.equal(profileLabel(draft.poll.profile),'HPE iLO');
 assert.deepEqual(hpeNotes(null),[]);
 const snapshot={snmp:{hpe:{power_state:2,storage_assessable:false}}};
 assert.equal(hpeNotes(snapshot).length,2);assert.match(hpeNotes(snapshot)[0],/ausgeschaltet/);assert.match(hpeNotes(snapshot)[1],/Kein auswertbarer Storage/);
 setLanguage('en');assert.match(hpeNotes(snapshot)[0],/powered off/);assert.match(hpeNotes(snapshot)[1],/No assessable storage/);
 snapshot.snmp.hpe={power_state:3,storage_assessable:true};assert.equal(hpeNotes(snapshot).length,1);assert.match(hpeNotes(snapshot)[0],/powered on/);
 setLanguage('de');
});


test('device editing preserves each hardware log mode alongside SNMP configuration',()=>{
 for(const hardware_log of [{mode:'disabled'},{mode:'all'},{mode:'latest',limit:123}]){
  const source=structuredClone(entry);source.device.hardware_log=hardware_log;
  const draft=deviceForm(source),input=deviceInput(draft,source);
  assert.deepEqual(input.hardware_log,hardware_log);
  assert.deepEqual(input.snmp_poll,source.device.snmp_poll);
 }
});

test('unfinished hidden log count cannot block SNMP or destroy the saved Redfish preference',()=>{
 const source=structuredClone(entry);source.device.hardware_log={mode:'latest',limit:123};
 for(const limit of ['',0,4097,1.5,'invalid']){
  const draft=deviceForm(source);draft.hardware_log_limit=limit;
  const input=deviceInput(draft,source);
  assert.deepEqual(input.hardware_log,{mode:'latest',limit:123});
  assert.equal(draft.hardware_log_limit,limit);
  assert.deepEqual(deviceForm({device:input}).hardware_log_limit,123);
 }
 const draft=deviceForm(source);draft.primary_protocol='redfish';draft.hardware_log_limit=321;
 draft.primary_protocol='snmp';assert.deepEqual(deviceInput(draft,source).hardware_log,{mode:'latest',limit:321});
 draft.primary_protocol='redfish';assert.deepEqual(deviceInput(draft,source).hardware_log,{mode:'latest',limit:321});
 const fresh=deviceForm(entry);fresh.hardware_log_mode='latest';fresh.hardware_log_limit='';
 assert.deepEqual(deviceInput(fresh,entry).hardware_log,{mode:'all'});
});
