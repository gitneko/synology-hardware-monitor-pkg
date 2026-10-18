import test from 'node:test';import assert from 'node:assert/strict';
import {mailInput} from '../src/mail-settings.js';import {deliveryText} from '../src/events.js';
const form={enabled:false,host:' smtp.example.com ',port:'587',security:'starttls',authentication:true,username:'monitor',password:'',from_address:' monitor@example.com ',from_name:'Hardware Monitor',recipients:'one@example.com\ntwo@example.com;three@example.com',subject_template:'{{device}}',body_template:'{{message}}',ca_pem:''};
test('SMTP input keeps empty secret as retention request and parses recipients without mutating form',()=>{
 const before=JSON.stringify(form),input=mailInput(form,7);assert.equal(input.password,null);assert.equal(input.revision,7);assert.equal(input.settings.host,'smtp.example.com');assert.equal(input.settings.port,587);assert.deepEqual(input.settings.recipients,['one@example.com','two@example.com','three@example.com']);assert.equal(input.settings.ca_pem,null);assert.equal(JSON.stringify(form),before);assert.equal(mailInput({...form,authentication:false},7).settings.username,'');assert.equal(mailInput({...form,password:'new-secret'},7).password,'new-secret');
});
test('SMTP acknowledgement, partial failure, queued retry and cancellation remain distinct',()=>{
 const e={transport:'smtp',submitted_recipients:1,total_recipients:2};assert.match(deliveryText(e),/E-Mail vorgemerkt/);assert.match(deliveryText({...e,delivery_error:'mail_timeout'}),/Erneuter Versuch/);assert.match(deliveryText({...e,failed_recipients:1}),/Versandfehler/);assert.match(deliveryText({...e,cancelled:true}),/storniert/);assert.match(deliveryText({...e,delivered:123,submitted_recipients:2}),/SMTP-Server angenommen · 2\/2/);
});

test('plaintext and configured event time are explicit; reason and desktop status stay separate',()=>{
 const input=mailInput({...form,port:'25',security:'plain',authentication:false,ca_pem:'old CA',timezone:'Europe/Zurich',date_format:'%d.%m.%Y %H:%M:%S'},2);
 assert.equal(input.settings.port,25);assert.equal(input.settings.security,'plain');assert.equal(input.settings.ca_pem,null);assert.equal(input.settings.timezone,'Europe/Zurich');
 assert.match(deliveryText({mail_reason:'device_disabled'}),/am Gerät deaktiviert/);
 assert.match(deliveryText({mail_reason:'mail_disabled',desktop:{delivered:123}}),/E-Mail: automatischer Versand deaktiviert · DSM-Desktop: an DSM übergeben/);
 assert.match(deliveryText({mail_reason:'filtered',desktop_reason:'filtered'}),/durch Ereignisauswahl ausgeschlossen/);
});
