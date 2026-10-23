<script setup>
import {t} from './i18n.js';
import {computed,reactive,ref,watch,onMounted,onUnmounted} from 'vue';
import {administer} from './device-api.js';
import {receiverState,handlingLabel,splitList} from './snmp.js';
import {timestamp} from './health.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['saved','edit']);
const admin=computed(()=>props.dashboard?.user?.role==='administrator');
const status=computed(()=>props.dashboard?.snmp_receiver??{});
const form=reactive({enabled:false,listen_port:1162,listen_addresses:'0.0.0.0'}),revision=ref(0),busy=ref(false),error=ref(''),message=ref(''),receipts=ref([]),device=ref(''),limit=ref(20),formElement=ref(null);
function load(){const saved=status.value;Object.assign(form,saved.settings??{});form.listen_addresses=(saved.settings?.listen_addresses??['0.0.0.0']).join('\n');revision.value=saved.revision??0;error.value='';message.value='';}
load();watch(()=>status.value.revision,value=>{if(value!==revision.value)error.value=t('Empfängereinstellungen wurden geändert. Bitte die gespeicherten Angaben laden.');});
let controller;onUnmounted(()=>controller?.abort());
async function run(action){
 if(busy.value||!admin.value)return;
 if(action==='snmp_receiver_save'&&!formElement.value.reportValidity())return;
 busy.value=true;error.value='';message.value='';controller=new AbortController();const timer=setTimeout(()=>controller.abort(),25000);
 try{
  const operation=action==='snmp_receiver_save'?{action,revision:revision.value,settings:{enabled:form.enabled,listen_port:Number(form.listen_port),listen_addresses:splitList(form.listen_addresses)}}:{action,device:device.value||null,limit:Number(limit.value)};
  const result=await administer(props.dashboard,operation,fetch,controller.signal);
  if(action==='snmp_receiver_save'){revision.value=result.revision;message.value=t('Empfängereinstellungen gespeichert. Der Status zeigt die tatsächliche lokale Bindung.');emit('saved');}
  else receipts.value=result.receipts;
 }catch(e){error.value=e.name==='AbortError'?t('Zeitüberschreitung. Bitte die Ansicht aktualisieren.'):e.message;}
 finally{clearTimeout(timer);busy.value=false;}
}
function senderState(entry){const sender=status.value.devices?.[entry.device.id];return receiverState(sender?.revision===entry.revision?sender.state:'verification_pending');}
function sourceKind(source){return source==='::1'||source.startsWith('127.')?t('Lokaler Loopback-Absender · kein Controller-Nachweis'):t('Netzwerk-Absender · Controllerherkunft separat prüfen');}
function receiptDevice(row){return props.dashboard.devices.find(d=>d.device.id===row.device);}
onMounted(()=>run('snmp_receipts'));
</script>
<template><section v-if="admin" class="panel device-editor snmp-settings">
<header><div><p class="eyebrow">SNMP</p><h2>{{t('Trap-Empfänger & Empfangsprüfung')}}</h2></div><button class="refresh" :disabled="busy" @click="load">{{t('Gespeicherte Angaben laden')}}</button></header>
<div class="notice" role="status"><strong>{{receiverState(status.state)}}</strong><p>{{t('Tatsächlich gebundene NAS-Adressen:')}} <code>{{status.listening?.join(', ')||'—'}}</code></p><p>{{t('Eine lokale Bindung bestätigt nicht die Erreichbarkeit vom Controller. Dort dieselbe NAS-Zieladresse und denselben UDP-Port einstellen und die DSM-Firewall prüfen.')}}</p></div>
<form ref="formElement" @submit.prevent="run('snmp_receiver_save')"><fieldset :disabled="busy">
<label class="check"><input v-model="form.enabled" type="checkbox">{{t('Globalen SNMP-Trap-Empfänger aktivieren')}}</label>
<div class="form-columns"><label>{{t('Lokaler Trap-Port (UDP)')}}<input v-model="form.listen_port" type="number" required min="1024" max="65535" step="1"><small>{{t('Standard im Paket: 1162. SNMP-Abfragen verwenden normalerweise den Agent-Port 161; Traps üblicherweise 162. Der Empfänger benötigt einen freien Port ab 1024.')}}</small></label><label>{{t('Lokale NAS-Adressen')}}<textarea v-model="form.listen_addresses" rows="3" required spellcheck="false" placeholder="0.0.0.0&#10;::"></textarea><small>{{t('Bis zu 16 lokale IPv4-/IPv6-Adressen. 0.0.0.0 bindet alle IPv4-Adressen, :: alle IPv6-Adressen. Keine überlappenden Bindungen derselben Familie.')}}</small></label></div>
</fieldset><footer><button class="primary" :disabled="busy">{{t('Trap-Empfänger speichern')}}</button></footer></form>
<p v-if="message" class="notice" role="status">{{t(message)}}</p><p v-if="error" class="error" role="alert">{{t(error)}}</p>
<h3>{{t('Sender und Verifikationsbasis')}}</h3><p class="form-note">{{t('Nach Dienstneustart und erhöhtem Boots-Zähler derselben Engine wird die Verifikationsbasis durch eine authentifizierte Abfrage erneuert. Eine andere Engine-ID benötigt eine ausdrückliche neue Freigabe im Gerät.')}}</p>
<p v-if="status.omitted_devices" class="error">{{t('{0} Sender werden wegen des Empfängerlimits nicht überwacht.',status.omitted_devices)}}</p>
<table><thead><tr><th>{{t('Gerät')}}</th><th>{{t('Senderstatus')}}</th><th>{{t('Letzter akzeptierter Trap')}}</th><th></th></tr></thead><tbody><tr v-for="entry in dashboard.devices.filter(d=>d.device.snmp_traps?.enabled)" :key="entry.device.id"><td>{{entry.device.name}}</td><td>{{entry.device.enabled?senderState(entry):t('Überwachung pausiert')}}<small v-if="status.devices?.[entry.device.id]?.revision===entry.revision && status.devices?.[entry.device.id]?.engine_id" class="log-time">{{t('Engine-ID:')}} <code>{{status.devices[entry.device.id].engine_id}}</code></small></td><td>{{entry.last_trap_received?timestamp(entry.last_trap_received):t('Noch kein Trap empfangen')}}</td><td><button class="refresh" :disabled="busy" @click="emit('edit',entry)">{{t('Bearbeiten')}}</button></td></tr></tbody></table>
<details><summary>{{t('Empfangs- und Ablehnungszähler')}}</summary><dl class="snmp-counters"><template v-for="[key,label] in [['received',t('Datagramme empfangen')],['verified',t('Sicherheit verifiziert')],['unverified',t('Ohne kryptografische Verifikation')],['rejected',t('Sicherheitsprüfung abgewiesen')],['unknown_source',t('Unbekannte Absender')],['pending',t('Verifikationsbasis ausstehend')],['ambiguous',t('Mehrdeutige Senderzuordnung')],['duplicates',t('Duplikate unterdrückt')],['queue_dropped',t('Warteschlange voll')],['verification_limited',t('Verifikationslimit')],['ingestion_limited',t('Verarbeitungslimit')],['oversized',t('Datagramm zu groß')],['stale',t('Veraltete Konfiguration verworfen')],['storage_errors',t('Speicherfehler')],['io_errors',t('UDP-Fehler')]]" :key="key"><dt>{{label}}</dt><dd>{{status.counters?.[key]??0}}</dd></template></dl><p>{{t('Die Zähler gelten für den aktuellen Dienstlauf. Abgewiesene Datagramme erzeugen keinen Empfangsbeleg.')}}</p></details>
<h3>{{t('Controller-Test-Trap prüfen')}}</h3><p class="form-note">{{t('Sende jetzt einen Test-Trap am Controller und aktualisiere die Empfangsbelege. Vergleiche Gerät, Absender-IP, Zeit, Version, Engine-ID, Sicherheitsprüfung und OID. Ein Test-Trap erzeugt keinen Hardwarealarm. Ein Loopback-Test beweist keinen Controllerempfang.')}}</p>
<div class="event-filters"><label>{{t('Gerät')}}<select v-model="device" :disabled="busy" @change="receipts=[]"><option value="">{{t('Alle Geräte')}}</option><option v-for="entry in dashboard.devices" :key="entry.device.id" :value="entry.device.id">{{entry.device.name}}</option></select></label><label>{{t('Anzahl Belege')}}<select v-model="limit" :disabled="busy"><option :value="20">20</option><option :value="50">50</option><option :value="100">100</option></select></label><button class="refresh" :disabled="busy" @click="run('snmp_receipts')">{{t('Empfangsbelege aktualisieren')}}</button></div>
<p v-if="!receipts.length" class="form-note">{{t('Keine passenden Empfangsbelege geladen. Absenderfreigabe, Senderstatus, Firewall und Zielport prüfen.')}}</p>
<div class="receipt-list"><article v-for="row in receipts" :key="row.id" class="snmp-receipt"><strong>{{receiptDevice(row)?.device.name??row.device}} · {{timestamp(row.received)}}</strong><p v-if="row.receipt.restored || row.revision!==receiptDevice(row)?.revision" class="form-note">{{t('Historischer Beleg · kein Nachweis für die aktuelle Konfiguration')}}</p><p>{{row.receipt.source}} · {{row.receipt.version??'—'}} · {{row.receipt.verified?t('Kryptografisch verifiziert'):t('Nicht kryptografisch verifiziert')}}</p><p>{{sourceKind(row.receipt.source)}} · {{handlingLabel(row.receipt.handling)}}</p><p>{{t('Trap-OID:')}} <code>{{row.receipt.trap_oid}}</code></p><p v-if="row.receipt.engine_id">{{t('Engine-ID:')}} <code>{{row.receipt.engine_id}}</code> · {{t('Boots-Zähler:')}} {{row.receipt.engine_boots}}</p><p v-if="row.receipt.component_key">{{t('Komponente:')}} {{row.receipt.component_key}}</p><p v-if="row.receipt.event?.message">{{row.receipt.event.message}}</p></article></div>
</section></template>
